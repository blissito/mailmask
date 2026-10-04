/**
 * Parser del stream SSE del asistente. **Puro**: sin DOM, sin React, sin red.
 *
 * Por qué existe: este mismo parseo estaba TRIPLICADO — en el cliente de
 * `/dash/asistente`, en `captureAssistantReply` (que persiste la respuesta del
 * lado del servidor) y, en otra forma, en el widget público. Tres copias de la
 * misma gramática significa que un evento nuevo de la flota se soporta en una y
 * se olvida en las otras, y el síntoma es un mensaje que se ve bien en pantalla
 * pero se guarda mal (o al revés).
 *
 * Es además la única lógica genuinamente testeable del feature: el repo no tiene
 * harness de DB y todo lo demás es React o I/O.
 *
 * ## La gramática de la flota
 *
 * Los frames se separan con `\n\n` y el payload va en la línea `data: <json>`.
 * Tipos que emite:
 *   - `{type:"chunk", value}`  incremento de texto
 *   - `{type:"done",  value}`  respuesta AUTORITATIVA — pisa lo acumulado
 *   - `{type:"tool"|"status", name|label|value}`  una tool MCP en curso
 *     (gs manda DOS por llamada: `phase:"start"` y `phase:"end"` con `ok`/`ms`)
 *   - `{type:"error"}`
 */
/** Evento ya normalizado. Los tipos que no entendemos no llegan hasta aquí. */
export type AssistantEvent =
  | { type: "chunk"; value: string }
  | { type: "done"; value: string }
  | {
      type: "tool"
      name: string
      durationMs?: number
      failed?: boolean
      /** Sólo gs: `start` abre la llamada y `end` la cierra. La flota no lo manda. */
      phase?: "start" | "end"
    }
  /**
   * Consumo del turno, al cerrar. Lo cablearon en la flota a petición nuestra:
   * antes teníamos que contar los eventos a mano y aun así no sabíamos los
   * tokens. Todo opcional — una caja con el binario viejo no lo manda y no debe
   * romper nada.
   */
  | {
      type: "usage"
      inputTokens?: number
      outputTokens?: number
      model?: string
    }
  | { type: "error"; message?: string }

/**
 * Corta el buffer en frames completos y los normaliza.
 *
 * Devuelve también el `rest`: lo que quedó sin un `\n\n` de cierre. **Hay que
 * volver a alimentarlo en la siguiente lectura** — un frame puede partirse a la
 * mitad entre dos chunks de la red, y tirarlo trunca el mensaje.
 *
 * Las líneas que no son JSON válido se ignoran en silencio (la flota manda
 * comentarios de keep-alive), y los tipos desconocidos se descartan: un evento
 * nuevo del upstream no debe romper el hilo.
 */
export function parseSseBuffer(buffer: string): {
  events: AssistantEvent[]
  rest: string
} {
  const events: AssistantEvent[] = []
  let rest = buffer
  let nl: number
  while ((nl = rest.indexOf("\n\n")) !== -1) {
    const frame = rest.slice(0, nl)
    rest = rest.slice(nl + 2)
    const dataLine = frame.split("\n").find((l) => l.startsWith("data: "))
    if (!dataLine) continue
    let raw: unknown
    try {
      raw = JSON.parse(dataLine.slice(6))
    } catch {
      continue // línea SSE no-JSON: ignorar
    }
    const evt = normalizeEvent(raw)
    if (evt) events.push(evt)
  }
  return { events, rest }
}

function normalizeEvent(raw: unknown): AssistantEvent | null {
  if (typeof raw !== "object" || raw === null) return null
  const o = raw as Record<string, unknown>

  if (o.type === "chunk" && typeof o.value === "string") {
    return { type: "chunk", value: o.value }
  }
  if (o.type === "done" && typeof o.value === "string") {
    return { type: "done", value: o.value }
  }
  if (o.type === "tool" || o.type === "status") {
    // La flota no es consistente: manda el nombre en `name`, `label` o `value`
    // según el caso. Resolverlo aquí evita que cada consumidor lo re-adivine.
    const name =
      typeof o.name === "string"
        ? o.name
        : typeof o.label === "string"
          ? o.label
          : typeof o.value === "string"
            ? o.value
            : null
    if (!name) return null
    /* `durationMs` y el resultado llegan sólo desde el binario nuevo del worker.
       Se leen si están y se ignoran si no: una caja viva o suspendida sigue con
       el anterior hasta que el reaper la recicle. */
    const ms = o.durationMs ?? o.ms
    const durationMs =
      typeof ms === "number" && Number.isFinite(ms) ? ms : undefined
    const failed =
      o.ok === false || o.failed === true || o.status === "error"
        ? true
        : undefined
    const phase =
      o.phase === "start" || o.phase === "end" ? o.phase : undefined
    return { type: "tool", name, durationMs, failed, phase }
  }
  if (o.type === "usage") {
    const num = (v: unknown) =>
      typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : undefined
    return {
      type: "usage",
      // La flota nombra distinto según el motor; se aceptan las dos formas.
      inputTokens: num(o.inputTokens) ?? num(o.input_tokens),
      outputTokens: num(o.outputTokens) ?? num(o.output_tokens),
      model: typeof o.model === "string" ? o.model : undefined,
    }
  }
  if (o.type === "error") {
    /* El `message` del upstream es el ÚNICO dato que dice POR QUÉ falló el turno
       (capacidad, rate limit, llave del motor inválida…). Tirarlo dejaba el fallo
       indistinguible en logs y en pantalla — pasó el 2026-08-13 y hubo que
       reproducir el turno a mano para descartar cada causa. */
    return {
      type: "error",
      message: typeof o.message === "string" ? o.message : undefined,
    }
  }
  return null
}

// ==================== ACUMULADOR DE LA RESPUESTA ====================
// Lo usa el capturador del servidor (`captureAssistantReply`), que no tiene
// estado de React: solo necesita quedarse con el texto final para persistirlo.

export interface ReplyAccumulator {
  chunks: string
  final: string
}

export const EMPTY_REPLY: ReplyAccumulator = { chunks: "", final: "" }

export function accumulateReply(
  acc: ReplyAccumulator,
  evt: AssistantEvent,
): ReplyAccumulator {
  if (evt.type === "chunk") return { ...acc, chunks: acc.chunks + evt.value }
  if (evt.type === "done") return { ...acc, final: evt.value }
  return acc
}

/**
 * Texto definitivo del turno. El `done` gana sobre los `chunk` porque es la
 * respuesta autoritativa de la flota: los chunks son un preview y pueden diferir
 * del resultado final.
 */
export function resolveReply(acc: ReplyAccumulator): string {
  return (acc.final || acc.chunks).trim()
}
