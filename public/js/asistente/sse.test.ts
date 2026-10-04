import assert from "node:assert/strict"
import { describe, it } from "node:test"
import {
  accumulateReply,
  EMPTY_REPLY,
  parseSseBuffer,
  resolveReply,
} from "./sse"

/* Portado de agenda (vitest) a `node:test`, que es lo que corre `npm test`.
   Shim mínimo con la semántica de vitest para no reescribir las aserciones:
   `toEqual` ignora propiedades `undefined` y `toMatchObject` compara un
   subconjunto (una clave `undefined` exige que falte o sea `undefined`). */
const clean = (v: unknown): unknown =>
  Array.isArray(v)
    ? v.map(clean)
    : v && typeof v === "object"
      ? Object.fromEntries(
          Object.entries(v as Record<string, unknown>)
            .filter(([, x]) => x !== undefined)
            .map(([k, x]) => [k, clean(x)]),
        )
      : v
const expect = (actual: unknown) => ({
  toBe: (expected: unknown) => assert.equal(actual, expected),
  toEqual: (expected: unknown) =>
    assert.deepStrictEqual(clean(actual), clean(expected)),
  toMatchObject: (expected: Record<string, unknown>) => {
    const a = actual as Record<string, unknown>
    for (const [k, v] of Object.entries(expected))
      assert.deepStrictEqual(clean(a?.[k]), clean(v), k)
  },
})

const frame = (obj: unknown) => `data: ${JSON.stringify(obj)}\n\n`

describe("parseSseBuffer", () => {
  it("corta frames completos y normaliza", () => {
    const { events, rest } = parseSseBuffer(
      frame({ type: "chunk", value: "Hola" }) +
        frame({ type: "chunk", value: " mundo" }),
    )
    expect(events).toEqual([
      { type: "chunk", value: "Hola" },
      { type: "chunk", value: " mundo" },
    ])
    expect(rest).toBe("")
  })

  it("devuelve el frame incompleto en `rest` sin perderlo", () => {
    // Es EL caso que rompe el chat: la red parte un frame a la mitad y, si se
    // tira, el mensaje sale truncado.
    const full = frame({ type: "chunk", value: "completo" })
    const partial = 'data: {"type":"chunk","value":"a med'
    const first = parseSseBuffer(full + partial)
    expect(first.events).toEqual([{ type: "chunk", value: "completo" }])
    expect(first.rest).toBe(partial)

    const second = parseSseBuffer(`${first.rest}io"}\n\n`)
    expect(second.events).toEqual([{ type: "chunk", value: "a medio" }])
    expect(second.rest).toBe("")
  })

  it("ignora líneas que no son JSON en vez de tirar el stream", () => {
    const { events } = parseSseBuffer(
      "data: keep-alive\n\n" +
        ": comentario\n\n" +
        frame({ type: "chunk", value: "ok" }),
    )
    expect(events).toEqual([{ type: "chunk", value: "ok" }])
  })

  it("descarta tipos desconocidos — un evento nuevo del upstream no debe romper nada", () => {
    const { events } = parseSseBuffer(
      frame({ type: "telemetry", foo: 1 }) +
        frame({ type: "done", value: "x" }),
    )
    expect(events).toEqual([{ type: "done", value: "x" }])
  })

  it("resuelve el nombre de la tool venga en `name`, `label` o `value`", () => {
    // La flota es inconsistente en esto; por eso se normaliza en un solo lugar.
    const { events } = parseSseBuffer(
      frame({ type: "tool", name: "list_events" }) +
        frame({ type: "status", label: "get_today_summary" }) +
        frame({ type: "tool", value: "cancel_event" }),
    )
    expect(events).toEqual([
      { type: "tool", name: "list_events" },
      { type: "tool", name: "get_today_summary" },
      { type: "tool", name: "cancel_event" },
    ])
  })

  it("descarta un evento de tool sin nombre en vez de trazar 'undefined'", () => {
    const { events } = parseSseBuffer(frame({ type: "tool" }))
    expect(events).toEqual([])
  })

  it("reconoce el frame de error", () => {
    const { events } = parseSseBuffer(frame({ type: "error", message: "boom" }))
    // El `message` viaja: es la única pista de POR QUÉ se cayó el turno.
    expect(events).toEqual([{ type: "error", message: "boom" }])
  })

  it("tolera un frame de error sin message", () => {
    const { events } = parseSseBuffer(frame({ type: "error" }))
    expect(events).toEqual([{ type: "error", message: undefined }])
  })

  it("un chunk sin `value` string no pasa (evita concatenar undefined)", () => {
    const { events } = parseSseBuffer(frame({ type: "chunk", value: 42 }))
    expect(events).toEqual([])
  })
})

describe("acumulador de la respuesta", () => {
  const run = (evts: Parameters<typeof accumulateReply>[1][]) =>
    resolveReply(evts.reduce(accumulateReply, EMPTY_REPLY))

  it("concatena los chunks cuando no llegó `done`", () => {
    expect(
      run([
        { type: "chunk", value: "uno " },
        { type: "chunk", value: "dos" },
      ]),
    ).toBe("uno dos")
  })

  it("`done` PISA lo acumulado — es la respuesta autoritativa", () => {
    // Los chunks son un preview y pueden diferir del resultado final; guardar la
    // concatenación cuando existe `done` persiste el texto equivocado.
    expect(
      run([
        { type: "chunk", value: "borrador incompleto" },
        { type: "done", value: "respuesta final" },
      ]),
    ).toBe("respuesta final")
  })

  it("cae a los chunks si el `done` viene vacío", () => {
    expect(
      run([
        { type: "chunk", value: "lo que alcanzó a llegar" },
        { type: "done", value: "" },
      ]),
    ).toBe("lo que alcanzó a llegar")
  })

  it("los eventos de tool y error no aportan texto", () => {
    expect(
      run([
        { type: "tool", name: "list_events" },
        { type: "error" },
        { type: "chunk", value: "hola" },
      ]),
    ).toBe("hola")
  })
})

/**
 * Los eventos que la flota empezó a mandar a petición nuestra.
 *
 * Se leen si están y se ignoran si no: una caja viva o suspendida sigue con el
 * binario anterior hasta que el reaper la recicle, así que durante un buen rato
 * conviven las dos formas. Romper con la vieja dejaría turnos sin traza.
 */
describe("telemetría del turno", () => {
  const uno = (o: unknown) =>
    parseSseBuffer(`data: ${JSON.stringify(o)}\n\n`).events[0]

  it("lee el consumo al cerrar", () => {
    expect(
      uno({ type: "usage", inputTokens: 4321, outputTokens: 890, model: "x" }),
    ).toEqual({
      type: "usage",
      inputTokens: 4321,
      outputTokens: 890,
      model: "x",
    })
  })

  it("acepta snake_case, que es como lo nombra otro motor", () => {
    const e = uno({ type: "usage", input_tokens: 10, output_tokens: 20 })
    expect(e).toMatchObject({ inputTokens: 10, outputTokens: 20 })
  })

  it("una tool con duración y fallo", () => {
    expect(
      uno({ type: "tool", name: "audit_page", durationMs: 900, ok: false }),
    ).toEqual({
      type: "tool",
      name: "audit_page",
      durationMs: 900,
      failed: true,
    })
  })

  it("una tool del binario VIEJO sigue funcionando", () => {
    // Sin `durationMs` ni `ok`: es el caso mayoritario hasta que reciclen.
    expect(uno({ type: "tool", name: "audit_page" })).toEqual({
      type: "tool",
      name: "audit_page",
      durationMs: undefined,
      failed: undefined,
    })
  })

  it("números basura no entran", () => {
    // Un NaN envenenaría cualquier suma del reporte.
    const e = uno({ type: "usage", inputTokens: "muchos", outputTokens: -5 })
    expect(e).toMatchObject({ inputTokens: undefined, outputTokens: undefined })
  })
})

describe("frames de tool de gs (start/end)", () => {
  it("conserva phase y lee `ms` como duración", () => {
    const { events } = parseSseBuffer(
      `data: ${JSON.stringify({ type: "tool", name: "denik__list_events", id: "c1", phase: "start", args: {} })}\n\n` +
        `data: ${JSON.stringify({ type: "tool", name: "denik__list_events", id: "c1", phase: "end", ok: false, ms: 42 })}\n\n`,
    )
    expect(events).toEqual([
      { type: "tool", name: "denik__list_events", durationMs: undefined, failed: undefined, phase: "start" },
      { type: "tool", name: "denik__list_events", durationMs: 42, failed: true, phase: "end" },
    ])
  })
})
