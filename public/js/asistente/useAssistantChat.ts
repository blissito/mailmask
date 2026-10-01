import { useEffect, useRef, useState } from "react"
import type { ScreenContext } from "./screen"
import { parseAttachmentMarkdown } from "./attachmentMarkdown"
import { splitGluedSentences } from "./splitGlued"
import { parseSseBuffer } from "./sse"
import { bareName, toolLabel } from "./toolLabel"
import type { Attachment, Msg, ToolRun } from "./types"

/**
 * Todo el estado del chat con Nik: historial, streaming SSE, adjuntos, traza de
 * tools y paginación hacia arriba.
 *
 * Vive fuera de la ruta porque lo consumen DOS superficies con la misma
 * conversación detrás: la página completa (`/dash/asistente`) y el dock global
 * del dashboard. El `groupId` de la flota es determinista por org
 * (`web-admin-${orgId}`), así que ambas hablan del mismo hilo — que es el
 * comportamiento correcto: lo que le pediste en el dock lo ves en la página.
 *
 * Lo que NO vive aquí, a propósito:
 *   - la animación de entrada de los mensajes (presentación),
 *   - el `confirm()` al borrar el hilo (cada superficie lo pregunta distinto).
 */
/**
 * Mensaje como sale del loader: `createdAt` es un `Date` de Prisma y `role` es
 * un `string` suelto (Mongo no lo estrecha). El hook es quien normaliza — pedir
 * `Msg[]` de entrada obligaría a cada caller a castear, que es justo la clase de
 * cast que esconde un bug el día que el rol venga con otro valor.
 */
export type RawMsg = {
  id: string
  role: string
  content: string
  status?: string | null
  createdAt: string | Date
}

/**
 * Un mensaje persistido → un mensaje del hilo.
 *
 * Los adjuntos se guardan incrustados como markdown dentro del texto (ver
 * `attachmentMarkdown.ts`), así que aquí se vuelven a separar: si no, la
 * burbuja del usuario —que pinta `content` como texto plano— mostraba
 * `![foto.png](https://…)` crudo y desbordado en cada recarga.
 */
const hydrate = (m: RawMsg): Msg => {
  const { content, attachments } = parseAttachmentMarkdown(m.content ?? "")
  return {
    ...m,
    role: m.role === "assistant" ? ("assistant" as const) : ("user" as const),
    content,
    ...(attachments ? { attachments } : {}),
    // La key se fija al insertar y no se toca aunque el id cambie (ver types).
    key: m.id,
    createdAt: String(m.createdAt),
  }
}

export function useAssistantChat({
  initialMessages = [],
  initialHasMore = false,
  /** En local no hay flota: se deshabilita el envío y la subida de archivos. */
  isLocalhost = false,
  screen,
  surface = "page",
  onTool,
  beforeSubmit,
}: {
  initialMessages?: RawMsg[]
  initialHasMore?: boolean
  isLocalhost?: boolean
  /**
   * Qué pantalla del dash está mirando el usuario ahora (ver `useCurrentScreen`).
   * Es lo que hace que "cancela esta cita" signifique algo.
   */
  screen?: ScreenContext | null
  /** Desde qué superficie se escribe. Sólo alimenta la métrica de uso. */
  surface?: "dock" | "page" | "editor"
  /**
   * Se llama con el NOMBRE de cada tool que el agente ejecuta, en cuanto el SSE
   * la anuncia.
   *
   * Existe para el editor de landing: cuando Nik corre `update_landing_node`, el
   * lienzo tiene que refrescarse en vivo. El evento de la flota trae el nombre y
   * **nada más** —ni args ni resultado (`sse.ts`)—, y añadírselos tocaría la
   * imagen del sandbox, que es de otro repo. El nombre alcanza: el editor relee
   * las secciones y parchea las que cambiaron.
   */
  onTool?: (name: string) => void
  /**
   * Corre ANTES de mandar el turno; si lanza, el turno no se manda.
   *
   * Para el editor: persiste el lienzo antes de que Nik lea el HTML guardado. Sin
   * esto el agente trabaja sobre una versión vieja y, al refrescar, las
   * ediciones sin guardar del usuario desaparecen.
   */
  beforeSubmit?: () => Promise<void> | void
} = {}) {
  const [messages, setMessages] = useState<Msg[]>(() =>
    initialMessages.map(hydrate),
  )
  const [input, setInput] = useState("")
  const [streaming, setStreaming] = useState(false)
  const [attachments, setAttachments] = useState<Attachment[]>([])
  const [uploading, setUploading] = useState(0)
  const [dragging, setDragging] = useState(false)
  const [hasMore, setHasMore] = useState(Boolean(initialHasMore))
  const [loadingMore, setLoadingMore] = useState(false)
  const [atBottom, setAtBottom] = useState(true)
  /**
   * Último fallo del turno, para pintar un aviso fuera del hilo.
   *
   * Existe aparte de `msg.failed` porque ese flag sólo se ve si el mensaje del
   * asistente llegó a tener texto: cuando el stream muere antes del primer
   * token, el error se marcaba en una burbuja vacía y no lo veía nadie. Se
   * limpia al mandar el siguiente turno.
   */
  const [error, setError] = useState<string | null>(null)
  const bottomRef = useRef<HTMLDivElement>(null)
  const scrollRef = useRef<HTMLElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  // Corta el stream en curso desde el botón "Detener".
  const abortRef = useRef<AbortController | null>(null)
  /** Última pantalla que el server ya conoce. Ver el `submit`. */
  const sentScreenRef = useRef<string | null>(null)
  // Último turno enviado, para el botón "Reintentar" cuando falla.
  const lastTurnRef = useRef<{
    text: string
    attachments: Attachment[]
  } | null>(null)

  /* Puntitos: hay stream abierto y todavía no hay texto. El mensaje del
     asistente puede existir ya con solo la traza de tools (content vacío). */
  const last = messages[messages.length - 1]
  const waitingAssistant =
    streaming && (last?.role !== "assistant" || !last.content)

  /* Auto-scroll solo si el usuario ya estaba abajo: si subió a releer, un
     mensaje nuevo no debe arrancarle la vista (para eso está el botón). */
  const lastContent = messages[messages.length - 1]?.content ?? ""
  /* La PRIMERA vez se salta sin animación: al abrir el chat el hilo ya debe
     estar abajo, no viajar hasta ahí. Con un historial largo ese viaje dura
     casi un segundo y se lee como si algo se estuviera cargando solo. */
  const firstScroll = useRef(true)
  /**
   * Cuándo scrolleamos nosotros por última vez.
   *
   * `atBottom` es una puerta de un solo sentido dentro del turno: si algo la
   * apaga, el efecto sale por su guard y el hilo deja de seguir a Nik hasta que
   * el usuario intervenga. Y lo que la apagaba era **nuestro propio scroll**:
   * cada `scrollTo` emite un evento que `onThreadScroll` lee para recalcular, y
   * si el contenido creció entre medias, esa lectura da "lejos del fondo".
   */
  const autoScrollAt = useRef(0)
  useEffect(() => {
    if (!atBottom) return
    const el = scrollRef.current
    if (!el) return
    /* **Instantáneo mientras streamea, suave sólo entre turnos.**
       Con `behavior: "smooth"` cada token reinicia la animación, y como los
       tokens llegan más rápido de lo que ésta tarda, se cancelaba a sí misma y
       el hilo NUNCA llegaba abajo: Nik escribía fuera de la vista. Se nota más
       en el dock que en la página completa porque a 420px de ancho el texto
       envuelve más y el alto crece más rápido por token.

       Se scrollea el contenedor directamente en vez de `bottomRef.scrollIntoView`:
       ese busca el ancestro scrolleable más cercano, que con el panel del dock
       (varios flex anidados) no siempre es el que queremos. */
    // Marca de "este scroll lo causamos nosotros" — ver `onThreadScroll`.
    autoScrollAt.current = Date.now()
    el.scrollTo({
      top: el.scrollHeight,
      behavior: firstScroll.current || streaming ? "auto" : "smooth",
    })
    firstScroll.current = false
    // `lastContent` sigue el texto del asistente mientras streamea (crece sin
    // cambiar el número de mensajes).
  }, [messages.length, lastContent, waitingAssistant, atBottom, streaming])

  /**
   * Página anterior del historial al llegar arriba. Se conserva la posición
   * de scroll: sin esto, insertar contenido arriba empuja el hilo y el usuario
   * pierde el punto donde iba leyendo.
   */
  const loadOlder = async () => {
    const el = scrollRef.current
    const oldest = messages[0]
    if (!el || !oldest || loadingMore || !hasMore) return
    setLoadingMore(true)
    const prevHeight = el.scrollHeight
    try {
      const res = await fetch(
        `/api/asistente?before=${encodeURIComponent(new Date(oldest.createdAt).toISOString())}`,
      )
      const data = (await res.json()) as { messages: Msg[]; hasMore: boolean }
      if (data.messages?.length) {
        setMessages((prev) => [...data.messages.map(hydrate), ...prev])
        requestAnimationFrame(() => {
          el.scrollTop += el.scrollHeight - prevHeight
        })
      }
      setHasMore(Boolean(data.hasMore))
    } catch {
      /* si falla, el botón sigue ahí para reintentar */
    } finally {
      setLoadingMore(false)
    }
  }

  const onThreadScroll = () => {
    const el = scrollRef.current
    if (!el) return
    /* Ignora el eco de nuestro propio scroll. Sin esto, el auto-scroll se
       apagaba a sí mismo: `scrollTo` emite un evento, aquí se leía una posición
       tomada mientras el contenido seguía creciendo, salía >80px del fondo y
       `atBottom` quedaba en false para el resto del turno — Nik escribiendo
       fuera de la vista y el botón "bajar" encendido.
       150ms alcanzan para el eco (el scroll de streaming es instantáneo) sin
       tragarse un gesto real: si el usuario sube justo en esa ventana, su
       siguiente movimiento sí cuenta. */
    if (Date.now() - autoScrollAt.current < 150) return
    setAtBottom(el.scrollHeight - el.scrollTop - el.clientHeight < 80)
    if (el.scrollTop < 120) loadOlder()
  }

  const scrollToBottom = () => {
    const el = scrollRef.current
    if (!el) return
    // Mismo contenedor que el auto-scroll, no `bottomRef.scrollIntoView`: aquí
    // sí queda suave porque es un gesto del usuario, no una ráfaga de tokens.
    el.scrollTo({ top: el.scrollHeight, behavior: "smooth" })
    setAtBottom(true)
  }

  /**
   * Salto INSTANTÁNEO al final. Para cuando el hilo aparece en pantalla (el
   * dock al abrirse): ahí no hay que animar nada, el usuario no vio el estado
   * anterior. Con historial largo el viaje suave dura casi un segundo y se lee
   * como si algo se estuviera cargando solo — misma razón que `firstScroll`.
   *
   * `firstScroll` se repone porque el auto-scroll lo consume UNA vez por vida
   * del hook, y el dock se abre muchas veces sin desmontarlo.
   */
  const jumpToBottom = () => {
    const el = scrollRef.current
    if (!el) return
    autoScrollAt.current = Date.now()
    el.scrollTo({ top: el.scrollHeight, behavior: "auto" })
    firstScroll.current = true
    setAtBottom(true)
  }

  // ── Adjuntos ──────────────────────────────────────────────────────────────
  /** Sube a Tigris y deja el adjunto listo; el envío manda solo la metadata. */
  const uploadFiles = async (files: File[]) => {
    if (!files.length) return
    setUploading((n) => n + files.length)
    await Promise.all(
      files.map(async (file) => {
        try {
          const fd = new FormData()
          fd.set("file", file)
          const res = await fetch("/api/asistente/upload", {
            method: "POST",
            body: fd,
          })
          const data = await res.json()
          if (!res.ok || !data?.url) throw new Error(data?.error || "upload")
          setAttachments((prev) => [
            ...prev,
            {
              url: data.url,
              name: data.name,
              contentType: data.contentType,
              size: data.size,
            },
          ])
        } catch (e) {
          console.error("[asistente] upload", e)
          setAttachments((prev) => [
            ...prev,
            { url: "", name: file.name, contentType: file.type, error: true },
          ])
        } finally {
          setUploading((n) => Math.max(0, n - 1))
        }
      }),
    )
  }

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragging(false)
    if (isLocalhost) return
    uploadFiles(Array.from(e.dataTransfer.files || []))
  }

  /** Pegar una captura del portapapeles la adjunta, como en ChatGPT. */
  const onPaste = (e: React.ClipboardEvent) => {
    const files = Array.from(e.clipboardData.files || [])
    if (!files.length) return
    e.preventDefault()
    uploadFiles(files)
  }

  // ── Envío / streaming ─────────────────────────────────────────────────────
  /**
   * Envía y consume el SSE token a token (mismo transporte que la burbuja
   * pública). Los adjuntos viajan como metadata: el server los baja del bucket
   * y los entrega por la superficie de media de la flota.
   */
  const submit = async (content: string, files: Attachment[] = []) => {
    const trimmed = content.trim()
    const usable = files.filter((f) => f.url && !f.error)
    if (!trimmed && !usable.length) return
    /* `streaming` bloquea el envío, así que si se queda encendido por error el
       panel queda MUERTO: el composer muestra "Detener", los puntitos giran y
       todo lo que escribas se descarta en silencio, sin que salga una sola
       petición. Pasó en producción.
   
       `abortRef` es la prueba de vida: si hay un turno de verdad en curso, hay
       un controller. Sin él, `streaming` está mintiendo y se sigue adelante en
       vez de dejar al usuario atrapado hasta que recargue. */
    if (streaming) {
      if (abortRef.current) return
      console.warn("[asistente] streaming colgado sin turno vivo; se ignora")
    }

    /* Antes de nada, y ANTES de vaciar el input: si esto falla, el usuario
       conserva lo que escribió. En el editor de landing aquí se persiste el
       lienzo, para que Nik lea el HTML que el usuario está viendo y no una
       versión vieja. */
    if (beforeSubmit) {
      try {
        await beforeSubmit()
      } catch (e) {
        console.error("[asistente] beforeSubmit falló", e)
        setError(
          e instanceof Error && e.message
            ? e.message
            : "No se pudo preparar el envío.",
        )
        return
      }
    }

    setInput("")
    setAttachments([])
    setAtBottom(true) // al escribir siempre seguimos el hilo
    setError(null)
    lastTurnRef.current = { text: trimmed, attachments: usable }
    const screenKey = screen ? JSON.stringify(screen) : null
    const hasSelection = Boolean(
      (screen as { params?: { dataId?: unknown } } | undefined)?.params?.dataId,
    )

    const stamp = Date.now()
    const userKey = `tmp_u_${stamp}`
    const assistantKey = `tmp_a_${stamp}`
    setMessages((prev) => [
      ...prev,
      {
        id: userKey,
        key: userKey,
        role: "user",
        content: trimmed,
        attachments: usable,
        status: "delivered",
        createdAt: new Date().toISOString(),
      },
    ])
    const patchAssistant = (
      fn: (prev: string) => string,
      extra?: Partial<Msg>,
    ) =>
      setMessages((prev) => {
        const found = prev.some((m) => m.key === assistantKey)
        if (!found) {
          return [
            ...prev,
            {
              id: assistantKey,
              key: assistantKey,
              role: "assistant",
              content: fn(""),
              status: "delivered",
              createdAt: new Date().toISOString(),
              ...extra,
            },
          ]
        }
        return prev.map((m) =>
          m.key === assistantKey
            ? { ...m, content: fn(m.content), ...extra }
            : m,
        )
      })

    /* Traza de tools del turno: al llegar una nueva, la anterior se da por
       terminada (la flota no emite un evento de cierre por tool). */
    const patchTools = (fn: (prev: ToolRun[]) => ToolRun[]) =>
      setMessages((prev) => {
        const found = prev.some((m) => m.key === assistantKey)
        if (!found) {
          return [
            ...prev,
            {
              id: assistantKey,
              key: assistantKey,
              role: "assistant",
              content: "",
              tools: fn([]),
              status: "delivered",
              createdAt: new Date().toISOString(),
            },
          ]
        }
        return prev.map((m) =>
          m.key === assistantKey ? { ...m, tools: fn(m.tools ?? []) } : m,
        )
      })

    const addTool = (name: string) => {
      patchTools((prev) => [
        ...prev.map((t) => ({ ...t, done: true })),
        { name, label: toolLabel(name), done: false },
      ])
      /* `run_tool` es el enmascaramiento de codemode: el nombre real viaja en
         argumentos que el SSE no trae, así que la traza decía "Usando una
         herramienta de Deník" una y otra vez. Nuestro dispatch sí lo conoce —se
         le pregunta y se reemplaza la etiqueta en cuanto conteste.

         Es cosmético a propósito: si falla o llega vacío, se queda el texto
         genérico. Y va sin await para no retrasar el pintado del renglón, que
         es lo que le dice al usuario que algo está pasando. */
      if (bareName(name) !== "run_tool") return
      fetch("/api/asistente/last-tool")
        .then((r) => (r.ok ? r.json() : null))
        .then((d: { name?: string } | null) => {
          const real = d?.name
          if (!real) return
          patchTools((prev) =>
            prev.map((t) =>
              t.name === name && t.label === toolLabel(name)
                ? { ...t, label: toolLabel(real) }
                : t,
            ),
          )
        })
        .catch(() => {})
    }
    const finishTools = () =>
      patchTools((prev) =>
        prev.some((t) => !t.done)
          ? prev.map((t) => ({ ...t, done: true }))
          : prev,
      )

    /* ¿El último evento fue una tool? Decide si el texto siguiente abre bloque.
       Vive por TURNO, no en un ref: es estado del stream que se está leyendo. */
    let trasTool = false

    const controller = new AbortController()
    abortRef.current = controller
    /* Se enciende JUNTO al controller y pegado al try, no antes: estaba fuera, y
       cualquier excepción entre ese punto y el `fetch` dejaba `streaming` en
       true para siempre porque el `finally` que lo apaga todavía no existía. */
    setStreaming(true)

    try {
      const res = await fetch("/api/asistente/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text: trimmed,
          attachments: usable,
          // Desde dónde se escribió. Sólo para la métrica: responde si el dock
          // es lo que dispara el consumo o si la gente sigue yendo a la página.
          surface,
          /* La pantalla viaja SIEMPRE (el ledger quiere saber desde dónde salió
             cada turno), pero sólo entra al system prompt cuando CAMBIÓ: la
             conversación de la flota es sticky por groupId, y repetir el mismo
             contexto en cada mensaje lo hace variar sin aportar nada. Si no te
             moviste de pantalla, ya lo sabe. */
          ...(screen ? { screen } : {}),
          /* La SELECCIÓN es contexto POR MENSAJE, no ambiental: si el usuario
             manda dos peticiones sobre el mismo nodo, la segunda tiene que
             volver a decir cuál. Con la regla de "sólo si cambió" el segundo
             mensaje salía sin él y el agente contestaba "no me llega
             automático, dime cuál" — con el chip a la vista. Es la misma
             garantía de determinismo del @-mention: si lo adjuntaste, viaja. */
          screenChanged: Boolean(
            hasSelection || (screenKey && screenKey !== sentScreenRef.current),
          ),
        }),
        signal: controller.signal,
      })
      if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`)
      // Se marca DESPUÉS de que el server aceptó: si el POST falló, el contexto
      // no llegó y el próximo turno tiene que volver a mandarlo.
      if (screenKey) sentScreenRef.current = screenKey

      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ""
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        // El parser vive en `~/components/asistente/sse` y es el MISMO que usa
        // el capturador del servidor: antes eran dos copias de la gramática y
        // se desincronizaban. `rest` es el frame que quedó a medias entre dos
        // lecturas — hay que re-alimentarlo o el mensaje sale truncado.
        const { events, rest } = parseSseBuffer(buffer)
        buffer = rest
        for (const evt of events) {
          if (evt.type === "chunk") {
            // Empezó a escribir → todas las tools quedaron listas.
            finishTools()
            /* Punto y APARTE cuando el texto retoma después de una tool.
   
               Los trozos se concatenaban crudos, así que la frase nueva quedaba
               pegada a la anterior: "…que ya sé que falla).Verifico una sola
               vez…". No es un fallo del modelo — él manda dos tramos distintos,
               separados por su trabajo; el pegote lo hacíamos aquí.
   
               Cada tramo es un paso ("busqué la foto", "la apliqué",
               "verifiqué"), así que se lee mucho mejor como lista, que es lo que
               hace ghosty-teams. Sólo el PRIMER trozo tras la tool abre bloque:
               los siguientes siguen concatenando o partiría cada palabra. */
            patchAssistant((prev) => {
              const separa =
                trasTool && prev && !/\n\s*$/.test(prev) && evt.value.trim()
              trasTool = false
              return separa
                ? `${prev.trimEnd()}\n\n${evt.value}`
                : prev + evt.value
            })
          } else if (evt.type === "done") {
            // Reply autoritativo: sobreescribe el preview de los chunks.
            finishTools()
            /* Apagar la animación ANTES del swap: el reply completo puede
               diferir del preview y hacer que React recree los nodos — con la
               clase puesta, el mensaje entero volvería a animarse de golpe. */
            setStreaming(false)
            /* El `done` trae la respuesta autoritativa CONCATENADA, así que
               pisaría los cortes que se hicieron durante el stream. Se separa
               igual: si no, el texto se ve bien mientras llega y se pega justo
               al terminar, que es el peor momento. */
            patchAssistant(() => splitGluedSentences(evt.value))
          } else if (evt.type === "tool") {
            /* gs manda `start` y `end` por tool (la flota, uno sin `phase`): la
               traza se pinta al empezar y el aviso de afuera va al terminar,
               cuando lo que escribió la tool ya está guardado. */
            if (evt.phase !== "end") {
              /* Se traza en el propio mensaje (no en un texto suelto) para que
                 quede en el historial del turno, como en claude.ai. */
              addTool(evt.name)
              // El texto que venga después arranca en bloque nuevo (ver arriba).
              trasTool = true
            }
            /* Y se avisa afuera: el editor de landing lo usa para refrescar el
               lienzo en cuanto Nik escribe. Va en try/catch porque un caller
               roto no puede tumbar el stream del turno. */
            if (evt.phase !== "start") {
              try {
                onTool?.(evt.name)
              } catch (e) {
                console.error("[asistente] onTool falló", e)
              }
            }
          } else if (evt.type === "error") {
            /* El texto que ya llegó se conserva (`prev ||`): una respuesta
               cortada a la mitad sigue siendo útil. Pero el aviso NO puede
               quedarse sólo ahí, porque en ese caso no se escribiría nada y el
               fallo sería invisible — de ahí el estado `error` aparte. */
            patchAssistant(
              (prev) => prev || "El asistente no pudo completar la respuesta.",
              { failed: true },
            )
            setError(
              evt.message
                ? `La respuesta se interrumpió: ${evt.message}`
                : "La respuesta se interrumpió.",
            )
          }
        }
      }
    } catch (err) {
      if ((err as Error)?.name === "AbortError") {
        // Detenido a propósito: lo que ya llegó se conserva (el server igual
        // persiste la respuesta completa del agente).
        patchAssistant((prev) => prev || "_Respuesta detenida._")
      } else {
        patchAssistant((prev) => prev || "No pude conectar con el asistente.", {
          failed: true,
        })
        setError("No pude conectar con el asistente.")
      }
    } finally {
      abortRef.current = null
      setStreaming(false)
      inputRef.current?.focus()
    }
  }

  const stop = () => abortRef.current?.abort()

  /** Reintenta el último turno: quita el mensaje fallido y lo manda otra vez. */
  const retry = () => {
    const turn = lastTurnRef.current
    if (!turn || streaming) return
    setMessages((prev) => {
      const next = [...prev]
      // Quita la respuesta fallida y el eco del usuario: submit los repone.
      if (next[next.length - 1]?.role === "assistant") next.pop()
      if (next[next.length - 1]?.role === "user") next.pop()
      return next
    })
    submit(turn.text, turn.attachments)
  }

  const onSend = (e: React.FormEvent) => {
    e.preventDefault()
    submit(input, attachments)
  }

  /** Enter envía; Shift+Enter hace salto de línea (estándar de chat). */
  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
      e.preventDefault()
      submit(input, attachments)
    }
  }

  const isEmpty = messages.length === 0
  const canSend =
    !isLocalhost &&
    !streaming &&
    !uploading &&
    (Boolean(input.trim()) || attachments.some((a) => a.url && !a.error))

  /** Borra el hilo. La CONFIRMACIÓN es del caller: el dock y la página la
   *  piden distinto, y un `confirm()` aquí obligaría a las dos a lo mismo. */
  const reset = async () => {
    const fd = new FormData()
    fd.set("intent", "reset")
    await fetch("/api/asistente", { method: "POST", body: fd })
    setMessages([])
    setHasMore(false)
  }
  return {
    // estado
    messages,
    input,
    setInput,
    streaming,
    attachments,
    setAttachments,
    uploading,
    dragging,
    setDragging,
    hasMore,
    loadingMore,
    atBottom,
    /** Aviso del último fallo, fuera del hilo. `null` si todo bien. */
    error,
    isEmpty,
    waitingAssistant,
    /** Texto del último mensaje: lo lee la región aria-live de la UI. */
    lastContent,
    canSend,
    // refs que la UI necesita enganchar
    bottomRef,
    scrollRef,
    inputRef,
    fileRef,
    // acciones
    submit,
    stop,
    retry,
    reset,
    loadOlder,
    onThreadScroll,
    scrollToBottom,
    jumpToBottom,
    uploadFiles,
    onDrop,
    onPaste,
    onSend,
    onKeyDown,
  }
}
