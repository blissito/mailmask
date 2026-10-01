import { AnimatePresence, motion } from "motion/react"
import {
  Fragment,
  type MutableRefObject,
  type ReactNode,
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from "react"

import { AssistantText } from "./AssistantText"
import {
  AttachmentChip,
  AttachmentList,
} from "./AttachmentList"
import { CopyButton } from "./CopyButton"
import {
  DaySeparator,
  needsDaySeparator,
} from "./DaySeparator"
import { ClipIcon, SendIcon, TypingDots } from "./icons"
import {
  type ActionOutcome,
  PendingActionList,
} from "./PendingActionCard"
import { SUGGESTIONS } from "./suggestions"
import { ToolTrace } from "./ToolTrace"
import {
  type RawMsg,
  useAssistantChat,
} from "./useAssistantChat"
import { usePendingActions } from "./usePendingActions"
import { ASSISTANT_ICON, ASSISTANT_NAME } from "./brand"
import { playReplyDone } from "./sound"
import { useCurrentScreen } from "./screen"

/**
 * Nik en todas las pantallas del dash.
 *
 * El caso que justifica esto es "cancela mi cita de las 3" **mientras estás
 * mirando la agenda**: con Nik en una pantalla aparte, pedírselo obliga a
 * abandonar lo que estabas haciendo, que es exactamente cuando ya no vale la
 * pena.
 *
 * ## Decisiones que no son cosméticas
 *
 * - **Cerrado es una astilla, no un botón.** En reposo la pestaña vive medio
 *   fuera de pantalla (`translate-x-[14px]`) al 60% de opacidad; el hover la
 *   mete. Un FAB opaco en cada pantalla del dash compite con el contenido para
 *   siempre, y el contenido es el trabajo del usuario.
 * - **En mobile NO hay pestaña en el borde.** El gesto de "atrás" de Android es
 *   dueño de los bordes verticales a nivel de sistema (~20dp, no se desactiva
 *   desde una página) y Safari usa el derecho para avanzar. Ahí el disparador es
 *   una pastilla en la esquina, apilada sobre el FAB de asistencias.
 * - **Arriba de 1280px EMPUJA el contenido; abajo se superpone.** Empujar es lo
 *   que permite el caso que justifica todo esto: Nik te lleva a la pantalla y te
 *   señala la fila que cambió — con el panel encima taparía justo eso. El hueco
 *   lo reserva el `SideBar` (ver `DOCK_WIDTH` y `useDockSplit`), que además
 *   colapsa el sidebar mientras tanto para que el costo neto sea 244px.
 *   En desktop **no hay backdrop**: el dash sigue clickeable detrás.
 * - **La conversación es la MISMA que la de `/dash/asistente`** (`groupId`
 *   determinista por org): lo que le pidas aquí lo ves allá y al revés.
 *
 * El estado abierto/cerrado no se persiste a propósito: `dash_layout` no se
 * desmonta al navegar entre rutas del dash, así que el dock sobrevive la
 * navegación sin cookie ni localStorage. Un reload lo cierra, que es el default
 * correcto.
 */
/** Ancho por default cuando el dock NO empuja (se superpone). */
export const DOCK_WIDTH = 420

/**
 * **Componente controlado**: el estado abierto/cerrado lo tiene el `SideBar`.
 *
 * Nació con estado propio, pero al hacer que el dock empuje el contenido y
 * colapse el sidebar, el `SideBar` necesita poder cerrarlo: con el dock abierto
 * el sidebar está colapsado a la fuerza, así que ⌘B sólo cambiaba la preferencia
 * de fondo — el botón animaba y no se abría nada. Ahora ⌘B en ese estado cierra
 * el dock, que es lo que el usuario está pidiendo.
 *
 * Sigue sin persistirse: `dash_layout` no se desmonta al navegar entre rutas del
 * dash, así que el dock sobrevive la navegación sin cookie; un reload lo cierra.
 */
export function AssistantDock({
  stacked = false,
  hasBottomNav = true,
  open,
  onOpenChange,
  width,
  prefill,
}: {
  /** El FAB de asistencias pendientes ya ocupa la esquina: hay que subirse. */
  stacked?: boolean
  hasBottomNav?: boolean
  open: boolean
  onOpenChange: (open: boolean) => void
  /**
   * Ancho cuando EMPUJA, decidido por `useDockSplit` (se encoge en pantallas
   * medianas antes de rendirse a superponerse). Llega por prop y no por
   * constante porque el `SideBar` reserva exactamente este hueco: si los dos
   * lados tuvieran su propio número y se desincronizaran, el contenido quedaría
   * debajo del panel o con una franja vacía al lado. `undefined` = superpuesto.
   */
  width?: number
  /**
   * Texto para dejar escrito en la caja (botones "Pídeselo al asistente" de
   * `app.js`). `n` cambia en cada petición para que repetir el mismo texto
   * también se aplique.
   */
  prefill?: { text: string; n: number } | null
}) {
  const setOpen = onOpenChange
  const triggerRef = useRef<HTMLButtonElement>(null)

  /**
   * Último historial conocido, para que reabrir el dock NO parpadee.
   *
   * `AnimatePresence` desmonta el panel al cerrar (es lo que anima la salida),
   * así que cada apertura lo re-montaba y volvía a pedir `/api/asistente` desde
   * cero: spinner y conversación en blanco durante el fetch, cada vez, aunque no
   * hubiera pasado nada. Guardar la copia aquí —donde nada se desmonta— hace que
   * la segunda apertura pinte al instante.
   *
   * El panel igual revalida en segundo plano: es la fuente de verdad, y sin eso
   * un mensaje mandado en una apertura anterior no aparecería.
   */
  const cacheRef = useRef<{ messages: RawMsg[]; hasMore: boolean } | null>(null)

  // ⌘K abre y cierra. ⌘B es del sidebar y no se toca. Se ignora si el foco está
  // escribiendo en otro lado: robarle el atajo a un campo de texto es peor que
  // no tener atajo.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && open) {
        setOpen(false)
        triggerRef.current?.focus()
        return
      }
      if (e.key !== "k" || !(e.metaKey || e.ctrlKey)) return
      const el = document.activeElement as HTMLElement | null
      if (el?.isContentEditable) return
      e.preventDefault()
      setOpen(!open)
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [open])

  const bottom = stacked
    ? hasBottomNav
      ? "bottom-[calc(144px+env(safe-area-inset-bottom))]"
      : "bottom-[calc(80px+env(safe-area-inset-bottom))]"
    : hasBottomNav
      ? "bottom-[calc(80px+env(safe-area-inset-bottom))]"
      : "bottom-[calc(16px+env(safe-area-inset-bottom))]"

  return (
    <>
      {/* Desktop: la astilla del borde derecho. */}
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setOpen(!open)}
        aria-label="Abrir asistente (⌘K)"
        aria-expanded={open}
        className={`fixed right-0 top-1/2 -translate-y-1/2 z-[56] hidden md:flex w-9 h-24 items-center justify-center rounded-l-2xl bg-bg-elev/90 backdrop-blur-sm border border-r-0 border-line shadow-[0_2px_12px_rgba(17,21,26,0.06)] transition-all duration-200 ease-out motion-reduce:transition-none hover:opacity-100 hover:translate-x-0 ${
          open
            ? "opacity-0 pointer-events-none"
            : "opacity-60 translate-x-[14px]"
        }`}
      >
        <img src={ASSISTANT_ICON} alt="" className="w-5 h-5 object-contain" />
      </button>

      {/* Mobile: pastilla en la esquina, apilada sobre el FAB de asistencias. */}
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-label="Abrir asistente"
        className={`md:hidden fixed right-4 z-[55] w-12 h-12 rounded-full bg-bg-elev border border-line shadow-lg flex items-center justify-center ${bottom} ${
          open ? "hidden" : ""
        }`}
      >
        <img src={ASSISTANT_ICON} alt="" className="w-6 h-6 object-contain" />
      </button>

      <AnimatePresence>
        {open && (
          <DockPanel
            onClose={() => setOpen(false)}
            cache={cacheRef}
            width={width}
            prefill={prefill}
          />
        )}
      </AnimatePresence>
    </>
  )
}

/**
 * ¿Es el mismo hilo? Basta con cuántos son y cuál es el último: los mensajes no
 * se editan, sólo se agregan. Comparar el array completo sería más caro y no
 * diría nada distinto.
 */
const sameThread = (a: RawMsg[] | undefined, b: RawMsg[]) =>
  !!a && a.length === b.length && a[a.length - 1]?.id === b[b.length - 1]?.id

/**
 * Carga el historial ANTES de montar el chat.
 *
 * `useAssistantChat` sólo lee `initialMessages` al inicializarse (la página se
 * los pasa desde su loader), así que sembrarlos después no serviría: el dock
 * abriría en blanco y la conversación aparecería recién al mandar el siguiente
 * mensaje. Sin esto, recargar el dash "borraba" el hilo a ojos del usuario
 * aunque en la DB estuviera intacto.
 */
function DockPanel({
  onClose,
  cache,
  width,
  prefill,
}: {
  onClose: () => void
  cache: MutableRefObject<{ messages: RawMsg[]; hasMore: boolean } | null>
  width?: number
  prefill?: { text: string; n: number } | null
}) {
  // Arranca de la copia de la apertura anterior (ver `cacheRef` arriba): sin
  // ella la segunda apertura mostraba spinner y conversación vacía.
  const [history, setHistory] = useState<RawMsg[] | null>(
    cache.current?.messages ?? null,
  )
  /* Sin esto el hook arranca con `hasMore: false` y `loadOlder` sale siempre
     por su guard: el scroll infinito del dock estaba MUERTO y el hilo se
     cortaba en seco, como si las conversaciones viejas se hubieran borrado. */
  const [hasMore, setHasMore] = useState(cache.current?.hasMore ?? false)
  /* Remonta el chat al reiniciar: `useAssistantChat` toma `initialMessages`
     sólo al inicializarse, así que la única forma de dejarlo realmente vacío
     es montarlo de nuevo. */
  const [threadKey, setThreadKey] = useState(0)

  useEffect(() => {
    let alive = true
    fetch("/api/asistente")
      .then((r) => (r.ok ? r.json() : { messages: [] }))
      .then((d: { messages?: RawMsg[]; hasMore?: boolean }) => {
        if (!alive) return
        const messages = d.messages ?? []
        const fresh = { messages, hasMore: Boolean(d.hasMore) }
        const prev = cache.current
        cache.current = fresh
        setHasMore(fresh.hasMore)
        /* Si el servidor trae lo mismo que ya estamos mostrando, NO se toca el
           estado: re-sembrar remontaría el chat (`threadKey`) y tiraría lo que
           el usuario tuviera escrito. Sólo se re-siembra cuando de verdad
           cambió — p.ej. mandó algo en una apertura anterior, o habló con Nik
           por WhatsApp, que va al mismo hilo. */
        if (sameThread(prev?.messages, messages)) return
        setHistory(messages)
        setThreadKey((k) => k + 1)
      })
      .catch(() => alive && setHistory((h) => h ?? []))
    return () => {
      alive = false
    }
  }, [cache])

  /* "Nueva conversación" y no "borrar": es como lo llaman ChatGPT, Claude y
     Sidekick, y describe lo que pasa. Se confirma porque Nik tiene memoria de
     lo hablado y no hay deshacer. */
  const reset = async () => {
    if (!confirm("¿Empezar una conversación nueva? Se borrará la actual."))
      return
    const fd = new FormData()
    fd.set("intent", "reset")
    await fetch("/api/asistente", { method: "POST", body: fd })
    cache.current = { messages: [], hasMore: false }
    setHistory([])
    setHasMore(false)
    setThreadKey((k) => k + 1)
  }

  return (
    <DockShell
      onClose={onClose}
      onReset={history?.length ? reset : undefined}
      width={width}
    >
      {history === null ? (
        <div className="flex-1 flex items-center justify-center">
          <TypingDots />
        </div>
      ) : (
        <DockChat
          key={threadKey}
          initialMessages={history}
          initialHasMore={hasMore}
          onClose={onClose}
          prefill={prefill}
        />
      )}
    </DockShell>
  )
}

function DockChat({
  initialMessages,
  initialHasMore,
  onClose,
  prefill,
}: {
  initialMessages: RawMsg[]
  initialHasMore: boolean
  onClose: () => void
  prefill?: { text: string; n: number } | null
}) {
  // La pantalla en la que está parado el usuario: el dominio y la pestaña que
  // `app.js` publica en `window.mailmaskScreen` (ver `screen.ts`).
  const screen = useCurrentScreen()

  const {
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
    loadOlder,
    atBottom,
    scrollToBottom,
    jumpToBottom,
    error,
    isEmpty,
    waitingAssistant,
    lastContent,
    canSend,
    bottomRef,
    scrollRef,
    inputRef,
    fileRef,
    submit,
    stop,
    retry,
    uploadFiles,
    onDrop,
    onPaste,
    onSend,
    onKeyDown,
    onThreadScroll,
  } = useAssistantChat({
    initialMessages,
    initialHasMore,
    screen,
    surface: "dock",
    // En agenda se apagaba en localhost (no hay flota local). En MailMask el
    // backend habla con Ghosty también en dev, así que se deja mandar.
    isLocalhost: false,
  })

  /* "Pídeselo al asistente": deja el texto escrito y el foco en la caja, sin
     mandarlo — el usuario lo revisa y da Enter. */
  useEffect(() => {
    if (!prefill?.text) return
    setInput(prefill.text)
    const t = setTimeout(() => {
      const el = inputRef.current
      if (!el) return
      el.focus()
      el.setSelectionRange(el.value.length, el.value.length)
      el.style.height = "auto"
      el.style.height = `${Math.min(el.scrollHeight, 120)}px`
    }, 280)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefill?.n])

  /* Al ABRIR, el hilo arranca abajo.

     `DockChat` se monta dentro de `{open && …}`, así que esto corre en cada
     apertura. El auto-scroll del hook no bastaba: depende de
     [messages.length, lastContent, …] y con el historial ya sembrado en
     `initialMessages` ninguna cambia después del montaje, así que el
     contenedor —recién montado, con scrollTop 0— se quedaba arriba.

     Se salta DOS veces a propósito: en el layout (antes del paint) y en el
     siguiente frame. El alto del hilo sigue creciendo después del primer
     cálculo (miniaturas de adjuntos, markdown que envuelve), y sin el segundo
     salto el hilo queda cerca del final pero no en él. Los dos son
     instantáneos, así que no se ve ningún viaje. */
  useLayoutEffect(() => {
    jumpToBottom()
    const raf = requestAnimationFrame(jumpToBottom)
    return () => cancelAnimationFrame(raf)
    // Sólo al montar: `jumpToBottom` se recrea en cada render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // En mobile el panel tapa la pantalla: quedarse abierto sobre el destino no
  // tiene sentido. En desktop se queda, que es todo el punto del dock.
  const closeIfMobile = useCallback(() => {
    if (window.matchMedia("(max-width: 767px)").matches) onClose()
  }, [onClose])

  const {
    actions: pendingActions,
    refresh: refreshPending,
    confirm,
    reject,
  } = usePendingActions()

  /* Al terminar un turno: recargar pendientes Y AVISAR A `app.js`.
     Nik acaba de mover datos —agendó, canceló, cobró— y la pantalla de atrás
     los está mostrando: sin esto, el usuario ve que Nik dice "listo, agendado"
     mientras su calendario sigue vacío, y no sabe a cuál de los dos creerle.
     Es el bug que hace que un asistente omnipresente se sienta roto. */
  // Sin router no hay `useRevalidator`: `app.js` escucha este evento y recarga
  // el dominio seleccionado y la lista de dominios.
  const revalidate = useCallback(() => {
    window.dispatchEvent(new CustomEvent("assistant:turn-end"))
  }, [])
  const wasStreaming = useRef(false)
  useEffect(() => {
    if (wasStreaming.current && !streaming) {
      void refreshPending()
      revalidate()
      playReplyDone()
    }
    wasStreaming.current = streaming
  }, [streaming, refreshPending, revalidate])

  // Y también al aprobar una acción: ahí la mutación la hace el servidor.
  const resolveAndRevalidate = useCallback(
    async (fn: (id: string) => Promise<ActionOutcome>, id: string) => {
      const outcome = await fn(id)
      if (outcome === "executed") revalidate()
      return outcome
    },
    [revalidate],
  )

  // (El bloqueo de scroll en mobile vive en `DockShell`, que es quien monta el
  // backdrop. Estaba duplicado aquí, idéntico, corriendo dos veces.)

  // El foco al abrir va a la caja: el dock se abre para escribir algo.
  useEffect(() => {
    const t = setTimeout(() => inputRef.current?.focus(), 260)
    return () => clearTimeout(t)
  }, [inputRef])

  return (
    <div
      className="flex-1 flex flex-col min-h-0 relative"
      onDragOver={(e) => {
        e.preventDefault()
        setDragging(true)
      }}
      onDragLeave={(e) => {
        // Sólo cuando el puntero SALE del panel, no al cruzar hijos.
        if (e.currentTarget.contains(e.relatedTarget as Node)) return
        setDragging(false)
      }}
      onDrop={onDrop}
    >
      <section
        ref={scrollRef}
        /* Sin esto `atBottom` se quedaba congelado: el hilo dejaba de seguir
             a la respuesta mientras Nik escribía y el texto nuevo quedaba fuera
             de vista. También es lo que dispara cargar mensajes viejos al
             llegar arriba. */
        onScroll={onThreadScroll}
        className="asis-scroll flex-1 overflow-y-auto min-h-0 px-4 py-5 flex flex-col gap-5"
      >
        {isEmpty ? (
          <div className="m-auto flex flex-col items-center gap-4 text-center">
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="relative flex items-center justify-center"
            >
              <img
                src={ASSISTANT_ICON}
                alt={ASSISTANT_NAME}
                className="w-20 h-20 object-contain"
              />
              <span className="absolute -top-1 -right-1 text-lg">✨</span>
            </motion.div>
            <p className="text-sm text-fg-muted max-w-[16rem]">
              Pregúntale algo sobre tus dominios, alias, DNS o correo.
            </p>
            <div className="flex flex-col gap-2 w-full">
              {SUGGESTIONS.map((s, i) => (
                <motion.button
                  key={s.text}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.05 * i }}
                  onClick={() => submit(s.text)}
                  className="flex items-center gap-2 text-left text-sm font-medium text-fg bg-bg-elev border border-line rounded-full px-3.5 py-2 hover:border-accent hover:text-accent-text transition"
                >
                  <span className="text-base leading-none">{s.icon}</span>
                  <span>{s.text}</span>
                </motion.button>
              ))}
            </div>
          </div>
        ) : (
          <>
            {hasMore && (
              <button
                type="button"
                onClick={loadOlder}
                disabled={loadingMore}
                className="self-center text-xs font-medium text-fg-muted hover:text-fg px-3 py-1.5 rounded-full hover:bg-fg/5 transition disabled:opacity-50"
              >
                {loadingMore ? "Cargando…" : "Ver mensajes anteriores"}
              </button>
            )}
            {messages.map((m, i) => (
              <Fragment key={m.key ?? m.id}>
                {needsDaySeparator(messages[i - 1], m) && (
                  <DaySeparator date={m.createdAt} />
                )}
                {m.role === "user" ? (
                  <motion.div
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="self-end max-w-[85%] flex flex-col items-end gap-1"
                  >
                    {!!m.attachments?.length && (
                      <AttachmentList items={m.attachments} />
                    )}
                    {/* `break-words` + `min-w-0`: una URL sin espacios no
                        envuelve sola y se sale de la burbuja (a 420px del dock,
                        por la izquierda). */}
                    {!!m.content && (
                      <div className="rounded-3xl rounded-br-lg bg-fg text-bg px-4 py-2.5 text-sm whitespace-pre-wrap break-words min-w-0 font-medium">
                        {m.content}
                      </div>
                    )}
                  </motion.div>
                ) : (
                  <motion.div
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="group flex gap-2.5 w-full"
                  >
                    <img
                      src={ASSISTANT_ICON}
                      alt=""
                      className="w-6 h-6 object-contain shrink-0 mt-0.5"
                    />
                    <div className="min-w-0 flex-1 text-sm">
                      {!!m.tools?.length && <ToolTrace tools={m.tools} />}
                      <AssistantText
                        text={m.content}
                        streaming={streaming && i === messages.length - 1}
                        onNavigate={closeIfMobile}
                      />
                      {!!m.content && (
                        <div className="mt-1 flex items-center gap-1 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
                          <CopyButton text={m.content} />
                          {m.failed && i === messages.length - 1 && (
                            <button
                              onClick={retry}
                              className="text-xs font-medium text-fg-muted hover:text-fg px-2 py-1 rounded-lg hover:bg-fg/5 transition"
                            >
                              Reintentar
                            </button>
                          )}
                        </div>
                      )}
                    </div>
                  </motion.div>
                )}
              </Fragment>
            ))}
          </>
        )}

        {/* Región viva: un lector de pantalla anuncia la respuesta */}
        <div aria-live="polite" className="sr-only">
          {waitingAssistant ? `${ASSISTANT_NAME} está escribiendo` : lastContent}
        </div>

        {/* Sin esto el panel se queda en blanco desde que mandas hasta que
              llega el primer token, y parece que no pasó nada. */}
        <AnimatePresence>
          {waitingAssistant && (
            <motion.div
              key="typing"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.9 }}
              transition={{ duration: 0.18 }}
              className="flex gap-2.5 items-center"
            >
              <img
                src={ASSISTANT_ICON}
                alt=""
                className="w-6 h-6 object-contain shrink-0"
              />
              <TypingDots />
            </motion.div>
          )}
        </AnimatePresence>
        <div ref={bottomRef} />
      </section>

      <div className="relative shrink-0">
        <AnimatePresence>
          {!atBottom && !isEmpty && (
            <motion.button
              type="button"
              onClick={scrollToBottom}
              initial={{ opacity: 0, y: 8, scale: 0.9 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 8, scale: 0.9 }}
              whileTap={{ scale: 0.92 }}
              aria-label="Ir al final"
              className="absolute -top-10 left-1/2 -translate-x-1/2 z-10 w-9 h-9 rounded-full bg-bg-elev border border-line shadow-[0_4px_16px_rgba(0,0,0,0.12)] text-fg flex items-center justify-center"
            >
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M12 5v14M19 12l-7 7-7-7" />
              </svg>
            </motion.button>
          )}
        </AnimatePresence>

        {/*
          Las acciones por aprobar viven en la zona FIJA, no al final del hilo.

          Estaban dentro del scroll, después del último mensaje — o sea que
          verlas dependía de haber scrolleado hasta abajo. Con el auto-scroll
          roto no aparecían nunca, y el usuario reportó que jamás había visto una
          confirmación: Nik decía "quedó pendiente de aprobación" y no había nada
          que aprobar a la vista. Los dos bugs eran el mismo.

          Aunque el scroll ya esté arreglado, esto no puede depender de él: es lo
          único de la interfaz que BLOQUEA trabajo del usuario, y una cosa que
          bloquea no se esconde en el historial.
        */}
        {/* SIN `max-height` ni scroll propio: al capar el alto, el card quedaba
            recortado justo donde están sus botones — visible pero imposible de
            aprobar, que es peor que no mostrarlo. El card es compacto y el
            `flex-1 min-h-0` del hilo ya le cede el espacio que necesita. */}
        {!!pendingActions.length && (
          <div className="px-3 pb-2">
            <PendingActionList
              actions={pendingActions}
              max={1}
              onConfirm={(id) => resolveAndRevalidate(confirm, id)}
              onReject={reject}
            />
          </div>
        )}

        {/* El fallo tiene que verse aunque el mensaje del asistente quedara
            vacío: ahí `m.failed` no se ve porque no hay burbuja que marcar. */}
        {error && (
          <div className="mx-3 mb-1 flex items-center gap-2 rounded-xl bg-red-500/10 border border-red-500/30 px-3 py-2 text-xs text-red-600 font-medium">
            <span className="flex-1">{error}</span>
            <button
              type="button"
              onClick={retry}
              className="shrink-0 underline underline-offset-2 hover:no-underline"
            >
              Reintentar
            </button>
          </div>
        )}

        <form
          onSubmit={onSend}
          className="px-3 pt-2 pb-[calc(10px+env(safe-area-inset-bottom))] md:pb-3"
        >
          <div className="bg-bg-elev rounded-3xl border border-line/70 shadow-[0_4px_24px_rgba(0,0,0,0.06)] px-2 py-1.5 focus-within:border-accent transition-colors">
            {(attachments.length > 0 || uploading > 0) && (
              <div className="flex flex-wrap gap-2 px-2 pt-1 pb-2">
                {attachments.map((a, i) => (
                  <AttachmentChip
                    key={`${a.url}-${i}`}
                    item={a}
                    onRemove={() =>
                      setAttachments((prev) => prev.filter((_, j) => j !== i))
                    }
                  />
                ))}
                {uploading > 0 && (
                  <span className="text-xs text-fg-muted font-medium self-center">
                    Subiendo {uploading}…
                  </span>
                )}
              </div>
            )}
            <div className="flex items-end gap-1">
              <input
                ref={fileRef}
                type="file"
                multiple
                hidden
                onChange={(e) => {
                  uploadFiles(Array.from(e.target.files || []))
                  // Sin esto, elegir el MISMO archivo dos veces seguidas no
                  // dispara `change` y parece que no pasó nada.
                  e.target.value = ""
                }}
              />
              <button
                type="button"
                onClick={() => fileRef.current?.click()}
                aria-label="Adjuntar archivo"
                title="Adjuntar archivo o imagen"
                className="w-9 h-9 shrink-0 rounded-full text-fg-muted hover:text-fg hover:bg-fg/5 flex items-center justify-center transition"
              >
                <ClipIcon />
              </button>
              <textarea
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={onKeyDown}
                onPaste={onPaste}
                rows={1}
                placeholder={`Pídele algo a ${ASSISTANT_NAME}…`}
                /* Auto-grow hasta ~5 líneas. El panel es angosto y sin esto un
                   mensaje de dos renglones se escribe a ciegas. */
                onInput={(e) => {
                  const el = e.currentTarget
                  el.style.height = "auto"
                  el.style.height = `${Math.min(el.scrollHeight, 120)}px`
                }}
                /* `border-0 ring-0 focus:ring-0`: el dash tiene un anillo de
                   foco global que, dentro de esta caja, dibujaba un segundo
                   recuadro azul encima del borde del contenedor. */
                className="flex-1 resize-none bg-transparent text-sm leading-6 py-2 px-1.5 max-h-[120px] outline-none border-0 ring-0 focus:outline-none focus:ring-0 placeholder:text-fg-muted asis-scroll"
              />
              {streaming ? (
                <motion.button
                  type="button"
                  onClick={stop}
                  whileTap={{ scale: 0.92 }}
                  aria-label="Detener"
                  title="Detener la respuesta"
                  className="w-9 h-9 shrink-0 rounded-full bg-fg text-bg flex items-center justify-center transition"
                >
                  <span className="w-2.5 h-2.5 rounded-[3px] bg-bg" />
                </motion.button>
              ) : (
                <motion.button
                  type="submit"
                  whileTap={{ scale: 0.92 }}
                  disabled={!canSend}
                  aria-label="Enviar"
                  className="w-9 h-9 shrink-0 rounded-full bg-accent text-white flex items-center justify-center disabled:opacity-40 transition"
                >
                  <SendIcon />
                </motion.button>
              )}
            </div>
          </div>
        </form>
      </div>

      {/* Sólo aparece arrastrando: un dropzone permanente ocuparía espacio en
            un panel angosto para algo que casi nadie hace. */}
      <AnimatePresence>
        {dragging && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="absolute inset-0 z-20 flex items-center justify-center bg-bg-elev/85 backdrop-blur-sm border-2 border-dashed border-accent rounded-2xl pointer-events-none"
          >
            <p className="text-sm font-medium text-accent-text">
              Suelta el archivo para adjuntarlo
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function DockShell({
  onClose,
  onReset,
  children,
  width,
}: {
  onClose: () => void
  /** Ausente mientras carga o si el hilo ya está vacío. */
  onReset?: () => void
  children: ReactNode
  /** Ver la prop `width` de `AssistantDock`. `undefined` = ancho por default. */
  width?: number
}) {
  // Sólo en mobile se bloquea el scroll del fondo: en desktop el dash tiene que
  // seguir usable con el dock abierto.
  useEffect(() => {
    const mobile = window.matchMedia("(max-width: 767px)").matches
    if (!mobile) return
    const prev = document.body.style.overflow
    document.body.style.overflow = "hidden"
    return () => {
      document.body.style.overflow = prev
    }
  }, [])

  return (
    <>
      {/* Backdrop SOLO en mobile: en desktop taparía el dash, que es justo lo
          que el dock viene a evitar. */}
      <motion.button
        type="button"
        aria-label="Cerrar asistente"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={onClose}
        className="md:hidden fixed inset-0 z-[56] bg-black/35 backdrop-blur-sm"
      />

      <motion.aside
        initial={{ x: "100%", opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        exit={{ x: "100%", opacity: 0 }}
        transition={{ type: "spring", stiffness: 380, damping: 38 }}
        role="dialog"
        aria-label={`Asistente ${ASSISTANT_NAME}`}
        /* El ancho va por variable CSS y no en el `animate` de motion: animarlo
           haría que el panel se re-dimensione mientras el usuario arrastra la
           ventana, encima de la animación de entrada. Aquí sólo tiene que
           SEGUIR al hueco que reserva el SideBar. */
        style={
          { "--dock-w": `${width ?? DOCK_WIDTH}px` } as React.CSSProperties
        }
        className="fixed z-[57] bg-bg-elev flex flex-col
          inset-x-0 bottom-0 h-[85dvh] rounded-t-3xl shadow-2xl
          md:inset-x-auto md:right-0 md:top-0 md:bottom-auto md:h-dvh md:w-[--dock-w] md:max-w-[92vw]
          md:rounded-none md:border-l md:border-line"
      >
        <header className="flex items-center gap-2 px-4 py-3 border-b border-line shrink-0">
          <img
            src={ASSISTANT_ICON}
            alt=""
            className="w-6 h-6 object-contain"
          />
          <span className="font-bold text-fg">{ASSISTANT_NAME}</span>
          {onReset && (
            <button
              type="button"
              onClick={onReset}
              aria-label="Nueva conversación"
              title="Nueva conversación"
              className="ml-auto w-8 h-8 rounded-full hover:bg-fg/5 text-fg-muted hover:text-fg transition flex items-center justify-center"
            >
              <NewChatIcon />
            </button>
          )}
          {/* Sin "Ver todo": MailMask no tiene página de asistente aparte. */}
          <button
            type="button"
            onClick={onClose}
            aria-label="Cerrar"
            className={`${onReset ? "" : "ml-auto "}w-8 h-8 rounded-full hover:bg-fg/5 text-fg-muted hover:text-fg transition flex items-center justify-center`}
          >
            <CloseIcon />
          </button>
        </header>
        {children}
      </motion.aside>
    </>
  )
}

const CloseIcon = () => (
  <svg
    width="16"
    height="16"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2.2"
    strokeLinecap="round"
  >
    <path d="M18 6 6 18M6 6l12 12" />
  </svg>
)

const NewChatIcon = () => (
  <svg
    width="17"
    height="17"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <path d="M12 20h9" />
    <path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z" />
  </svg>
)
