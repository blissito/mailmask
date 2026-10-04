import { useCallback, useEffect, useRef, useState } from "react"
import { createRoot } from "react-dom/client"
import { AssistantDock, DOCK_WIDTH } from "./AssistantDock"
import "./screen" // tipos globales de window.mailmask*

/**
 * Montaje del dock en `/app` (vanilla, sin router). Hace lo que en agenda hacía
 * el `SideBar`: tener el estado abierto/cerrado y reservar el hueco cuando el
 * dock EMPUJA el contenido (≥1280px). Abajo de eso se superpone, igual que allá.
 *
 * API para `app.js` (botones "Pídeselo al asistente" y el trigger de la cabecera):
 *   window.mailmaskAssistant.open({ text })  — abre con el texto ya escrito
 *   window.mailmaskAssistant.close() / .toggle()
 */
const PUSH_QUERY = "(min-width: 1280px)"

function useMedia(query: string) {
  const [match, setMatch] = useState(() => window.matchMedia(query).matches)
  useEffect(() => {
    const mq = window.matchMedia(query)
    const on = () => setMatch(mq.matches)
    mq.addEventListener("change", on)
    return () => mq.removeEventListener("change", on)
  }, [query])
  return match
}

function App() {
  const [open, setOpen] = useState(false)
  const [prefill, setPrefill] = useState<{ text: string; n: number } | null>(
    null,
  )
  const n = useRef(0)
  const push = useMedia(PUSH_QUERY)

  const openWith = useCallback((opts?: { text?: string }) => {
    if (opts?.text) setPrefill({ text: opts.text, n: ++n.current })
    setOpen(true)
  }, [])

  // API global + trigger de la cabecera.
  const openRef = useRef(open)
  openRef.current = open
  useEffect(() => {
    window.mailmaskAssistant = {
      open: openWith,
      close: () => setOpen(false),
      toggle: () => setOpen(!openRef.current),
    }
    const trigger = document.getElementById("assistant-trigger")
    const onClick = () => setOpen((v) => !v)
    trigger?.addEventListener("click", onClick)
    return () => trigger?.removeEventListener("click", onClick)
  }, [openWith])

  useEffect(() => {
    document
      .getElementById("assistant-trigger")
      ?.setAttribute("aria-expanded", String(open))
  }, [open])

  // Un texto sugerido vale para UNA apertura: cerrar lo olvida, o reabrir con
  // la astilla volvería a escribirlo encima.
  useEffect(() => {
    if (!open) setPrefill(null)
  }, [open])

  // Empujar el contenido: el hueco lo reserva el body, con la misma constante
  // que el ancho del panel para que nunca se desincronicen.
  const pushing = open && push
  useEffect(() => {
    const b = document.body
    b.style.transition = "padding-right 0.25s cubic-bezier(0.22, 1, 0.36, 1)"
    b.style.paddingRight = pushing ? `${DOCK_WIDTH}px` : ""
  }, [pushing])

  return (
    <AssistantDock
      open={open}
      onOpenChange={setOpen}
      width={push ? DOCK_WIDTH : undefined}
      hasBottomNav={false}
      prefill={prefill}
    />
  )
}

const el = document.getElementById("assistant-root")
if (el) createRoot(el).render(<App />)
