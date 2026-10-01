import { useEffect, useState } from "react"

/**
 * Qué está mirando el usuario en `/app`. Reemplaza a `useCurrentScreen` de agenda
 * (que leía la ruta de react-router): aquí no hay router, así que `app.js`
 * publica `window.mailmaskScreen` y avisa con el evento `mailmask:screen` cada
 * vez que cambia el dominio seleccionado o la pestaña.
 */
export type ScreenContext = {
  domainId?: string | null
  tab?: string | null
}

declare global {
  interface Window {
    mailmaskScreen?: ScreenContext
    /** Navega a `dominio/<id>[/<pestaña>]` (lo implementa `app.js`). */
    mailmaskNav?: (to: string) => void
    mailmaskAssistant?: {
      open: (opts?: { text?: string }) => void
      close: () => void
      toggle: () => void
    }
  }
}

const read = (): ScreenContext | null => {
  const s = typeof window !== "undefined" ? window.mailmaskScreen : undefined
  if (!s?.domainId) return null
  return { domainId: s.domainId, tab: s.tab ?? null }
}

export function useCurrentScreen(): ScreenContext | null {
  const [screen, setScreen] = useState<ScreenContext | null>(read)
  useEffect(() => {
    const on = () =>
      setScreen((prev) => {
        const next = read()
        return JSON.stringify(prev) === JSON.stringify(next) ? prev : next
      })
    window.addEventListener("mailmask:screen", on)
    return () => window.removeEventListener("mailmask:screen", on)
  }, [])
  return screen
}
