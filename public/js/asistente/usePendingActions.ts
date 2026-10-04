import { useCallback, useEffect, useRef, useState } from "react"
import type {
  ActionOutcome,
  PendingAction,
} from "./PendingActionCard"

/**
 * Buzón de acciones del agente que esperan aprobación.
 *
 * **Vive fuera del stream a propósito.** Si el card se armara con un frame del
 * SSE, recargar la página lo desaparecería y la acción quedaría pendiente sin
 * que nadie la vea — o peor, el usuario asumiría que se ejecutó. Aquí la fuente
 * es siempre `GET /api/agent-actions`, así que sobrevive al reload, al cambio de
 * ruta y a que la petición se haya originado en WhatsApp.
 *
 * `refresh()` se llama al terminar cada turno del chat: es cuando pudo aparecer
 * algo nuevo. No hay polling — un intervalo corriendo en todo el dash para algo
 * que sólo cambia cuando el agente actúa es puro ruido.
 */
export function usePendingActions({
  enabled = true,
}: {
  enabled?: boolean
} = {}) {
  const [actions, setActions] = useState<PendingAction[]>([])
  const inFlight = useRef(false)

  const refresh = useCallback(async () => {
    if (!enabled || inFlight.current) return
    inFlight.current = true
    try {
      const res = await fetch("/api/agent-actions")
      if (!res.ok) return
      const data = (await res.json()) as { actions?: PendingAction[] }
      setActions(data.actions ?? [])
    } catch {
      // Silencioso: no poder listar pendientes no debe romper el chat.
    } finally {
      inFlight.current = false
    }
  }, [enabled])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const resolve = useCallback(
    async (
      id: string,
      intent: "confirm" | "reject",
    ): Promise<ActionOutcome> => {
      try {
        const res = await fetch("/api/agent-actions", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ intent, actionId: id }),
        })
        // La sacamos de la lista pase lo que pase: si ya no está pendiente
        // (otra pestaña la resolvió, o venció), dejarla en pantalla con sus
        // botones vivos es mentir sobre lo que se puede hacer.
        setActions((prev) => prev.filter((a) => a.id !== id))
        if (res.ok) return intent === "confirm" ? "executed" : "rejected"
        const data = (await res.json().catch(() => ({}))) as { status?: string }
        if (data.status === "expired") return "expired"
        if (data.status === "executed") return "executed"
        if (data.status === "rejected") return "rejected"
        return "failed"
      } catch {
        return "failed"
      }
    },
    [],
  )

  const confirm = useCallback((id: string) => resolve(id, "confirm"), [resolve])
  const reject = useCallback((id: string) => resolve(id, "reject"), [resolve])

  return { actions, refresh, confirm, reject }
}
