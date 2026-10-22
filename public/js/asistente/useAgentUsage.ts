import { useCallback, useEffect, useState } from "react"
import type { ScreenContext } from "./screen"

/**
 * Uso de Mascarito del dominio al que se cargaría el siguiente turno (el de la
 * pantalla o el activado más antiguo; lo decide el servidor). Sólo porcentajes:
 * el cliente nunca ve tokens ni dólares. Se pide al abrir, al cambiar de dominio
 * y al terminar cada turno (`assistant:turn-end`); sin polling.
 */
export type AgentUsage = {
  domainId: string | null
  window5h?: { pct: number; resetsAt: string | null }
  week?: { pct: number; resetsAt: string }
  uncapped?: boolean
  blocked?: boolean
  /** «a las 14:00 (hora del centro de México)» o «el lunes…», sólo si está bloqueado. */
  renewal?: string | null
}

export function useAgentUsage(screen: ScreenContext | null): AgentUsage | null {
  const [usage, setUsage] = useState<AgentUsage | null>(null)
  const domainId = screen?.domainId ?? ""

  const refresh = useCallback(async () => {
    try {
      const res = await fetch(`/api/asistente/usage${domainId ? `?domainId=${encodeURIComponent(domainId)}` : ""}`)
      if (!res.ok) return
      setUsage((await res.json()) as AgentUsage)
    } catch {
      // Silencioso: sin el indicador el chat sigue funcionando.
    }
  }, [domainId])

  useEffect(() => {
    refresh()
    const on = () => refresh()
    window.addEventListener("assistant:turn-end", on)
    return () => window.removeEventListener("assistant:turn-end", on)
  }, [refresh])

  return usage
}

/** Hora local de CDMX («14:05») de un ISO. */
export function clockCdmx(iso: string): string {
  return new Date(iso).toLocaleTimeString("es-MX", {
    timeZone: "America/Mexico_City",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  })
}
