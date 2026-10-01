import type { Msg } from "./types"

// Extraído de `app/routes/dash/dash.asistente.tsx` para que el dock global
// pueda reusarlo. Movimiento mecánico: sin cambios de comportamiento.

export /** ¿Cambió el día entre dos mensajes? (separador tipo "Hoy" / "12 abr 2026") */
function needsDaySeparator(prev: Msg | undefined, current: Msg) {
  if (!prev) return true
  return (
    new Date(prev.createdAt).toDateString() !==
    new Date(current.createdAt).toDateString()
  )
}

export function DaySeparator({ date }: { date: string }) {
  const d = new Date(date)
  const today = new Date()
  const yesterday = new Date(today)
  yesterday.setDate(today.getDate() - 1)
  const label =
    d.toDateString() === today.toDateString()
      ? "Hoy"
      : d.toDateString() === yesterday.toDateString()
        ? "Ayer"
        : d.toLocaleDateString("es-MX", {
            day: "numeric",
            month: "short",
            year: "numeric",
          })
  return (
    <div className="flex items-center gap-3 text-[11px] text-fg-muted/80 font-medium uppercase tracking-wide">
      <span className="flex-1 h-px bg-line/70" />
      {label}
      <span className="flex-1 h-px bg-line/70" />
    </div>
  )
}
