import { AnimatePresence, motion } from "motion/react"
import type { ToolRun } from "./types"

// Extraído de `app/routes/dash/dash.asistente.tsx` para que el dock global
// pueda reusarlo. Movimiento mecánico: sin cambios de comportamiento.

/**
 * Colapsa corridas de la MISMA tool en un renglón con contador.
 *
 * Hace falta por codemode: casi todo lo que hace Nik pasa por `run_tool`, así
 * que la traza salía como cuatro "Usando una herramienta de Deník" seguidos —
 * cuatro veces la misma no-información. Se colapsan sólo las CONSECUTIVAS: si
 * entre dos vuelve a aparecer otra tool, el orden es lo que se está contando y
 * juntarlas lo falsearía.
 */
function collapse(tools: ToolRun[]): (ToolRun & { count: number })[] {
  const out: (ToolRun & { count: number })[] = []
  for (const t of tools) {
    const last = out[out.length - 1]
    if (last && last.label === t.label) {
      last.count++
      // El grupo sigue "corriendo" mientras la última no termine, o el spinner
      // se apagaría con la primera y parecería que ya acabó.
      last.done = t.done
      continue
    }
    out.push({ ...t, count: 1 })
  }
  return out
}

/**
 * Traza de las tools del turno, al estilo claude.ai: una línea discreta por
 * tool, con spinner mientras corre y palomita al terminar. Queda en el mensaje
 * (no es un estado efímero), así que al releer el hilo se ve qué consultó Nik.
 */
export function ToolTrace({ tools }: { tools: ToolRun[] }) {
  return (
    <div className="flex flex-col gap-1 mb-2">
      <AnimatePresence initial={false}>
        {collapse(tools).map((t, i) => (
          <motion.div
            key={`${t.label}-${i}`}
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center gap-2 text-[13px] font-medium text-fg-muted"
          >
            {t.done ? (
              <svg
                width="13"
                height="13"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="3"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="shrink-0 text-emerald-500"
              >
                <path d="M20 6 9 17l-5-5" />
              </svg>
            ) : (
              <span className="w-3 h-3 shrink-0 rounded-full border-2 border-accent border-t-transparent animate-spin" />
            )}
            <span className="truncate">{t.label}</span>
            {t.count > 1 && (
              <span className="shrink-0 text-[11px] opacity-60">
                ×{t.count}
              </span>
            )}
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  )
}
