import { AnimatePresence, motion } from "motion/react"
import { useEffect, useState } from "react"
import { confirmLabel } from "./confirmLabel"

/**
 * El artefacto de confirmación: lo que el usuario ve antes de que Nik ejecute
 * algo irreversible.
 *
 * **Todo lo que se muestra aquí viene del SERVIDOR**, resuelto de la DB en
 * `agent-confirmation.server.ts`. Este componente no recibe ni renderiza texto
 * del modelo — si el modelo dijo "la cita de Ana" pero el id apunta a Pedro,
 * aquí dice Pedro. Es la única razón por la que apretar el botón es seguro.
 *
 * Reglas de UX que lo hacen confiable y no sólo bonito:
 *
 * - **Se declara el efecto colateral** ("se le enviará un correo"). Es lo que la
 *   gente no anticipa, y enterarse después es lo que quema la confianza.
 * - **El botón primario dice el verbo** ("Sí, cancelar"), no "OK". Un "OK" se
 *   aprieta en automático.
 * - **Acento rojo sólo en lo destructivo.** Pintar de rojo también un cambio de
 *   precio diluye la señal para cuando sí importa.
 * - **Al resolverse colapsa a un recibo de una línea.** Nada de cards zombis
 *   ocupando el hilo con botones que ya no hacen nada.
 */

export type PendingActionSummary = {
  title: string
  lines: string[]
  effects: string[]
  destructive: boolean
}

export type PendingAction = {
  id: string
  tool: string
  summary: PendingActionSummary
  createdAt: string
  expiresAt: string
}

/** Cómo terminó, para el recibo. */
export type ActionOutcome = "executed" | "rejected" | "failed" | "expired"

const OUTCOME_COPY: Record<ActionOutcome, { icon: string; text: string }> = {
  executed: { icon: "✓", text: "Hecho" },
  rejected: { icon: "✕", text: "No se hizo" },
  failed: { icon: "!", text: "Falló al ejecutarse" },
  expired: { icon: "⏱", text: "Venció sin confirmarse" },
}

export function PendingActionCard({
  action,
  onConfirm,
  onReject,
}: {
  action: PendingAction
  onConfirm: (id: string) => Promise<ActionOutcome>
  onReject: (id: string) => Promise<ActionOutcome>
}) {
  const [busy, setBusy] = useState<"confirm" | "reject" | null>(null)
  /* Segundos desde que se confirmó. Rehacer una sección tarda 17-60 s —se
     regenera con el modelo y se descargan las fotos de stock— y un botón que
     sólo dice "Ejecutando…" durante un minuto se ve idéntico a algo colgado.
     El usuario lo reportó como "se cuelga ahí"; el servidor había respondido en
     17.5 s. Un contador que avanza es la diferencia entre esperar y abandonar. */
  const [segundos, setSegundos] = useState(0)
  useEffect(() => {
    if (busy !== "confirm") return setSegundos(0)
    const t = setInterval(() => setSegundos((s) => s + 1), 1000)
    return () => clearInterval(t)
  }, [busy])
  const [outcome, setOutcome] = useState<ActionOutcome | null>(null)
  const { title, lines, effects, destructive } = action.summary

  const run = async (
    kind: "confirm" | "reject",
    fn: (id: string) => Promise<ActionOutcome>,
  ) => {
    if (busy || outcome) return
    setBusy(kind)
    try {
      setOutcome(await fn(action.id))
    } finally {
      setBusy(null)
    }
  }

  if (outcome) {
    const { icon, text } = OUTCOME_COPY[outcome]
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="flex items-center gap-2 text-sm font-medium text-fg-muted py-1.5"
      >
        <span
          className={
            outcome === "executed" ? "text-accent-text" : "text-fg-muted"
          }
          aria-hidden
        >
          {icon}
        </span>
        <span>
          {text}: <span className="text-fg-subtle">{title.toLowerCase()}</span>
        </span>
      </motion.div>
    )
  }

  const accent = destructive
    ? {
        border: "border-red-600/40",
        bar: "bg-red-600",
        title: "text-red-600",
        primary: "bg-red-600 hover:bg-red-600/90",
      }
    : {
        border: "border-accent/40",
        bar: "bg-accent",
        title: "text-fg",
        primary: "bg-accent hover:bg-accent/90",
      }

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      className={`relative overflow-hidden rounded-2xl border ${accent.border} bg-bg-elev shadow-[0_2px_12px_rgba(17,21,26,0.06)]`}
      role="group"
      aria-label={`Confirmación requerida: ${title}`}
    >
      <div className={`absolute left-0 top-0 bottom-0 w-1 ${accent.bar}`} />
      <div className="pl-5 pr-4 py-4 flex flex-col gap-3">
        <h3
          className={`font-bold text-base leading-tight ${accent.title} flex items-center gap-2`}
        >
          {destructive && <span aria-hidden>⚠</span>}
          {title}
        </h3>

        {!!lines.length && (
          <div className="flex flex-col gap-0.5">
            {lines.map((line, i) => (
              <p
                key={i}
                className={`text-base break-words ${
                  i === 0
                    ? "text-fg font-medium"
                    : "text-fg-subtle"
                }`}
              >
                {line}
              </p>
            ))}
          </div>
        )}

        {!!effects.length && (
          <ul className="flex flex-col gap-1 border-t border-line pt-3">
            {effects.map((effect, i) => (
              <li
                key={i}
                className="text-sm text-fg-muted flex gap-2"
              >
                <span aria-hidden>·</span>
                <span>{effect}</span>
              </li>
            ))}
          </ul>
        )}

        <div className="flex items-center justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={() => run("reject", onReject)}
            disabled={!!busy}
            className="text-sm font-medium text-fg-subtle px-4 py-2 rounded-full hover:bg-fg/5 transition disabled:opacity-40"
          >
            {/* "Descartar" y NO "No, cancelar": cuando la acción ES cancelar una
                cita, un botón que dice "cancelar" se lee como aprobarla. */}
            {busy === "reject" ? "Descartando…" : "Descartar"}
          </button>
          <button
            type="button"
            onClick={() => run("confirm", onConfirm)}
            disabled={!!busy}
            className={`text-sm font-medium text-white px-4 py-2 rounded-full transition disabled:opacity-40 ${accent.primary}`}
          >
            {busy === "confirm"
              ? `Ejecutando… ${segundos}s`
              : confirmLabel(title)}
          </button>
        </div>
      </div>
    </motion.div>
  )
}

export function PendingActionList({
  actions,
  onConfirm,
  onReject,
  max,
}: {
  actions: PendingAction[]
  onConfirm: (id: string) => Promise<ActionOutcome>
  onReject: (id: string) => Promise<ActionOutcome>
  /**
   * Cuántas mostrar a la vez. Lo usa la zona fija del chat, que comparte el alto
   * con el composer: sin tope, tres pendientes empujaban la caja de texto fuera
   * de la pantalla. El resto no se pierde — se anuncia y aparece al resolver
   * las de arriba, una por una, que además es como se leen de verdad.
   */
  max?: number
}) {
  const shown = max ? actions.slice(0, max) : actions
  const restantes = actions.length - shown.length
  return (
    <>
      <AnimatePresence initial={false}>
        {shown.map((a) => (
          <PendingActionCard
            key={a.id}
            action={a}
            onConfirm={onConfirm}
            onReject={onReject}
          />
        ))}
      </AnimatePresence>
      {restantes > 0 && (
        <p className="text-xs text-fg-muted font-medium text-center pb-1">
          {restantes === 1
            ? "1 acción más esperando"
            : `${restantes} acciones más esperando`}
        </p>
      )}
    </>
  )
}
