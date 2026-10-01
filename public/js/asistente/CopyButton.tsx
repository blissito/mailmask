import { useState } from "react"

// Extraído de `app/routes/dash/dash.asistente.tsx` para que el dock global
// pueda reusarlo. Movimiento mecánico: sin cambios de comportamiento.

export function CopyButton({
  text,
  onSurface = "light",
}: {
  text: string
  /**
   * El reposo (`text-fg-muted`) se lee en los dos fondos, pero el HOVER no:
   * `hover:text-fg` sobre el panel oscuro del editor hace DESAPARECER
   * el botón justo cuando el usuario va a pulsarlo. Y `hover:bg-fg/5` sobre
   * negro tampoco marca nada.
   */
  onSurface?: "light" | "dark"
}) {
  const [copied, setCopied] = useState(false)
  const dark = onSurface === "dark"
  return (
    <button
      type="button"
      onClick={() => {
        navigator.clipboard.writeText(text)
        setCopied(true)
        window.setTimeout(() => setCopied(false), 1500)
      }}
      className={`text-xs font-medium px-2 py-1 rounded-lg transition ${
        dark
          ? "text-white/60 hover:text-white hover:bg-white/10"
          : "text-fg-muted hover:text-fg hover:bg-fg/5"
      }`}
      aria-label="Copiar respuesta"
    >
      {copied ? "¡Copiado!" : "Copiar"}
    </button>
  )
}
