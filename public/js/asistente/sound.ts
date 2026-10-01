/**
 * Sonidito al terminar la respuesta: dos notas que suben (Web Audio, sin archivos).
 * Mismo espíritu que el `playBeep` de `docs-chat.tsx`, pero con un salto de quinta
 * para que suene a "listo" y no a error. Volumen bajo; si el navegador no deja
 * crear el AudioContext (sin gesto previo, iOS en silencio…) no pasa nada.
 */
let ctx: AudioContext | null = null

export function playReplyDone() {
  try {
    ctx ??= new AudioContext()
    if (ctx.state === "suspended") void ctx.resume()
    const t0 = ctx.currentTime
    for (const [i, freq] of [660, 990].entries()) {
      const osc = ctx.createOscillator()
      const gain = ctx.createGain()
      osc.type = "triangle"
      osc.frequency.value = freq
      osc.connect(gain)
      gain.connect(ctx.destination)
      const start = t0 + i * 0.09
      gain.gain.setValueAtTime(0.0001, start)
      gain.gain.exponentialRampToValueAtTime(0.07, start + 0.015)
      gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.14)
      osc.start(start)
      osc.stop(start + 0.15)
    }
  } catch {
    /* sin audio, sin drama */
  }
}
