/**
 * Texto del botón que aprueba una acción del agente.
 *
 * Repite el VERBO de la acción ("Sí, cancelar"), nunca un "OK" genérico: un
 * "OK" se aprieta en automático, y el punto entero de este card es que la
 * persona registre QUÉ está aprobando.
 *
 * Puro y testeado porque el título lo escribe el servidor y va a crecer: si
 * mañana alguien agrega un resumen que no empieza con verbo, el botón no puede
 * quedar diciendo "Sí, no" — cae al genérico.
 */
const NOT_A_VERB = /^(no|sin|confirmar)$/

export function confirmLabel(title: string): string {
  const first = title
    .trim()
    .split(/\s+/)[0]
    ?.replace(/[^\p{L}]/gu, "")
    .toLowerCase()
  if (!first || NOT_A_VERB.test(first)) return "Sí, continuar"
  return `Sí, ${first}`
}
