/**
 * Separa las frases que la flota devuelve PEGADAS.
 *
 * El agente escribe en tramos —uno por paso de su trabajo— y el `done` los
 * entrega concatenados sin separador. En pantalla sale así:
 *
 *   "…evitando el token primary con opacidad que ya sé que falla).Verifico una
 *   sola vez con captura final."
 *
 * No es un fallo del modelo: son dos tramos legítimos, separados por su trabajo,
 * que alguien tiene que volver a separar. Se leen mucho mejor como lista —un
 * paso por bloque— que es lo que hace ghosty-teams.
 *
 * ## Por qué sólo mayúscula pegada a puntuación
 *
 * Es la firma exacta del pegote: un cierre de frase seguido SIN ESPACIO de algo
 * que empieza. Con espacio de por medio es prosa normal y no se toca. Es
 * heurístico y se asume: el peor error posible es un salto de línea de más.
 */

/** Trozos de código donde NO se toca nada: fences y `código en línea`. */
const CODIGO = /(```[\s\S]*?```|`[^`\n]*`)/g

const PEGADO = /([.!?)])([A-ZÁÉÍÓÚÑ¿¡])/g

export function splitGluedSentences(text: string): string {
  if (!text) return text
  // Se parte por código y se transforma sólo lo de fuera: un `obj.Method` o una
  // URL dentro de backticks no es una frase nueva.
  return text
    .split(CODIGO)
    .map((trozo, i) =>
      // Los índices impares son los delimitadores capturados, o sea el código.
      i % 2 === 1 ? trozo : trozo.replace(PEGADO, "$1\n\n$2"),
    )
    .join("")
}
