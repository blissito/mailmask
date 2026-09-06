// Sanitización de la consulta de búsqueda antes de pasarla a FTS5 MATCH.
//
// Esto es entrada de usuario cruda hacia un parser: comillas, `*`, `-`, `:`,
// paréntesis y las palabras AND/OR/NOT/NEAR son sintaxis de FTS5 y revientan la
// consulta con SQLITE_ERROR. La estrategia NO es escapar la sintaxis —es
// neutralizarla entera—: partimos por todo lo que no sea letra o número, así no
// queda ningún carácter especial, y envolvemos cada token en comillas dobles
// para que ni `near` ni `and` ni `or` se interpreten como operadores.

const MAX_ENTRADA = 200;
const MAX_TOKENS = 10;

/**
 * Devuelve una expresión MATCH segura, o null si no queda nada que buscar
 * (en cuyo caso el llamador debe devolver lista vacía sin tocar FTS).
 */
export function sanitizarConsultaFts(entrada: string): string | null {
  if (typeof entrada !== "string") return null;

  const tokens = entrada
    .slice(0, MAX_ENTRADA)
    .toLowerCase()
    .split(/[^\p{L}\p{N}_]+/u)
    .filter((t) => t.length > 0)
    .slice(0, MAX_TOKENS);

  if (tokens.length === 0) return null;

  // Prefijo sólo en el último token, para que escribir "fact" encuentre
  // "factura" mientras se teclea, sin volver difusos los términos ya completos.
  return tokens
    .map((t, i) => (i === tokens.length - 1 ? `"${t}"*` : `"${t}"`))
    .join(" ");
}

/** Escapa los comodines de LIKE para el camino degradado (sin FTS5). */
export function escaparLike(entrada: string): string {
  return entrada.slice(0, MAX_ENTRADA).replace(/[\\%_]/g, (c) => `\\${c}`);
}
