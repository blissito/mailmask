/**
 * El marcador de navegación que Nik puede escribir en su respuesta.
 *
 *     Ya creé el alias. [[ir:dominio/<id>/aliases]]
 *
 * El cliente lo convierte en un botón que navega **dentro** de la SPA (sin
 * recargar, sin cerrar el dock). En WhatsApp nadie lo interpreta, así que el
 * texto tiene que sostenerse sin él — eso lo pide el system prompt.
 *
 * ## Por qué en el texto y no en el resultado de una tool
 *
 * Es como lo hace agent-native (`registerActionChatRenderer`): el resultado
 * tipado de la acción elige el componente. Aquí no se puede: el SSE de la flota
 * sólo trae `{type:"tool", name}` —sin args ni resultado— y ese evento nace en
 * el worker del sandbox, tres capas más arriba y en otro repo.
 *
 * A cambio, el marcador tiene una ventaja real que el otro camino no da: **el
 * modelo decide dónde va el botón dentro de su respuesta**. Con tool-results, la
 * posición la dicta el orden de las llamadas y el botón aterriza antes de la
 * frase que lo explica.
 *
 * ## Es un botón, no un salto automático
 *
 * Arrancarle la pantalla al usuario a media tarea es exactamente el fallo que el
 * dock existe para evitar, y un modelo que se equivoca de ruta te saca de donde
 * estabas sin deshacer. El click no cuesta nada y deja el control donde va.
 */

/**
 * Pestañas del detalle de dominio en `/app` (los `data-tab` de `app.html`) a las
 * que el agente puede mandar. El panel de salud vive dentro de `dns`.
 */
export const TABS: Record<string, string> = {
  aliases: "Ver alias",
  rules: "Ver reglas",
  logs: "Ver logs",
  dns: "Ver DNS",
  members: "Ver miembros",
  smtp: "Ver SMTP",
  webhooks: "Ver webhooks",
  apikeys: "Ver API keys",
}

/** Destinos: `dominio/<id>` y `dominio/<id>/<pestaña>`. El id es opaco (uuid/slug). */
const TARGET = /^dominio\/([A-Za-z0-9_-]{1,64})(?:\/([a-z]+))?$/

const MARKER = /\[\[ir:([^\]\s]+)\]\]/g

export type NavPart =
  | { type: "text"; value: string }
  | { type: "nav"; to: string; label: string }

/**
 * Valida un destino y devuelve su etiqueta, o `null` si no está permitido.
 *
 * Sólo `dominio/<id>[/<pestaña>]` con pestañas de la lista blanca: nada de
 * URLs, `//host`, `..` ni esquemas. El destino no es una URL — lo resuelve
 * `window.mailmaskNav` en `app.js` con `selectDomain`/`switchTab`.
 */
export function resolveNavTarget(
  raw: string,
): { to: string; label: string } | null {
  const to = raw.trim()
  const m = TARGET.exec(to)
  if (!m) return null
  const tab = m[2]
  if (tab === undefined) return { to, label: "Ver dominio" }
  return TABS[tab] ? { to, label: TABS[tab] } : null
}

/**
 * Parte el texto en tramos de markdown y botones de navegación.
 *
 * `streaming` recorta un marcador a medio escribir del final (`[[ir:domi`): sin
 * eso, el usuario ve corchetes sueltos apareciendo letra por letra en cada
 * respuesta que termina con un botón.
 *
 * Un destino no permitido **se deja como texto plano**, no se borra: si el
 * agente se equivocó de ruta, que se note, en vez de que la frase quede coja.
 */
export function parseNavParts(text: string, streaming = false): NavPart[] {
  let src = text
  if (streaming) {
    const abierto = src.lastIndexOf("[[")
    if (abierto !== -1 && !src.slice(abierto).includes("]]")) {
      src = src.slice(0, abierto)
    }
  }

  const parts: NavPart[] = []
  let last = 0
  MARKER.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = MARKER.exec(src)) !== null) {
    const target = resolveNavTarget(m[1])
    if (!target) continue // marcador inválido: se queda dentro del texto
    if (m.index > last)
      parts.push({ type: "text", value: src.slice(last, m.index) })
    parts.push({ type: "nav", ...target })
    last = m.index + m[0].length
  }
  if (last < src.length) parts.push({ type: "text", value: src.slice(last) })
  return parts.length ? parts : [{ type: "text", value: src }]
}

/** ¿El texto trae al menos un botón? Evita re-render de más cuando no hay. */
export const hasNavMarker = (text: string) => {
  MARKER.lastIndex = 0
  return MARKER.test(text)
}
