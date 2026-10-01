import type { Attachment } from "./types"

/**
 * Las dos mitades de un mismo contrato, juntas a propósito.
 *
 * Un adjunto se PERSISTE incrustado como markdown dentro del texto del mensaje
 * (`saveUserMessage` en `/api/asistente/stream`), porque el historial es una
 * sola columna de texto. Al RECARGAR hay que deshacer eso, o la burbuja —que
 * pinta `content` como texto plano— muestra `![foto.png](https://…)` crudo.
 *
 * Si alguien cambia el formato de escritura y no el de lectura, el síntoma es
 * exactamente ese link crudo. Por eso viven en el mismo archivo.
 */

/** Cómo se escribe. Debe coincidir con `renderAttachmentMarkdown` del server. */
export const renderAttachmentMarkdown = (a: {
  url: string
  name?: string
  contentType?: string
}): string => {
  const name = a.name || "archivo"
  return a.contentType?.startsWith("image/")
    ? `![${name}](${a.url})`
    : `[${name}](${a.url})`
}

/**
 * Un adjunto ocupa una línea entera: `![nombre](url)` o `[nombre](url)`.
 *
 * Se ancla a la línea completa (`^…$` con flag `m`) a propósito: sin eso, un
 * link que el usuario escribió DENTRO de una frase ("mira [esto](url)") se
 * arrancaría del texto y se pintaría como adjunto, mutilando su mensaje.
 */
const ATTACHMENT_LINE = /^(!?)\[([^\]\n]*)\]\((\S+?)\)$/gm

/** Extensiones que se muestran como imagen cuando no hay contentType guardado. */
const IMAGE_EXT = /\.(png|jpe?g|gif|webp|avif|bmp|svg)(\?|$)/i

/**
 * Separa los adjuntos incrustados del texto real del mensaje.
 *
 * Devuelve `attachments: undefined` (no `[]`) cuando no hay ninguno, para que
 * el `!!m.attachments?.length` de la UI siga funcionando igual y un mensaje sin
 * adjuntos no cambie de forma.
 */
export const parseAttachmentMarkdown = (
  content: string,
): { content: string; attachments?: Attachment[] } => {
  if (!content?.includes("](")) return { content }

  const found: Attachment[] = []
  const rest = content
    .replace(ATTACHMENT_LINE, (match, bang: string, name: string, url: string) => {
      // Sólo URLs absolutas: un `[texto](#ancla)` o una ruta relativa no es un
      // adjunto y quitarla del texto sería perder lo que el usuario escribió.
      if (!/^https?:\/\//i.test(url)) return match
      found.push({
        url,
        name: name || undefined,
        // El `!` del markdown ya dice que era imagen; la extensión cubre los
        // links guardados sin él.
        contentType:
          bang === "!" || IMAGE_EXT.test(url) ? "image/*" : undefined,
      })
      return ""
    })
    .replace(/\n{3,}/g, "\n\n")
    .trim()

  return found.length ? { content: rest, attachments: found } : { content }
}
