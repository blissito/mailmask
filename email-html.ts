// Convierte el markdown del compositor en HTML que sobrevive a los clientes de
// correo, junto con su equivalente en texto plano.
//
// Por qué no basta con el HTML del editor: Outlook de Windows renderiza con el
// motor de Word (sin flexbox, sin grid) y Gmail recorta el `<head>` en mensajes
// largos, llevándose cualquier `<style>`. La salida tiene que ser tablas con
// estilos inline.
//
// Aquí no se parsea ni se estiliza nada a mano; sólo se encadenan librerías:
//   markdown-it   markdown -> HTML         (23.9M desc/semana)
//   sanitize-html lista blanca de nodos    (9.2M, ApostropheCMS)
//   juice         CSS del <style> a inline (2.1M, Automattic)
//   html-to-text  HTML -> texto plano      (9.8M)

import MarkdownIt from "markdown-it";
import sanitizeHtml from "sanitize-html";
import juice from "juice";
import { convert as htmlToText } from "html-to-text";
import githubAlerts from "markdown-it-github-alerts";

import { wrapEmailHtml } from "./email-template.js";

// Gmail recorta el mensaje pasados ~102 KB y muestra "[Mensaje recortado]".
export const MAX_EMAIL_HTML_BYTES = 102_400;

// `html: false` es la pieza de seguridad principal: el HTML crudo incrustado en el
// markdown NO se interpreta, se escapa. La lista blanca es entonces estructural
// —lo que markdown-it no sabe generar, no existe— y no un filtro que mantener.
//
// `linkify` enlaza las URLs sueltas. Es necesario porque el editor corre con
// `autolink: false`: con autolink activo el caret queda atrapado dentro del <a> y
// no se puede seguir escribiendo, así que el enlace se hace aquí, al renderizar.
const md = new MarkdownIt({
  html: false,
  linkify: true,
  breaks: true,
  typographer: false,
});

// Las tablas de markdown salen sin clase; se la ponemos para que enganche con
// `table.data` de la hoja de estilos.
md.renderer.rules.table_open = () => '<table class="data">';

// Cajas de color con la sintaxis de GitHub: "> [!NOTE]", "> [!WARNING]", "> [!TIP]",
// "> [!IMPORTANT]", "> [!CAUTION]". Se elige ésta y no uno propio porque ya es el
// estándar de facto (GitHub, Obsidian, VitePress): quien la conoce la teclea sin
// aprender nada, y en la parte de texto plano se sigue leyendo como una cita.
md.use(githubAlerts, {
  icons: { note: "", tip: "", important: "", warning: "", caution: "" }, // los SVG no sobreviven a Outlook
  titles: { note: "Nota", tip: "Consejo", important: "Importante", warning: "Advertencia", caution: "Precaución" },
});

// El plugin emite un <div>. Se cambia por una tabla: Word no aplica de forma fiable
// ni el borde ni el fondo de un div, y una caja de color que no pinta el fondo deja
// de ser una caja. `juice` además copia el background-color al atributo `bgcolor`,
// que es el respaldo que Outlook sí entiende.
md.renderer.rules.alert_open = (tokens, idx) => {
  const { title, type } = (tokens[idx] as unknown as { meta: { title: string; type: string } }).meta;
  return `<table class="alert alert-${type}" role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">` +
    `<tr><td class="alert-cell alert-cell-${type}">` +
    `<p class="alert-title alert-title-${type}">${md.utils.escapeHtml(title)}</p>`;
};
md.renderer.rules.alert_close = () => `</td></tr></table>`;

// El ancho del correo. Va como atributo `width` en cada imagen porque el motor de
// Word ignora `max-width` a secas y la muestra a tamaño original, desbordando.
const CONTENT_WIDTH = 600;

const defaultImage = md.renderer.rules.image!;
md.renderer.rules.image = (tokens, idx, options, env, self) => {
  const token = tokens[idx];
  if (token.attrGet("width") === null) token.attrSet("width", String(CONTENT_WIDTH));
  return defaultImage(tokens, idx, options, env, self);
};

const SANITIZE_OPTIONS: sanitizeHtml.IOptions = {
  allowedTags: [
    "p", "br", "strong", "em", "b", "i", "u", "s",
    "code", "pre", "blockquote",
    "h1", "h2", "h3",
    "ul", "ol", "li",
    "a", "img", "hr",
    "table", "thead", "tbody", "tr", "td", "th",
  ],
  allowedAttributes: {
    a: ["href", "target", "rel"],
    img: ["src", "alt", "width", "height", "style"],
    table: ["class", "role", "cellpadding", "cellspacing", "border", "width", "style", "bgcolor"],
    tr: ["style"],
    td: ["class", "align", "style", "bgcolor", "width"],
    th: ["class", "align", "style", "bgcolor"],
    p: ["class", "style"],
  },
  // Sin `data:` ni `cid:`: el primero infla el correo y lo bloquean varios
  // clientes; el segundo requiere multipart/mixed, que sendFromDomain no arma.
  // `cid` va aquí porque las imágenes de la Bandeja se adjuntan en el propio correo
  // (ver extractInlineImages) y sin él sanitize-html borraría el src.
  allowedSchemes: ["http", "https", "mailto", "cid"],
  allowProtocolRelative: false,
  // Un <img> sin alt es invisible en Outlook, que bloquea imágenes por defecto:
  // el alt es lo único que el destinatario lee hasta que las habilita.
  transformTags: {
    a: sanitizeHtml.simpleTransform("a", { target: "_blank", rel: "noopener noreferrer" }),
    img: (tagName, attribs) => ({
      tagName,
      attribs: { ...attribs, alt: attribs.alt || "imagen" },
    }),
  },
};

const TEXT_OPTIONS = {
  wordwrap: 78,
  selectors: [
    { selector: "img", format: "skip" },
    { selector: "a", options: { hideLinkHrefIfSameAsText: true } },
  ],
};

export interface RenderedEmail {
  /** HTML listo para la parte text/html, con los estilos ya inline. */
  html: string;
  /** Cuerpo para la parte text/plain. */
  text: string;
}

/** Pasa el HTML por la lista blanca, lo envuelve en la plantilla e inlinea el CSS. */
function toEmailHtml(bodyHtml: string): string {
  const clean = sanitizeHtml(bodyHtml, SANITIZE_OPTIONS);
  // removeStyleTags: el <style> se vacía tras inlinear, así no queda nada que
  // Gmail pueda recortar.
  return juice(wrapEmailHtml(clean), {
    removeStyleTags: true,
    preserveMediaQueries: false,
    preserveImportant: true,
    // juice copia `width`/`height` del CSS a atributos HTML. Con `height: auto`
    // eso produce `height="auto"`, que no es un valor válido de atributo y que
    // Outlook interpreta como 0. Los atributos los ponemos nosotros (ver la regla
    // de `image` en el renderizador), que sí sabemos cuáles son válidos.
    applyWidthAttributes: false,
    applyHeightAttributes: false,
  });
}

/** Camino principal: lo que escribe el usuario en el compositor. */
export function renderEmailHtml(markdown: string): RenderedEmail {
  const source = (markdown ?? "").trim();
  return {
    html: toEmailHtml(md.render(source)),
    // El markdown ES el texto plano: legible tal cual, sin derivarlo del HTML.
    text: source,
  };
}

/**
 * Camino del SDK y de la API, donde el cliente manda HTML crudo. Aquí sí hay que
 * sanear y derivar el texto plano, porque antes se mandaba el marcado crudo como
 * parte text/plain.
 */
export function sanitizeEmailHtml(rawHtml: string): RenderedEmail {
  const html = toEmailHtml(rawHtml ?? "");
  return { html, text: htmlToText(html, TEXT_OPTIONS) };
}

/**
 * Pega la firma al final del markdown, separada por una regla horizontal.
 *
 * Se hace sobre el MARKDOWN y no sobre el HTML ya renderizado para que la firma
 * salga también en la parte de texto plano. Si se pegara al HTML, quien lea en modo
 * texto vería un correo sin firmar.
 */
export function appendSignature(markdown: string, signature?: string | null): string {
  const firma = (signature ?? "").trim();
  if (!firma) return markdown;
  return `${markdown.trim()}\n\n---\n\n${firma}`;
}

/**
 * Antepone la cita del mensaje al que se responde, al estilo de los clientes de
 * correo: una línea de atribución y el texto anterior con "> ".
 *
 * Va en markdown por la misma razón que la firma, y usa `>` porque es cita nativa
 * de markdown: se ve como recuadro en el HTML y sigue leyéndose en texto plano.
 */
export function quotePrevious(markdown: string, previous?: { from?: string; date?: string; text?: string } | null): string {
  const cuerpo = (previous?.text ?? "").trim();
  if (!cuerpo) return markdown;

  const fecha = previous?.date ? new Date(previous.date) : null;
  const cuando = fecha && !isNaN(fecha.getTime())
    ? fecha.toLocaleString("es-MX", { day: "numeric", month: "long", year: "numeric", hour: "2-digit", minute: "2-digit" })
    : null;
  const quien = previous?.from ?? "el remitente";
  const atribucion = cuando ? `El ${cuando}, ${quien} escribió:` : `${quien} escribió:`;

  // Se recorta: citar veinte pantallas de hilo llena el correo de ruido y hace que
  // Gmail lo colapse con "[Mensaje recortado]".
  const lineas = cuerpo.split("\n").slice(0, 40);
  if (cuerpo.split("\n").length > 40) lineas.push("[…]");

  // Los ">" ya existentes se conservan: así se ve la profundidad del hilo.
  const citado = lineas.map((l) => (l.trim() ? `> ${l}` : ">")).join("\n");
  return `${markdown.trim()}\n\n${atribucion}\n\n${citado}`;
}

/**
 * Extrae las imágenes propias (`/api/img/<uuid>.<ext>`) que referencia el HTML y
 * reescribe su `src` a `cid:<uuid>.<ext>`.
 *
 * Por qué: al insertar una foto, Gmail no la hospeda — la adjunta dentro del correo
 * y la referencia con `cid:`. Eso es lo correcto en un correo de persona a persona:
 * la imagen viaja con el mensaje, así que no hay URL pública, no quedan huérfanas en
 * el bucket, y el cliente no la trata como "contenido remoto" bloqueable.
 *
 * El envío masivo NO usa esto: adjuntar la misma imagen a cada destinatario
 * multiplicaría los bytes. Ahí el enlace hospedado sigue siendo lo correcto.
 */
export function extractInlineImages(html: string): { html: string; keys: string[] } {
  const keys: string[] = [];
  const rewritten = html.replace(
    /src="[^"]*\/api\/img\/([0-9a-f-]{36}\.(?:png|jpg|gif|webp))"/gi,
    (_m, key: string) => {
      if (!keys.includes(key)) keys.push(key);
      return `src="cid:${key}"`;
    },
  );
  return { html: rewritten, keys };
}

/**
 * Resuelve el cuerpo de un envío a partir de lo que llegó por la API.
 * Precedencia: markdown > html crudo > texto pelón.
 *
 * Existe para arreglar en un solo lugar el bug de `(textBody ?? html)`, que hacía
 * viajar el marcado crudo como parte text/plain cuando sólo se mandaba `html`.
 */
export function resolveEmailBody(input: {
  markdown?: string;
  html?: string;
  body?: string;
}): { html?: string; text: string } {
  if (input.markdown?.trim()) return renderEmailHtml(input.markdown);
  if (input.html?.trim()) {
    const rendered = sanitizeEmailHtml(input.html);
    // Si el cliente mandó también un texto propio, se respeta: sabe mejor que
    // nosotros cómo quiere leerse su correo sin formato.
    return input.body?.trim() ? { html: rendered.html, text: input.body } : rendered;
  }
  // Sin markdown ni html: el correo sale sólo como texto plano, como hasta ahora.
  return { text: input.body ?? "" };
}
