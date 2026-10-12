// Reglas de SEO de las páginas públicas de `public/`. Las comparten `docs-seo.test.ts` (que
// además vigila lo propio de /docs) y `public-seo.test.ts`, para que no haya dos copias del
// mismo chequeo desfasándose. Ficha: docs/agents/seo-paginas-publicas.md
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const HOST = "https://www.mailmask.studio";

/** Tarjeta social genérica del sitio. Cada página del sitemap trae la suya (ficha). */
export const OG_GENERICA = `${HOST}/img/og-image.png`;

/** Metas que toda página pública declara. Su valor se compara aparte (regla `og-coincide`). */
const METAS_OBLIGATORIAS = [
  "og:type",
  "og:site_name",
  "og:locale",
  "og:url",
  "og:title",
  "og:description",
  "og:image",
  "og:image:width",
  "og:image:height",
  "twitter:card",
  "twitter:title",
  "twitter:description",
  "twitter:image",
];

export type Meta = { clave: string; valor: string };

/** Sólo la cabecera: las metas sueltas más abajo no cuentan. */
export function leerHead(html: string): string {
  const fin = html.indexOf("</head>");
  return fin === -1 ? html : html.slice(0, fin);
}

/** Las metas de la cabecera, en cualquier orden de atributos y repartidas en varias líneas. */
export function metas(head: string): Meta[] {
  const encontradas: Meta[] = [];
  for (const etiqueta of head.matchAll(/<meta\b[^>]*>/g)) {
    const clave = etiqueta[0].match(/\b(?:name|property)="([^"]+)"/)?.[1];
    const valor = etiqueta[0].match(/\bcontent="([^"]*)"/)?.[1];
    if (clave && valor !== undefined) encontradas.push({ clave, valor });
  }
  return encontradas;
}

/** Un enlace de la cabecera, aguantando que sus atributos vayan en varias líneas. */
function enlace(head: string, atributo: string, href: string): boolean {
  return new RegExp(`${atributo}="${href.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`).test(head);
}

export function meta(head: string, clave: string): string | undefined {
  return metas(head).find((m) => m.clave === clave)?.valor;
}

export function titulo(head: string): string | undefined {
  return head.match(/<title>([^<]*)<\/title>/)?.[1];
}

function scriptsJsonLd(head: string): string[] {
  return [...head.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)].map((m) => m[1]);
}

/** El `@graph` del JSON-LD. Se queja si hay más de un bloque o si no trae `@graph`. */
export function grafo(head: string): any[] {
  const scripts = scriptsJsonLd(head);
  assert.equal(scripts.length, 1, "el JSON-LD va en un solo <script>");
  const json = JSON.parse(scripts[0]);
  assert.ok(Array.isArray(json["@graph"]), "falta @graph");
  return json["@graph"];
}

/** Igual que `grafo()` pero sin reventar: `null` cuando el JSON-LD no cumple. */
function grafoSi(head: string): any[] | null {
  const scripts = scriptsJsonLd(head);
  if (scripts.length !== 1) return null;
  try {
    const json = JSON.parse(scripts[0]);
    return Array.isArray(json["@graph"]) ? json["@graph"] : null;
  } catch {
    return null;
  }
}

/** Ancho y alto de un JPEG leyendo su marcador SOF. */
export function medidasJpeg(buf: Buffer): { w: number; h: number } {
  assert.equal(buf.readUInt16BE(0), 0xffd8, "no es un JPEG");
  let i = 2;
  while (i < buf.length) {
    assert.equal(buf[i], 0xff);
    const marcador = buf[i + 1];
    const largo = buf.readUInt16BE(i + 2);
    if (marcador >= 0xc0 && marcador <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marcador)) {
      return { h: buf.readUInt16BE(i + 5), w: buf.readUInt16BE(i + 7) };
    }
    i += 2 + largo;
  }
  throw new Error("JPEG sin SOF");
}

/** Medidas de un JPEG o un PNG; `null` si el archivo no es ninguno de los dos. */
export function medidasImagen(buf: Buffer): { w: number; h: number } | null {
  if (buf.length > 24 && buf.readUInt32BE(0) === 0x89504e47) return { w: buf.readUInt32BE(16), h: buf.readUInt32BE(20) };
  try {
    return medidasJpeg(buf);
  } catch {
    return null;
  }
}

/** Este módulo vive en la raíz del repo: sus rutas se resuelven contra su carpeta. */
const RAIZ = new URL("./", import.meta.url);

const local = (archivo: string) => fileURLToPath(new URL(archivo, RAIZ));

/** La ruta de un archivo de `public/` a partir de su URL en el sitio. */
export function archivoPublico(url: string): string | null {
  return url.startsWith(`${HOST}/`) ? `public${url.slice(HOST.length)}` : null;
}

/** Ruta→archivo. La landing y el índice del blog no viven en el nombre de su ruta. */
export function archivoDe(ruta: string): string {
  if (ruta === "/") return "public/landing.html";
  if (ruta === "/blog") return "public/blog/index.html";
  return `public${ruta}.html`;
}

/** Rutas del sitemap que vigila la suite: todas menos las entradas del blog (/blog/<slug>). */
export function paginasDelSitemap(sitemap: string): string[] {
  return [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)]
    .map((m) => m[1].replace(HOST, ""))
    .filter((ruta) => ruta === "/" || ruta.split("/").length === 2);
}

export type OpcionesPagina = {
  /** La ficha pide fecha visible («Actualizado: <time datetime>»): legales y /docs. */
  fechaVisible?: boolean;
};

/**
 * Reglas incumplidas por una página, como lista de identificadores estables. Es pura:
 * `public-seo.test.ts` la compara contra su lista de `PENDIENTES` y falla si aparece un
 * hueco nuevo o si un pendiente ya arreglado sigue listado.
 */
export function huecos(ruta: string, html: string, opciones: OpcionesPagina = {}): string[] {
  const head = leerHead(html);
  const ms = metas(head);
  const url = `${HOST}${ruta}`;
  const faltas: string[] = [];

  const suyo = titulo(head);
  if ((head.match(/<title>/g) ?? []).length !== 1 || !suyo) faltas.push("title");
  else if (suyo.length > 60) faltas.push("title-largo");

  const descripciones = ms.filter((m) => m.clave === "description");
  const descripcion = descripciones.length === 1 ? descripciones[0].valor : undefined;
  if (descripcion === undefined) faltas.push("description");
  else if (descripcion.length < 140 || descripcion.length > 160) faltas.push("description-medida");

  if (!enlace(head, "rel=\"canonical\"\\s+href", url)) faltas.push("canonical");
  if (!enlace(head, "hreflang=\"es-MX\"\\s+href", url) || !enlace(head, "hreflang=\"x-default\"\\s+href", url)) faltas.push("hreflang");

  if (METAS_OBLIGATORIAS.some((clave) => !meta(head, clave))) faltas.push("og");
  const repite = meta(head, "og:title") === suyo && meta(head, "og:description") === descripcion &&
    meta(head, "twitter:title") === suyo && meta(head, "twitter:description") === descripcion &&
    meta(head, "twitter:card") === "summary_large_image" && meta(head, "og:url") === url;
  if (!repite) faltas.push("og-coincide");

  if (scriptsJsonLd(head).length !== 1) faltas.push("jsonld-unico");
  if (grafoSi(head) === null) faltas.push("jsonld-graph");
  if (scriptsJsonLd(head).some((s) => /SoftwareApplication|MobileApplication|WebApplication/.test(s))) faltas.push("softwareapplication");

  const og = meta(head, "og:image");
  const archivo = og ? archivoPublico(og) : null;
  if (!archivo || !existsSync(local(archivo))) faltas.push("og-imagen");
  else {
    const medidas = medidasImagen(readFileSync(local(archivo)));
    if (!medidas || medidas.w !== 1200 || medidas.h !== 630) faltas.push("og-medidas");
    else if (String(medidas.w) !== meta(head, "og:image:width") || String(medidas.h) !== meta(head, "og:image:height")) faltas.push("og-medidas");
  }
  if (og === OG_GENERICA) faltas.push("og-propia");

  if (opciones.fechaVisible && !html.match(/Actualizado:\s*<time datetime="\d{4}-\d{2}-\d{2}">/)) faltas.push("fecha-visible");

  return faltas;
}
