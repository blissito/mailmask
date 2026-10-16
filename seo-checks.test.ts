// Suite propia de seo-checks.ts: un caso por cada función exportada, sin red ni base de datos.
// Las reglas sobre las páginas reales las corre public-seo.test.ts; aquí se prueban las piezas.
// Ficha: docs/agents/seo-paginas-publicas.md
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  HOST,
  OG_GENERICA,
  archivoDe,
  archivoPublico,
  grafo,
  huecos,
  leerHead,
  medidasImagen,
  medidasJpeg,
  meta,
  metas,
  paginasDelSitemap,
  titulo,
} from "./seo-checks.ts";

/** JPEG mínimo: SOI, un APP0 opcional y un SOF con el alto y el ancho dados. */
function jpeg({ w, h, app0 = false }: { w: number; h: number; app0?: boolean }): Buffer {
  const bytes: number[] = [0xff, 0xd8];
  if (app0) bytes.push(0xff, 0xe0, 0x00, 0x02);
  bytes.push(0xff, 0xc0, 0x00, 0x11, 0x08, h >> 8, h & 0xff, w >> 8, w & 0xff);
  bytes.push(0x03, 0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01);
  return Buffer.from(bytes);
}

/** PNG mínimo: firma y cabecera IHDR con el ancho y alto dados. */
function png(w: number, h: number): Buffer {
  const bytes = Buffer.alloc(33);
  bytes.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], 0);
  bytes.writeUInt32BE(13, 8);
  bytes.write("IHDR", 12, "latin1");
  bytes.writeUInt32BE(w, 16);
  bytes.writeUInt32BE(h, 20);
  bytes[24] = 8;
  bytes[25] = 2;
  return bytes;
}

test("medidasJpeg lee el alto y el ancho del marcador SOF", () => {
  assert.deepEqual(medidasJpeg(jpeg({ w: 640, h: 480 })), { w: 640, h: 480 });
});

test("medidasJpeg salta un APP0 que va antes del SOF", () => {
  assert.deepEqual(medidasJpeg(jpeg({ w: 320, h: 200, app0: true })), { w: 320, h: 200 });
});

test("medidasJpeg rechaza lo que no empieza con FFD8", () => {
  assert.throws(() => medidasJpeg(Buffer.from("hola")), /no es un JPEG/);
});

test("medidasJpeg lanza si el JPEG no trae SOF", () => {
  assert.throws(() => medidasJpeg(Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x02])), /JPEG sin SOF/);
});

test("medidasImagen devuelve las medidas exactas de un PNG", () => {
  assert.deepEqual(medidasImagen(png(1200, 630)), { w: 1200, h: 630 });
});

test("medidasImagen devuelve las medidas de un JPEG", () => {
  assert.deepEqual(medidasImagen(jpeg({ w: 640, h: 480 })), { w: 640, h: 480 });
});

test("medidasImagen da null si el archivo no es imagen", () => {
  assert.equal(medidasImagen(Buffer.from("hola")), null);
});

test("medidasImagen da null si el JPEG está truncado", () => {
  assert.equal(medidasImagen(Buffer.from([0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x01])), null);
});

test("paginasDelSitemap deja la portada y las páginas de un nivel, no los artículos", () => {
  const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>${HOST}/</loc></url>
  <url><loc>${HOST}/docs</loc></url>
  <url><loc>${HOST}/blog</loc></url>
  <url><loc>${HOST}/blog/un-articulo</loc></url>
</urlset>`;
  assert.deepEqual(paginasDelSitemap(sitemap), ["/", "/docs", "/blog"]);
});

test("archivoPublico traduce una URL del sitio a su archivo en public/", () => {
  assert.equal(archivoPublico(`${HOST}/img/x.jpg`), "public/img/x.jpg");
});

test("archivoPublico da null para una URL de otro dominio", () => {
  assert.equal(archivoPublico("https://otro.example/img/x.jpg"), null);
});

test("archivoDe resuelve la landing, el índice del blog y las páginas normales", () => {
  assert.equal(archivoDe("/"), "public/landing.html");
  assert.equal(archivoDe("/blog"), "public/blog/index.html");
  assert.equal(archivoDe("/docs"), "public/docs.html");
});

const CABECERA = `<head>
<title>Título de prueba</title>
<meta
  name="description"
  content="Descripción de prueba"
/>
<meta content="es_MX" property="og:locale" />
<meta name="x-vacia" content="" />
</head>
<body><meta name="description" content="Meta fuera de la cabecera" /></body>`;

test("leerHead corta la cabecera en </head>", () => {
  const head = leerHead(CABECERA);
  assert.equal(head.includes("Meta fuera"), false);
  assert.equal(leerHead("<head></head>"), "<head>");
  assert.equal(leerHead("<head><title>sin cierre"), "<head><title>sin cierre");
});

test("metas lee name y property en cualquier orden y en varias líneas", () => {
  assert.deepEqual(metas(leerHead(CABECERA)), [
    { clave: "description", valor: "Descripción de prueba" },
    { clave: "og:locale", valor: "es_MX" },
    { clave: "x-vacia", valor: "" },
  ]);
});

test("meta devuelve el valor, incluido el vacío, y undefined si no existe", () => {
  const head = leerHead(CABECERA);
  assert.equal(meta(head, "og:locale"), "es_MX");
  assert.equal(meta(head, "x-vacia"), "");
  assert.equal(meta(head, "og:title"), undefined);
});

test("titulo lee el <title> y devuelve undefined si no hay", () => {
  assert.equal(titulo(leerHead(CABECERA)), "Título de prueba");
  assert.equal(titulo("<head></head>"), undefined);
});

test("grafo devuelve el @graph del único bloque JSON-LD", () => {
  const head = `<head><script type="application/ld+json">{"@graph":[{"@type":"WebSite","@id":"#website"}]}</script></head>`;
  assert.deepEqual(grafo(head), [{ "@type": "WebSite", "@id": "#website" }]);
});

test("grafo lanza si hay más de un bloque JSON-LD", () => {
  const bloque = `<script type="application/ld+json">{"@graph":[]}</script>`;
  assert.throws(() => grafo(`<head>${bloque}${bloque}</head>`), /un solo <script>/);
});

test("grafo lanza si el JSON-LD no trae @graph", () => {
  const head = `<head><script type="application/ld+json">{"@type":"WebSite"}</script></head>`;
  assert.throws(() => grafo(head), /falta @graph/);
});

test("OG_GENERICA apunta a la tarjeta social genérica del sitio", () => {
  assert.equal(OG_GENERICA, `${HOST}/img/og-image.png`);
});

// Una página completa según la ficha. Cada caso quita una pieza y mira qué regla la marca.
const RUTA = "/muestra";
const URL_MUESTRA = `${HOST}${RUTA}`;
const TITULO = "Página de muestra de las reglas de SEO";
const DESCRIPCION =
  "Página de muestra para probar las reglas de SEO, sin depender del contenido real de ninguna página del sitio; mide exactamente lo que pide la ficha.";

const OG = `<meta property="og:type" content="website" />
<meta property="og:site_name" content="MailMask" />
<meta property="og:locale" content="es_MX" />
<meta property="og:url" content="${URL_MUESTRA}" />
<meta property="og:title" content="${TITULO}" />
<meta property="og:description" content="${DESCRIPCION}" />
<meta property="og:image" content="${HOST}/img/og-docs.jpg" />
<meta property="og:image:width" content="1200" />
<meta property="og:image:height" content="630" />
<meta name="twitter:card" content="summary_large_image" />
<meta name="twitter:title" content="${TITULO}" />
<meta name="twitter:description" content="${DESCRIPCION}" />
<meta name="twitter:image" content="${HOST}/img/og-docs.jpg" />`;

function pagina({ canonical = true, og = true }: { canonical?: boolean; og?: boolean } = {}): string {
  return `<!doctype html>
<html lang="es-MX">
<head>
<meta charset="UTF-8" />
<title>${TITULO}</title>
<meta name="description" content="${DESCRIPCION}" />
${canonical ? `<link rel="canonical" href="${URL_MUESTRA}" />` : ""}
<link rel="alternate" hreflang="es-MX" href="${URL_MUESTRA}" />
<link rel="alternate" hreflang="x-default" href="${URL_MUESTRA}" />
${og ? OG : ""}
<script type="application/ld+json">{"@context":"https://schema.org","@graph":[{"@type":"WebSite","@id":"${HOST}/#website","url":"${HOST}/"}]}</script>
</head>
<body><main>Contenido de muestra</main></body>
</html>`;
}

test("huecos no reporta nada en una página completa", () => {
  assert.deepEqual(huecos(RUTA, pagina()), []);
});

test("huecos reporta og, og-coincide y og-imagen si la página no trae metas OG", () => {
  const faltas = huecos(RUTA, pagina({ og: false }));
  for (const esperada of ["og", "og-coincide", "og-imagen"]) {
    assert.ok(faltas.includes(esperada), `falta «${esperada}» en ${JSON.stringify(faltas)}`);
  }
});

test("huecos reporta canonical si la página no lo declara", () => {
  assert.ok(huecos(RUTA, pagina({ canonical: false })).includes("canonical"));
});
