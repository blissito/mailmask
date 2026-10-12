// SEO de las páginas públicas del sitemap (las del blog van aparte, una prueba por artículo).
// Las reglas viven en seo-checks.ts; aquí sólo se corren contra cada página y se comparan con
// la lista de PENDIENTES. Ficha: docs/agents/seo-paginas-publicas.md
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { HOST, archivoDe, huecos, paginasDelSitemap } from "./seo-checks.ts";

const leer = (ruta: string) => readFileSync(new URL(`./${ruta}`, import.meta.url), "utf8");

const RUTAS = paginasDelSitemap(leer("public/sitemap.xml"));

/**
 * Huecos de hoy, página → reglas incumplidas. Los vacían los tickets B–D del sprint #9.
 * Claves: title · title-largo · description · description-medida · canonical · hreflang · og ·
 * og-coincide · jsonld-unico · jsonld-graph · softwareapplication · og-imagen · og-medidas ·
 * og-propia · fecha-visible (ver la ficha).
 */
const PENDIENTES: Record<string, string[]> = {
  "/": ["og-coincide", "jsonld-unico", "jsonld-graph", "softwareapplication", "og-propia"],
  "/pricing": ["description-medida", "hreflang", "og-coincide", "jsonld-unico", "jsonld-graph", "og-propia"],
  "/blog": ["description-medida", "hreflang", "og-coincide", "jsonld-unico", "jsonld-graph", "og-propia"],
  "/register": ["hreflang", "jsonld-graph", "og-propia"],
  "/login": ["description-medida", "hreflang", "jsonld-graph", "og-propia"],
  "/terms": ["hreflang", "jsonld-graph", "og-propia", "fecha-visible"],
  "/privacy": ["hreflang", "jsonld-graph", "og-propia", "fecha-visible"],
  "/docs": [],
};

/** Páginas que además muestran su fecha de actualización (ficha). */
const CON_FECHA_VISIBLE = ["/docs", "/terms", "/privacy"];

/**
 * Compara lo que la página incumple contra su fila de PENDIENTES. Falla en las dos
 * direcciones: un hueco que nadie apuntó, y un pendiente que ya se arregló y sigue listado.
 */
function revisar(ruta: string, html: string, pendientes: string[]): void {
  const reales = huecos(ruta, html, { fechaVisible: CON_FECHA_VISIBLE.includes(ruta) }).sort();
  const esperados = [...pendientes].sort();
  assert.deepEqual(
    { nuevos: reales.filter((h) => !esperados.includes(h)), arreglados: esperados.filter((h) => !reales.includes(h)) },
    { nuevos: [], arreglados: [] },
    `${ruta}: así queda su fila de PENDIENTES → ${JSON.stringify(reales)}`,
  );
}

test("el sitemap lista páginas que existen como archivo", () => {
  assert.ok(RUTAS.length >= 8, `el sitemap sólo trae ${RUTAS.length} páginas`);
  for (const ruta of RUTAS) {
    assert.ok(existsSync(new URL(`./${archivoDe(ruta)}`, import.meta.url)), `${ruta} no tiene ${archivoDe(ruta)}`);
  }
});

test("la tabla de pendientes habla sólo de páginas del sitemap", () => {
  assert.deepEqual(Object.keys(PENDIENTES).filter((ruta) => !RUTAS.includes(ruta)), []);
});

test("cada página pública cumple las reglas, salvo lo apuntado en PENDIENTES", () => {
  for (const ruta of RUTAS) revisar(ruta, leer(archivoDe(ruta)), PENDIENTES[ruta] ?? []);
});

// La regla es una función pura, así que quitarle una pieza a una página de muestra demuestra
// que el chequeo falla por lo que dice fallar (y que la comparación no perdona un pendiente viejo).

const DESCRIPCION = "Página de muestra para probar las reglas de SEO, sin depender del contenido real de ninguna página del sitio; mide exactamente lo que pide la ficha.";

const MUESTRA = `<!doctype html>
<html lang="es-MX">
<head>
<meta charset="UTF-8" />
<title>Página de muestra de las reglas de SEO</title>
<meta name="description" content="${DESCRIPCION}" />
<link rel="canonical" href="${HOST}/muestra" />
<link rel="alternate" hreflang="es-MX" href="${HOST}/muestra" />
<link rel="alternate" hreflang="x-default" href="${HOST}/muestra" />
<meta property="og:type" content="website" />
<meta property="og:site_name" content="MailMask" />
<meta property="og:locale" content="es_MX" />
<meta property="og:url" content="${HOST}/muestra" />
<meta property="og:title" content="Página de muestra de las reglas de SEO" />
<meta property="og:description" content="${DESCRIPCION}" />
<meta property="og:image" content="${HOST}/img/og-docs.jpg" />
<meta property="og:image:width" content="1200" />
<meta property="og:image:height" content="630" />
<meta name="twitter:card" content="summary_large_image" />
<meta name="twitter:title" content="Página de muestra de las reglas de SEO" />
<meta name="twitter:description" content="${DESCRIPCION}" />
<meta name="twitter:image" content="${HOST}/img/og-docs.jpg" />
<script type="application/ld+json">
{"@context":"https://schema.org","@graph":[{"@type":"Organization","@id":"${HOST}/#org","name":"MailMask","url":"${HOST}/"},{"@type":"WebSite","@id":"${HOST}/#website","url":"${HOST}/","publisher":{"@id":"${HOST}/#org"}}]}
</script>
</head>
<body><h1>Muestra</h1></body>
</html>
`;

const muestraSin = (pieza: string) => MUESTRA.replace(pieza, "");
const muestraCon = (pieza: string, nueva: string) => MUESTRA.replace(pieza, nueva);

test("una página de muestra sin huecos no reporta nada", () => {
  assert.deepEqual(huecos("/muestra", MUESTRA), []);
});

test("quitarle una pieza a la muestra levanta exactamente su hueco", () => {
  const jsonld = MUESTRA.match(/<script type="application\/ld\+json">[\s\S]*?<\/script>/)![0];
  const casos: [string, string, string][] = [
    ["canonical", `<link rel="canonical" href="${HOST}/muestra" />`, "canonical"],
    ["hreflang x-default", `<link rel="alternate" hreflang="x-default" href="${HOST}/muestra" />`, "hreflang"],
    ["og:image", `<meta property="og:image" content="${HOST}/img/og-docs.jpg" />`, "og"],
    ["el bloque JSON-LD", jsonld, "jsonld-unico"],
  ];
  for (const [nombre, pieza, hueco] of casos) {
    const rotas = huecos("/muestra", muestraSin(pieza));
    assert.ok(rotas.includes(hueco), `sin ${nombre} faltó "${hueco}" (reportó ${JSON.stringify(rotas)})`);
  }
});

test("los huecos de contenido y de valor también se reportan", () => {
  const largo = muestraCon("<title>Página de muestra de las reglas de SEO</title>", `<title>${"Título de muestra que pasa de los sesenta caracteres de la ficha"}</title>`);
  assert.ok(huecos("/muestra", largo).includes("title-largo"));

  const corta = muestraCon(DESCRIPCION, "Corta.");
  assert.ok(huecos("/muestra", corta).includes("description-medida"));

  const desalineada = muestraCon(`<meta property="og:title" content="Página de muestra de las reglas de SEO" />`, '<meta property="og:title" content="Otro título" />');
  assert.ok(huecos("/muestra", desalineada).includes("og-coincide"));

  const generica = muestraCon(`${HOST}/img/og-docs.jpg`, `${HOST}/img/og-image.png`);
  assert.ok(huecos("/muestra", generica).includes("og-propia"));

  const software = muestraCon('"@type":"Organization"', '"@type":"SoftwareApplication"');
  assert.ok(huecos("/muestra", software).includes("softwareapplication"));
});

test("un hueco nuevo y un pendiente ya arreglado hacen fallar la comparación", () => {
  assert.throws(() => revisar("/muestra", muestraSin('<link rel="canonical" href="' + HOST + '/muestra" />'), []), /nuevos/);
  assert.throws(() => revisar("/muestra", MUESTRA, ["canonical"]), /arreglados/);
  assert.doesNotThrow(() => revisar("/muestra", MUESTRA, []));
});
