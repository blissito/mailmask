// SEO de las páginas públicas del sitemap (las del blog van aparte, una prueba por artículo).
// Las reglas viven en seo-checks.ts; aquí sólo se corren contra cada página y se comparan con
// la lista de PENDIENTES. Ficha: docs/agents/seo-paginas-publicas.md
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { HOST, archivoDe, grafo, huecos, leerHead, paginasDelSitemap } from "./seo-checks.ts";

const leer = (ruta: string) => readFileSync(new URL(`./${ruta}`, import.meta.url), "utf8");

const RUTAS = paginasDelSitemap(leer("public/sitemap.xml"));

/**
 * Huecos de hoy, página → reglas incumplidas. Los vacían los tickets B–D del sprint #9.
 * Claves: title · title-largo · description · description-medida · canonical · hreflang · og ·
 * og-coincide · jsonld-unico · jsonld-graph · softwareapplication · og-imagen · og-medidas ·
 * og-propia · fecha-visible (ver la ficha).
 */
const PENDIENTES: Record<string, string[]> = {
  "/": ["og-coincide", "og-propia"],
  "/pricing": ["description-medida", "hreflang", "og-coincide", "jsonld-unico", "jsonld-graph", "og-propia"],
  "/blog": ["description-medida", "hreflang", "og-coincide", "jsonld-unico", "jsonld-graph", "og-propia"],
  "/register": ["hreflang", "jsonld-graph", "og-propia"],
  "/login": ["description-medida", "hreflang", "jsonld-graph", "og-propia"],
  "/terms": ["hreflang", "jsonld-graph", "og-propia", "fecha-visible"],
  "/privacy": ["hreflang", "jsonld-graph", "og-propia", "fecha-visible"],
  "/docs": [],
};

/** Páginas que además muestran su fecha de actualización (ficha). */
const CON_FECHA_VISIBLE = ["/", "/docs", "/terms", "/privacy"];

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

// El JSON-LD de la landing (`/`): un solo `@graph` con Organization, WebSite, WebPage,
// BreadcrumbList, Product y FAQPage. Los planes y precios viven en UN Product —el
// SoftwareApplication que los duplicaba y que Google marca inválido sin ratings ya no existe—
// y `dateModified` es la misma fecha que se ve en el pie y que el `lastmod` del sitemap.
// Ficha: docs/agents/seo-paginas-publicas.md

const LANDING = leer("public/landing.html");
const SITEMAP = leer("public/sitemap.xml");
const nodosDeLaLanding = () => grafo(leerHead(LANDING));

test("el @graph de / trae FAQPage con 10 Question con Answer y el BreadcrumbList «Inicio»", () => {
  const nodos = nodosDeLaLanding();
  const faq = nodos.find((n) => n["@type"] === "FAQPage");
  assert.ok(faq, "falta el FAQPage");
  assert.equal(faq.mainEntity.length, 10, "el plan pide las 10 preguntas frecuentes");
  for (const q of faq.mainEntity) {
    assert.equal(q["@type"], "Question");
    assert.ok(q.name, "una Question va sin name");
    assert.equal(q.acceptedAnswer?.["@type"], "Answer", `«${q.name}» sin Answer`);
    assert.ok(q.acceptedAnswer.text.length > 40, `respuesta demasiado corta en «${q.name}»`);
  }

  const bc = nodos.find((n) => n["@type"] === "BreadcrumbList");
  assert.ok(bc, "falta el BreadcrumbList (la ruta «Inicio»)");
  assert.deepEqual(bc.itemListElement.map((i: any) => i.name), ["Inicio"]);
  assert.equal(bc.itemListElement[0].item, `${HOST}/`);
});

test("el @graph de / trae un solo Product con sus 4 offers y brand #org", () => {
  const nodos = nodosDeLaLanding();
  const productos = nodos.filter((n) => n["@type"] === "Product");
  assert.equal(productos.length, 1, `hay ${productos.length} Product: los precios viven en uno solo`);
  const [producto] = productos;
  assert.equal(producto.brand["@id"], `${HOST}/#org`);
  assert.equal(producto.offers.length, 4);
  assert.deepEqual([...new Set(producto.offers.map((o: any) => o.priceCurrency))], ["MXN"]);

  // El SoftwareApplication que se borró traía su propia AggregateOffer con los mismos precios.
  const plano = JSON.stringify(nodos);
  assert.doesNotMatch(plano, /SoftwareApplication|MobileApplication|WebApplication|AggregateOffer/);
  assert.equal([...plano.matchAll(/"price":"(\d+)"/g)].length, 4, "los precios se declaran una sola vez");
});

test("el WebPage de / no deja referencias colgantes y declara la fecha de actualización", () => {
  const nodos = nodosDeLaLanding();
  const ids = new Set(nodos.map((n) => n["@id"]));
  assert.ok(ids.has(`${HOST}/#org`) && ids.has(`${HOST}/#website`) && ids.has(`${HOST}/#webpage`));
  for (const m of JSON.stringify(nodos).matchAll(/\{"@id":"([^"]+)"\}/g)) {
    assert.ok(ids.has(m[1]), `@id colgante ${m[1]}`);
  }
  const web = nodos.find((n) => n["@type"] === "WebPage");
  assert.ok(web, "falta el WebPage");
  assert.match(web.dateModified, /^\d{4}-\d{2}-\d{2}$/);
  assert.equal(web.isPartOf["@id"], `${HOST}/#website`);
  assert.equal(web.breadcrumb["@id"], `${HOST}/#breadcrumb`);
});

test("la fecha visible de / es la del dateModified y la del lastmod del sitemap", () => {
  const web = nodosDeLaLanding().find((n) => n["@type"] === "WebPage");
  const visible = LANDING.match(/Actualizado:\s*<time datetime="(\d{4}-\d{2}-\d{2})">/);
  assert.ok(visible, "falta «Actualizado: <time datetime=…>» a la vista");
  assert.equal(visible[1], web.dateModified, "la fecha visible y la del JSON-LD");
  const lastmod = SITEMAP.match(new RegExp(`<loc>${HOST}/</loc><lastmod>(\\d{4}-\\d{2}-\\d{2})</lastmod>`))?.[1];
  assert.equal(lastmod, web.dateModified, "el lastmod de / en el sitemap");
});
