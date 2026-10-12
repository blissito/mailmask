// Lo propio de /alternativa-google-workspace: la comparativa con Google Workspace.
//
// Google cobra por persona y en la moneda de cada país, así que la página NO publica la
// conversión a pesos: publica la CITA (su página oficial de precios, con fecha de consulta) y
// nada más. La tabla completa vive sólo aquí —/pricing y la portada resumen y enlazan— porque
// dos tablas con la misma cifra es exactamente cómo se desfasan.
//
// Los precios de MailMask sí se publican, y salen de `plans.ts`: si alguien cambia el catálogo
// sin tocar la página, esta prueba truena. Reglas compartidas: seo-checks.ts ·
// Ficha: docs/agents/seo-paginas-publicas.md
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

import { ADDONS, DOMAIN_ACTIVATED, DOMAIN_ANNUAL_PRICE } from "./plans.ts";
import { HOST, OG_GENERICA, grafo, huecos, leerHead, meta as metaDe, medidasJpeg } from "./seo-checks.ts";

const leer = (ruta: string) => readFileSync(new URL(`./${ruta}`, import.meta.url), "utf8");

const html = leer("public/alternativa-google-workspace.html");
const head = leerHead(html);
const cuerpo = html.slice(html.indexOf("</head>"));
const sitemap = leer("public/sitemap.xml");
const pricing = leer("public/pricing.html");
const landing = leer("public/landing.html");
const meta = (clave: string) => metaDe(head, clave);

/** La cita que comparten la landing y /pricing: misma fuente y misma fecha. */
const FUENTE_GOOGLE = "https://workspace.google.com/pricing?hl=es_mx";
const CONSULTA = "2026-10-12";
// El enlace y su fecha, pegados uno al otro (el hueco es el propio marcado del `<a>` y la
// frase que lo sigue: más allá de eso ya no es una cita, son dos cosas sueltas en la página).
const cita = /href="https:\/\/workspace\.google\.com\/pricing\?hl=es_mx"[\s\S]{0,700}?<time datetime="2026-10-12">/;

test("la página no deja huecos de SEO", () => {
  assert.deepEqual(huecos("/alternativa-google-workspace", html), []);
});

test("los precios de MailMask de la página son los de plans.ts", () => {
  const cifras = [...cuerpo.matchAll(/\$\d[\d,.]*/g)].map((m) => m[0]);
  assert.ok(cifras.length >= 3, `la página debería publicar los precios de MailMask (encontré ${cifras.length})`);
  const permitidas = new Set([
    `$${ADDONS.domain.price / 100}`,                 // dominio activado, al mes
    `$${DOMAIN_ANNUAL_PRICE / 100}`,                 // el mismo dominio, pagado al año
    `$${(5 * ADDONS.domain.price) / 100}`,           // los 5 dominios del escenario de la tabla
  ]);
  for (const cifra of cifras) {
    assert.ok(permitidas.has(cifra), `la página publica ${cifra}, que no sale de plans.ts`);
  }
  assert.match(cuerpo, /el primero es gratis|dominio gratis/i, "el dominio gratis de plans.ts no aparece");
  assert.match(cuerpo, new RegExp(`\\b${DOMAIN_ACTIVATED.sends} (envíos|al día)`), `los ${DOMAIN_ACTIVATED.sends} envíos al día`);
  assert.match(cuerpo, new RegExp(`\\b${DOMAIN_ACTIVATED.mailboxBytes / 1024 ** 3} GB`), "el buzón del dominio activado");
});

test("cada fila de la comparativa que menciona a Google lleva su cita", () => {
  const filas = html.split(/<div class="grid grid-cols-3 px-4 py-3 border-t border-line"/).slice(1);
  const deGoogle = filas.filter((f) => f.slice(0, f.indexOf("</div>\n        </div>")).includes("data-precio-google"));
  assert.ok(deGoogle.length >= 3, `esperaba las filas de precios de Google (encontré ${deGoogle.length})`);
  for (const fila of deGoogle) {
    const celda = fila.slice(0, fila.indexOf("</div>\n        </div>"));
    assert.match(celda, /data-fuente-google/, "una fila habla de licencias de Google sin citar la fuente");
    assert.match(celda, /href="#fuente-precios"/, "la cita de la fila no apunta al bloque de la fuente");
  }
});

test("la cita de Google es la misma fuente y la misma fecha en la página y en /pricing", () => {
  const bloque = cuerpo.slice(cuerpo.indexOf('id="fuente-precios"'));
  assert.match(bloque, /por usuario al mes/i, "la cita no dice cómo cobra Google");
  assert.match(bloque, /no incluye impuestos/i, "la cita no copia lo que dice la fuente");
  assert.ok(bloque.includes(FUENTE_GOOGLE), "la cita no enlaza la página oficial de precios de Google");
  assert.match(bloque, new RegExp(`<time datetime="${CONSULTA}">`), "la cita no dice cuándo se consultó");

  for (const [nombre, pagina] of [["/pricing", pricing], ["la portada", landing]]) {
    assert.ok(pagina.includes(FUENTE_GOOGLE), `${nombre} no enlaza la página oficial de precios de Google`);
    assert.ok(pagina.includes(`<time datetime="${CONSULTA}">`), `${nombre} no fecha la consulta`);
    assert.match(pagina, cita, `${nombre} tiene el enlace y la fecha, pero no pegados como una cita`);
    assert.match(pagina, /href="\/alternativa-google-workspace"/, `${nombre} no manda a la comparativa`);
  }
});

test("la tabla completa vive sólo en la página, y /pricing y la portada la resumen", () => {
  for (const [nombre, pagina] of [["/pricing", pricing], ["la portada", landing]]) {
    assert.ok(!pagina.includes("data-precio-google"), `${nombre} repite la tabla de la comparativa`);
    assert.ok(!/\$495/.test(pagina), `${nombre} publica una cifra de Google o una fila de más`);
  }
  assert.ok(!/\$140/.test(pricing), "/pricing volvió a publicar la cifra de Google sin fuente");
  assert.match(landing, /href="\/alternativa-google-workspace"/, "el footer de la portada enlaza la comparativa");
});

test("los dos posts de Google Workspace enlazan la comparativa", () => {
  for (const post of ["public/blog/migrar-google-workspace-a-mailmask.html", "public/blog/email-profesional-sin-google-workspace.html"]) {
    assert.match(leer(post), /href="\/alternativa-google-workspace"/, `${post} no manda a la comparativa`);
  }
});

test("el @graph no deja @id colgantes y no trae SoftwareApplication", () => {
  const nodos = grafo(head);
  const ids = new Set(nodos.map((n) => n["@id"]));
  assert.ok(ids.has(`${HOST}/#org`) && ids.has(`${HOST}/#website`) && ids.has(`${HOST}/alternativa-google-workspace#webpage`));
  for (const m of JSON.stringify(nodos).matchAll(/\{"@id":"([^"]+)"\}/g)) {
    assert.ok(ids.has(m[1]), `@id colgante ${m[1]}`);
  }
  assert.doesNotMatch(JSON.stringify(nodos), /SoftwareApplication|MobileApplication|WebApplication|AggregateOffer/);

  const web = nodos.find((n) => n["@type"] === "WebPage");
  assert.equal(web.url, `${HOST}/alternativa-google-workspace`);
  assert.equal(web.isPartOf["@id"], `${HOST}/#website`);
  const bc = nodos.find((n) => n["@type"] === "BreadcrumbList");
  assert.deepEqual(bc.itemListElement.map((i: { name: string }) => i.name), ["Inicio", "Alternativa a Google Workspace"]);
});

test("gen-sitemap.ts y sitemap.xml traen /alternativa-google-workspace", () => {
  assert.match(
    leer("scripts/gen-sitemap.ts"),
    /\{ ruta: "\/alternativa-google-workspace", archivo: "alternativa-google-workspace\.html", freq: "monthly", prio: "0\.8" \}/,
    "sin su renglón en la lista de páginas el generador borra la URL del sitemap en silencio",
  );
  assert.match(sitemap, new RegExp(`<loc>${HOST}/alternativa-google-workspace</loc><lastmod>\\d{4}-\\d{2}-\\d{2}</lastmod>`));
});

test("main.ts sirve la página y no la anuncia en la API", () => {
  const main = leer("main.ts");
  assert.match(main, /\.get\("\/alternativa-google-workspace", \(\) => serveStatic\("\/alternativa-google-workspace\.html"\)\)/);
  assert.match(main, /"\/dominios", "\/alternativa-google-workspace"/, "tiene que estar en exclude.paths del OpenAPI");
});

test("la fecha visible de la página es la del dateModified y la del lastmod del sitemap", () => {
  const visible = html.match(/Actualizado:\s*<time datetime="(\d{4}-\d{2}-\d{2})">/);
  assert.ok(visible, "falta «Actualizado: <time datetime=…>» a la vista");
  const web = grafo(head).find((n) => n["@type"] === "WebPage");
  assert.equal(visible![1], web.dateModified, "la fecha visible y la del JSON-LD");
  const lastmod = sitemap.match(new RegExp(`<loc>${HOST}/alternativa-google-workspace</loc><lastmod>(\\d{4}-\\d{2}-\\d{2})</lastmod>`))?.[1];
  assert.equal(lastmod, web.dateModified, "el lastmod de la página en el sitemap");
});

test("la imagen social es propia, mide 1200×630 y pesa menos de 200 KB", () => {
  const ruta = new URL("./public/img/og-alternativa-google-workspace.jpg", import.meta.url);
  assert.ok(existsSync(ruta), "falta public/img/og-alternativa-google-workspace.jpg");
  const bytes = readFileSync(ruta);
  assert.deepEqual(medidasJpeg(bytes), { w: 1200, h: 630 });
  assert.ok(bytes.byteLength < 200 * 1024, `pesa ${Math.round(bytes.byteLength / 1024)} KB`);
  assert.ok(existsSync(new URL("./scripts/og-alternativa-google-workspace.html", import.meta.url)), "falta la plantilla de la imagen");
  assert.notEqual(meta("og:image"), OG_GENERICA, "la imagen social es la genérica del sitio");
});
