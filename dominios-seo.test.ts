// Lo propio de /dominios: es una landing de precios que NO publica precios.
//
// El único endpoint con el precio por TLD (`GET /api/domains/tlds`) exige sesión, así que una
// página pública tendría que copiar `TLD_PRICES` a mano y quedarse como segunda fuente —el bug
// del «desde $549» frente a los 899 de la tabla—. La decisión es no publicar ninguna cifra por
// extensión y mandar al buscador; la única cifra permitida es el plan anual de `plans.ts`.
// Ficha: docs/agents/landing-dominios.md · Reglas comunes: seo-checks.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { DOMAIN_ANNUAL_PRICE } from "./plans.ts";
import { TLD_PRICES } from "./db.ts";
import { HOST, grafo, leerHead } from "./seo-checks.ts";

const html = readFileSync(new URL("./public/dominios.html", import.meta.url), "utf8");
const cuerpo = html.slice(html.indexOf("</head>"));
const sitemap = readFileSync(new URL("./public/sitemap.xml", import.meta.url), "utf8");
const head = leerHead(html);

/** Todo lo que la tabla curada cobra por registrar o por transferir, en pesos. */
const pesosDeTld = [...new Set(
  Object.values(TLD_PRICES).flatMap((t) => [t.userMxnCents, t.transferMxnCents]),
)].map((cents) => cents / 100);

test("la página no repite ningún precio de TLD_PRICES", () => {
  for (const precio of pesosDeTld) {
    assert.ok(
      !cuerpo.includes(`$${precio}`),
      `la página muestra $${precio}, que es un precio de TLD_PRICES: sería una segunda fuente frente a la tabla`,
    );
  }
});

test("la única cifra en pesos de la página es el plan anual de plans.ts", () => {
  const cifras = [...cuerpo.matchAll(/\$\d[\d,.]*/g)].map((m) => m[0]);
  assert.ok(cifras.length >= 1, "la página debería mencionar el dominio anual");
  for (const cifra of cifras) {
    assert.equal(cifra, `$${DOMAIN_ANNUAL_PRICE / 100}`, `la página publica ${cifra}, que no sale de plans.ts`);
  }
});

test("si la página dice que transferir sale más barato que renovar, TLD_PRICES lo respalda", () => {
  const dice = /transferencia[^.]*m[aá]s barat[ao] que renovar/i.test(cuerpo);
  const algunaMasBarata = Object.values(TLD_PRICES).some((t) => t.transferMxnCents < t.renewMxnCents);
  assert.ok(
    !dice || algunaMasBarata,
    "la página promete transferencia más barata que renovar y en TLD_PRICES ninguna extensión lo es (en .click/.link es más cara)",
  );
});

test("el @graph de /dominios no deja @id colgantes y no trae SoftwareApplication", () => {
  const nodos = grafo(head);
  const ids = new Set(nodos.map((n) => n["@id"]));
  assert.ok(ids.has(`${HOST}/#org`) && ids.has(`${HOST}/#website`) && ids.has(`${HOST}/dominios#webpage`));
  for (const m of JSON.stringify(nodos).matchAll(/\{"@id":"([^"]+)"\}/g)) {
    assert.ok(ids.has(m[1]), `@id colgante ${m[1]}`);
  }
  assert.doesNotMatch(JSON.stringify(nodos), /SoftwareApplication|MobileApplication|WebApplication|AggregateOffer/);
});

test("el WebPage es el de /dominios y su breadcrumb lleva Inicio → Dominios", () => {
  const nodos = grafo(head);
  const web = nodos.find((n) => n["@type"] === "WebPage");
  assert.ok(web, "falta el WebPage");
  assert.equal(web.url, `${HOST}/dominios`);
  assert.equal(web.isPartOf["@id"], `${HOST}/#website`);
  assert.equal(web.breadcrumb["@id"], `${HOST}/dominios#breadcrumb`);

  const bc = nodos.find((n) => n["@type"] === "BreadcrumbList");
  assert.deepEqual(bc.itemListElement.map((i: any) => i.name), ["Inicio", "Dominios"]);
  assert.equal(bc.itemListElement[1].item, `${HOST}/dominios`);
});

test("la página lleva a registro y a los artículos que promete", () => {
  for (const destino of ["/register", "/blog/enviar-emails-desde-dominio", "/blog/migrar-google-workspace-a-mailmask"]) {
    assert.match(html, new RegExp(`href="${destino}"`), `falta el enlace a ${destino}`);
  }
});

test("gen-sitemap.ts y sitemap.xml traen /dominios", () => {
  const generador = readFileSync(new URL("./scripts/gen-sitemap.ts", import.meta.url), "utf8");
  assert.match(
    generador,
    /\{ ruta: "\/dominios", archivo: "dominios\.html", freq: "monthly", prio: "0\.8" \}/,
    "sin su renglón en la lista de páginas el generador borra la URL del sitemap en silencio",
  );
  assert.match(sitemap, new RegExp(`<loc>${HOST}/dominios</loc><lastmod>\\d{4}-\\d{2}-\\d{2}</lastmod>`));
});

test("el footer de la landing enlaza /dominios", () => {
  const landing = readFileSync(new URL("./public/landing.html", import.meta.url), "utf8");
  assert.match(landing, /href="\/dominios"/, "la landing general no lleva a la página de dominios");
});

test("main.ts sirve /dominios y no la anuncia en la API", () => {
  const main = readFileSync(new URL("./main.ts", import.meta.url), "utf8");
  assert.match(main, /\.get\("\/dominios", \(\) => serveStatic\("\/dominios\.html"\)\)/);
  assert.match(main, /"\/bandeja-compartida", "\/dominios"/, "/dominios tiene que estar en exclude.paths del OpenAPI");
});

test("la fecha visible de /dominios es la del dateModified y la del lastmod del sitemap", () => {
  const visible = html.match(/Actualizado:\s*<time datetime="(\d{4}-\d{2}-\d{2})">/);
  assert.ok(visible, "falta «Actualizado: <time datetime=…>» a la vista");
  const web = grafo(head).find((n) => n["@type"] === "WebPage");
  assert.equal(visible![1], web.dateModified, "la fecha visible y la del JSON-LD");
  const lastmod = sitemap.match(new RegExp(`<loc>${HOST}/dominios</loc><lastmod>(\\d{4}-\\d{2}-\\d{2})</lastmod>`))?.[1];
  assert.equal(lastmod, web.dateModified, "el lastmod de /dominios en el sitemap");
});
