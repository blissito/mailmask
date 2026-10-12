// Lo propio de /pricing: un solo `@graph` con las 5 ofertas de hoy y una imagen social propia.
// Además amarra los precios que MUESTRA la página a `plans.ts` (lo que de verdad se cobra):
// si alguien cambia un precio en el catálogo sin tocar la página, esta prueba truena.
// Reglas compartidas y medidas de la imagen: seo-checks.ts · Ficha: docs/agents/seo-paginas-publicas.md
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

import { ADDONS, DOMAIN_ANNUAL_PRICE } from "./plans.ts";
import { HOST, grafo, leerHead, meta as metaDe, metas as metasDe, medidasJpeg } from "./seo-checks.ts";

const html = readFileSync(new URL("./public/pricing.html", import.meta.url), "utf8");
const sitemap = readFileSync(new URL("./public/sitemap.xml", import.meta.url), "utf8");
const head = leerHead(html);
const metas = metasDe(head);
const meta = (clave: string) => metaDe(head, clave);
const nodos = grafo(head);
const ofertas = (nodos.find((n) => n["@type"] === "Product")?.offers ?? []) as { name: string; price: string }[];
const precioMostrado = (cents: number) => String(cents / 100);

// Cada tarjeta de la página con su precio a la vista. `data-*` es lo que lee la prueba;
// el texto de al lado es lo que ve la persona.
const tarjeta = (attrs: string) => html.match(new RegExp(`<div[^>]*${attrs}[^>]*>[\\s\\S]*?</div>\\s*</div>`))?.[0] ?? "";

test("el @graph de /pricing trae un solo Product con las 5 ofertas y sus precios de plans.ts", () => {
  assert.equal(nodos.filter((n) => n["@type"] === "Product").length, 1, "los precios viven en un solo Product");
  assert.equal(ofertas.length, 5);

  const porNombre = Object.fromEntries(ofertas.map((o) => [o.name, o.price]));
  assert.equal(porNombre["Gratis"], "0", "el plan gratis no tiene precio en plans.ts: es $0 por definición");
  assert.equal(porNombre["Dominio activado"], precioMostrado(ADDONS.domain.price));
  assert.equal(porNombre["+50 GB de buzón"], precioMostrado(ADDONS.storage50.price));
  assert.equal(porNombre["+100 envíos al día"], precioMostrado(ADDONS.sends100.price));
  assert.equal(porNombre["Dominio activado — anual"], precioMostrado(DOMAIN_ANNUAL_PRICE));

  // El anual se cobra cada 12 meses, no cada mes: va en su propia UnitPriceSpecification.
  const anual = ofertas.find((o) => o.name === "Dominio activado — anual") as any;
  assert.equal(anual.priceSpecification["@type"], "UnitPriceSpecification");
  assert.equal(anual.priceSpecification.billingDuration, "P1Y");
  assert.equal(anual.priceSpecification.price, precioMostrado(DOMAIN_ANNUAL_PRICE));
  assert.deepEqual([...new Set(ofertas.map((o: any) => o.priceCurrency))], ["MXN"]);
});

test("los precios que muestra la tarjeta del dominio son los de plans.ts", () => {
  const attrs = "data-plan=\"dominio\"";
  assert.ok(html.includes(attrs), "la tarjeta del dominio perdió su data-plan");
  assert.equal(tarjeta(attrs).match(/data-monthly="(\d+)"/)?.[1], precioMostrado(ADDONS.domain.price));
  assert.equal(tarjeta(attrs).match(/data-yearly="(\d+)"/)?.[1], precioMostrado(DOMAIN_ANNUAL_PRICE));
  // El «ahorras» de la página es la diferencia real entre doce meses y el anual.
  const ahorro = (ADDONS.domain.price / 100) * 12 - DOMAIN_ANNUAL_PRICE / 100;
  assert.equal(tarjeta(attrs).match(/data-savings="(\d+)"/)?.[1], String(ahorro));
});

test("los bloques de add-on muestran el precio de plans.ts", () => {
  for (const kind of ["storage50", "sends100"] as const) {
    const bloque = tarjeta(`data-addon="${kind}"`);
    assert.ok(bloque, `la página no trae el bloque ${kind}`);
    const precio = precioMostrado(ADDONS[kind].price);
    assert.equal(bloque.match(/data-price="(\d+)"/)?.[1], precio, `el data-price de ${kind}`);
    assert.ok(bloque.includes(`+$${precio}`), `el bloque ${kind} no muestra +$${precio}`);
  }
});

test("un solo JSON-LD con @graph, sin @id colgantes y sin SoftwareApplication ni AggregateOffer", () => {
  assert.equal((head.match(/<script type="application\/ld\+json">/g) ?? []).length, 1);
  const ids = new Set(nodos.map((n) => n["@id"]));
  assert.ok(ids.has(`${HOST}/#org`) && ids.has(`${HOST}/#website`) && ids.has(`${HOST}/pricing#webpage`));
  for (const m of JSON.stringify(nodos).matchAll(/\{"@id":"([^"]+)"\}/g)) {
    assert.ok(ids.has(m[1]), `@id colgante ${m[1]}`);
  }
  assert.doesNotMatch(JSON.stringify(nodos), /SoftwareApplication|MobileApplication|WebApplication|AggregateOffer/);
});

test("el WebPage es el de /pricing y su breadcrumb lleva Inicio → Precios", () => {
  const web = nodos.find((n) => n["@type"] === "WebPage");
  assert.ok(web, "falta el WebPage");
  assert.equal(web.url, `${HOST}/pricing`);
  assert.equal(web.isPartOf["@id"], `${HOST}/#website`);
  assert.equal(web.breadcrumb["@id"], `${HOST}/pricing#breadcrumb`);
  assert.equal(web.primaryImageOfPage?.url, `${HOST}/img/og-pricing.jpg`);

  const bc = nodos.find((n) => n["@type"] === "BreadcrumbList");
  assert.deepEqual(bc.itemListElement.map((i: any) => i.name), ["Inicio", "Precios"]);
  assert.equal(bc.itemListElement[1].item, `${HOST}/pricing`);
});

test("la fecha visible de /pricing es la del dateModified y la del lastmod del sitemap", () => {
  const web = nodos.find((n) => n["@type"] === "WebPage");
  assert.match(web.dateModified, /^\d{4}-\d{2}-\d{2}$/);
  const visible = html.match(/Actualizado:\s*<time datetime="(\d{4}-\d{2}-\d{2})">/);
  assert.ok(visible, "falta «Actualizado: <time datetime=…>» a la vista");
  assert.equal(visible[1], web.dateModified, "la fecha visible y la del JSON-LD");
  const lastmod = sitemap.match(new RegExp(`<loc>${HOST}/pricing</loc><lastmod>(\\d{4}-\\d{2}-\\d{2})</lastmod>`))?.[1];
  assert.equal(lastmod, web.dateModified, "el lastmod de /pricing en el sitemap");
});

test("og-pricing.jpg es propia, mide lo que dicen sus metas y pesa menos de 200 KB", () => {
  const img = `${HOST}/img/og-pricing.jpg`;
  assert.equal(meta("og:image"), img);
  assert.equal(meta("og:image:secure_url"), img);
  assert.equal(meta("twitter:image"), img);
  assert.equal(meta("og:image:type"), "image/jpeg");
  assert.equal(metas.filter((m) => m.clave === "description").length, 1);

  const ruta = new URL("./public/img/og-pricing.jpg", import.meta.url);
  assert.ok(existsSync(ruta), "falta public/img/og-pricing.jpg");
  const buf = readFileSync(ruta);
  assert.ok(buf.length < 200 * 1024, `pesa ${buf.length} bytes`);
  const { w, h } = medidasJpeg(buf);
  assert.equal(String(w), meta("og:image:width"));
  assert.equal(String(h), meta("og:image:height"));
  assert.deepEqual([w, h], [1200, 630]);
  assert.ok(existsSync(new URL("./scripts/og-pricing.html", import.meta.url)), "falta la plantilla scripts/og-pricing.html");
});
