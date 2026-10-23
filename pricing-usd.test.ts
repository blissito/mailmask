// /pricing en USD: el selector, la nota de cobro en MXN, la pregunta del FAQ y el hook que usa
// el toggle anual de landing.js para formatear. Prueba estática: lee los archivos, sin DOM.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const html = readFileSync(new URL("./public/pricing.html", import.meta.url), "utf8");
const fxJs = readFileSync(new URL("./public/js/pricing-fx.js", import.meta.url), "utf8");
const landingJs = readFileSync(new URL("./public/js/landing.js", import.meta.url), "utf8");

test("el selector MXN / USD existe y arranca oculto hasta confirmar el tipo de cambio", () => {
  assert.match(html, /id="selector-moneda"[^>]*\bhidden\b/);
  assert.match(html, /data-moneda="mxn"/);
  assert.match(html, /data-moneda="usd"/);
});

test("pricing-fx.js carga antes que landing.js, que lo usa para formatear", () => {
  const fx = html.indexOf('src="/js/pricing-fx.js"');
  const landing = html.indexOf('src="/js/landing.js"');
  assert.ok(fx !== -1, "la página no carga pricing-fx.js");
  assert.ok(fx < landing, "pricing-fx.js llega después de landing.js");
});

test("en USD se lee que el cobro es en MXN por MercadoPago", () => {
  assert.match(html, /Se cobra en MXN por MercadoPago; tu banco hace la conversión/);
});

test("la pregunta «¿Puedo pagar en dólares?» está en el FAQ y en su JSON-LD", () => {
  assert.match(html, /<summary>¿Puedo pagar en dólares\?/);
  assert.ok(html.includes('"name": "¿Puedo pagar en dólares?"'), "falta en el FAQPage");
});

test("el JSON-LD sigue en MXN: la página en dólares no cambia lo que se cobra", () => {
  assert.ok(!/priceCurrency": "USD"/.test(html));
});

test("el selector lee ?moneda=usd y pide el tipo de cambio a /api/fx", () => {
  assert.match(fxJs, /fetch\("\/api\/fx"/);
  assert.match(fxJs, /get\("moneda"\) === "usd"/);
});

test("landing.js formatea con el mismo hook y no lee el monto de su texto", () => {
  assert.match(landingJs, /precioEnMoneda/);
  assert.match(landingJs, /dataset\.mxn/);
});
