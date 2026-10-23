// Precios en USD de /pricing (solo referencia). `aUsd` es la única cuenta que hace la página:
// los literales salen a mano, porque una prueba que copia la fórmula pasa siempre.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

// El archivo es un script clásico para el navegador: lo corremos en un contexto vacío (sin DOM)
// y leemos lo que deja en el objeto global.
const src = readFileSync(new URL("./public/js/pricing-fx.js", import.meta.url), "utf8");
const contexto: { aUsd?: (mxn: number, tipo: number) => string | null } = {};
runInNewContext(src, contexto);
const aUsd = contexto.aUsd!;

test("convierte MXN a dólares y lo marca como aproximado", () => {
  assert.equal(aUsd(99, 18.33), "≈ US$5.40");
  assert.equal(aUsd(999, 18.33), "≈ US$54.50");
  assert.equal(aUsd(199, 17), "≈ US$11.71");
  assert.equal(aUsd(99, 16.5), "≈ US$6.00");
});

test("redondea al centavo más cercano y no trunca", () => {
  // 199 / 16 = 12.4375: truncar daría 12.43.
  assert.equal(aUsd(199, 16), "≈ US$12.44");
});

test("sin un tipo de cambio válido no muestra ningún monto en dólares", () => {
  for (const malo of [0, -3, NaN, undefined, null]) {
    assert.equal(aUsd(99, malo as number), null, `aceptó ${malo}`);
  }
});
