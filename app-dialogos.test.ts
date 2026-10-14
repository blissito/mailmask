// /app usaba confirm() y alert() nativos: ventanas del navegador sin la marca y con
// «Aceptar» en lugar del verbo. Ahora las confirmaciones pasan por confirmar() (diálogo
// propio) y los errores por showToast(msg, true). Prueba estática: lee los archivos, sin
// DOM. Foco, Escape y clic fuera se verifican a mano en la preview.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const leer = (ruta: string) => readFileSync(new URL(ruta, import.meta.url), "utf8");
const appJs = leer("./public/js/app.js");
const appHtml = leer("./public/app.html");

const VERBOS = [
  "Cancelar add-on",
  "Cancelar plan",
  "Eliminar dominio",
  "Eliminar dirección",
  "Eliminar regla",
  "Quitar del dominio",
  "Borrar registro",
  "Revocar credencial",
  "Revocar API key",
  "Generar contraseña nueva",
  "Borrar buzón",
];

test("app.js no usa confirm() ni alert() nativos", () => {
  assert.deepEqual(appJs.match(/\bconfirm\(/g) ?? [], []);
  assert.deepEqual(appJs.match(/\balert\(/g) ?? [], []);
});

test("app.html declara el diálogo propio con id confirm-dialog", () => {
  assert.match(appHtml, /<dialog[^>]*id="confirm-dialog"/);
});

test("confirmar() existe y devuelve una promesa de booleano por su firma", () => {
  assert.match(appJs, /function confirmar\(\{\s*titulo,\s*mensaje,\s*accion,\s*peligro = true\s*\}\)/);
});

test("las 12 confirmaciones llaman a confirmar() con await", () => {
  assert.equal(appJs.match(/await confirmar\(\{/g)?.length ?? 0, 12);
});

test("cada confirmación usa el verbo exacto de su acción", () => {
  for (const verbo of VERBOS) {
    assert.ok(appJs.includes(`accion: "${verbo}"`), `falta accion: "${verbo}"`);
  }
});

test("ningún botón de confirmación dice Aceptar ni OK", () => {
  assert.doesNotMatch(appJs, /accion:\s*["'`](Aceptar|OK)["'`]/);
});
