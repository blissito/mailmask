// Borrar en la Bandeja no pide confirmación: lo borrado va a la papelera 15 días y
// «Deshacer» lo regresa con un clic. Ficha: docs/agents/bandeja-deshacer.md
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const leer = (ruta: string) => readFileSync(new URL(`./${ruta}`, import.meta.url), "utf8");
const JS = leer("public/js/bandeja.js");
const CSS = leer("public/css/bandeja.css");

/** El cuerpo de una función de bandeja.js: desde su `function` hasta la llave que la cierra en columna 0. */
function cuerpo(nombre: string): string {
  const abre = JS.indexOf(`function ${nombre}(`);
  assert.ok(abre >= 0, `falta function ${nombre}()`);
  const cierra = JS.indexOf("\n}\n", abre);
  assert.ok(cierra > abre, `${nombre}() no cierra en columna 0`);
  return JS.slice(abre, cierra);
}

test("bandeja.js no vuelve a pedir confirm() para borrar", () => {
  assert.doesNotMatch(JS, /\bconfirm\(/);
});

test("borrar la conversación abierta deshace con /restore", () => {
  assert.match(cuerpo("deleteConversation"), /\/restore/);
});

test("borrar en lote deshace con /restore, sólo de los ids que estaban vivos", () => {
  const f = cuerpo("borrarSeleccionadas");
  assert.match(f, /\/restore/);
  assert.match(f, /deletedAt/, "un id ya borrado no se debe restaurar: el servidor responde 404");
});

test("el aviso con «Deshacer» dura 6 segundos y lleva botón", () => {
  const f = cuerpo("toastDeshacer");
  assert.match(f, /6000/);
  assert.match(f, /createElement\("button"\)/);
  assert.match(f, /Deshacer/);
});

test("un toast normal limpia el «Deshacer» previo", () => {
  assert.match(cuerpo("toast"), /clearTimeout/);
});

test("sólo el aviso con botón recibe clics", () => {
  assert.match(CSS, /\.mesa-toast\.con-accion\s*\{[^}]*pointer-events:\s*auto/);
});
