// Borrar en la Bandeja no pide confirmación: lo borrado va a la papelera 15 días y
// «Deshacer» lo regresa con un clic. Ficha: docs/agents/bandeja-deshacer.md
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";

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

test("si «Deshacer» falla por red, avisa en vez de tirar un error sin atrapar", () => {
  assert.match(
    cuerpo("deleteConversation"),
    /try\s*\{[\s\S]*\/restore[\s\S]*\}\s*catch[\s\S]*No se pudo restaurar/,
  );
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

test("AGENTS.md enlaza cada ficha de docs/agents", () => {
  const indice = leer("AGENTS.md");
  const sinEnlace = readdirSync(new URL("./docs/agents", import.meta.url))
    .filter((f) => f.endsWith(".md"))
    .filter((f) => !indice.includes(`docs/agents/${f}`));
  assert.deepEqual(sinEnlace, [], "fichas sin renglón en AGENTS.md");
});

test("AGENTS.md conserva la entrada de diálogos y pone la de Bandeja debajo", () => {
  const indice = leer("AGENTS.md");
  const dialogos = indice.indexOf("docs/agents/dialogos-app.md");
  const bandeja = indice.indexOf("docs/agents/bandeja-deshacer.md");
  assert.ok(dialogos >= 0, "se perdió el renglón de dialogos-app.md");
  assert.ok(bandeja > dialogos, "el renglón de Bandeja debe ir después del de diálogos");
});
