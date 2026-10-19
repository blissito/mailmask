// Pedido #110: en lo que lee quien usa la CLI (README y la sección #cli de la documentación web)
// el recurso se llama «dirección», nunca «alias» ni «máscara». El nombre del comando `aliases`
// y del flag `--alias` se quedan (son identificadores, no texto). Ficha: docs/agents/mailmask-cli.md
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const leer = (ruta: string) => readFileSync(new URL(ruta, import.meta.url), "utf8");

// Quita los identificadores que sí se conservan, para que sólo quede el texto visible.
const sinIdentificadores = (t: string) => t.replace(/aliases/g, "").replace(/--alias\b/g, "");
const PROHIBIDO = /\balias\b|m(á|&aacute;|a)scara\b/i;
const lineasProhibidas = (t: string) => sinIdentificadores(t).split("\n").filter((l) => PROHIBIDO.test(l));

test("la sección #cli de la documentación web dice «dirección», no «alias»", () => {
  const html = leer("./public/docs.html");
  const cli = html.slice(html.indexOf('id="cli"'), html.indexOf('id="mcp"'));
  assert.ok(cli.length > 0, "no encontré la sección #cli");
  assert.deepEqual(lineasProhibidas(cli), []);
});

test("cli/README.md dice «dirección», no «alias»", () => {
  assert.deepEqual(lineasProhibidas(leer("./cli/README.md")), []);
});
