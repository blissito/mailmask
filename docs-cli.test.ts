// La CLI se documenta en tres lugares (cli/README.md, public/docs.html#cli y public/llms.txt)
// y los tres se desfasaron de `main` más de una vez. Esta prueba lee los comandos del código
// fuente de cli/src (sin importarlo: cli/ tiene su propio node_modules) y exige que los
// documentos públicos los mencionen. Ficha: docs/agents/mailmask-cli.md
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";

const leer = (ruta: string) => readFileSync(new URL(ruta, import.meta.url), "utf8");

/** Claves del objeto `subCommands: { a, "b-c": x, d: y }` → ["a", "b-c", "d"]. */
function claves(cuerpo: string): string[] {
  return cuerpo
    .split(",")
    .map((p) => p.trim().split(":")[0].trim().replace(/^"|"$/g, ""))
    .filter(Boolean);
}

/** Rutas completas de comando (`aliases mailbox reset-password`) leídas de cli/src. */
export function comandosDelCli(): { topLevel: string[]; rutas: string[] } {
  const topLevel = claves(leer("./cli/src/index.ts").match(/subCommands:\s*\{([^}]*)\}/)![1]);

  // Un grupo es `meta: { name: "x" ... }, subCommands: { ... }` dentro de cli/src/commands/.
  const grupos = new Map<string, string[]>();
  for (const archivo of readdirSync(new URL("./cli/src/commands", import.meta.url))) {
    const src = leer(`./cli/src/commands/${archivo}`);
    for (const m of src.matchAll(/meta:\s*\{\s*name:\s*"([^"]+)"[^}]*\},\s*subCommands:\s*\{([^}]*)\}/g)) {
      grupos.set(m[1], claves(m[2]));
    }
  }

  const expandir = (prefijo: string, nombre: string): string[] => {
    const ruta = prefijo ? `${prefijo} ${nombre}` : nombre;
    const hijos = grupos.get(nombre);
    return hijos ? hijos.flatMap((h) => expandir(ruta, h)) : [ruta];
  };
  return { topLevel, rutas: topLevel.flatMap((t) => expandir("", t)) };
}

/** Texto plano de la sección `<h2 id="cli">` de docs.html (hasta el siguiente `<h2`). */
function seccionCli(): string {
  const html = leer("./public/docs.html");
  const ini = html.indexOf('<h2 id="cli"');
  assert.ok(ini >= 0, 'docs.html no tiene <h2 id="cli">');
  const fin = html.indexOf("<h2 ", ini + 10);
  return html
    .slice(ini, fin)
    .replace(/<[^>]+>/g, "")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&mdash;/g, "—");
}

test("el lector de comandos ve la CLI de main (si no, esta prueba no vigila nada)", () => {
  const { topLevel, rutas } = comandosDelCli();
  assert.deepEqual(topLevel, ["login", "logout", "whoami", "domains", "dns", "aliases", "webhooks", "smtp", "api-keys", "rules", "suppressions", "inbox", "canned", "signature"]);
  assert.ok(rutas.includes("aliases mailbox reset-password"), "no expandió aliases mailbox");
  assert.ok(rutas.includes("dns create-zone"));
  assert.ok(rutas.includes("api-keys revoke") && rutas.includes("webhooks deliveries"), "no expandió webhooks/api-keys");
  assert.ok(rutas.length >= 20, `solo ${rutas.length} rutas`);
});

test("docs.html#cli lista cada comando de la CLI", () => {
  const texto = seccionCli();
  const faltan = comandosDelCli().rutas.filter((r) => !texto.includes(`mailmask ${r}`));
  assert.deepEqual(faltan, [], "comandos que la CLI tiene y /docs no menciona");
});

test("docs.html#cli explica exit codes 0–5, --json, --yes y la contraseña enmascarada", () => {
  const texto = seccionCli();
  for (const codigo of [0, 1, 2, 3, 4, 5]) {
    assert.match(texto, new RegExp(`(^|\\s)${codigo}\\s+[—-]`), `falta el código de salida ${codigo}`);
  }
  assert.match(texto, /--json/);
  assert.match(texto, /--yes/);
  assert.match(texto, /enmascar/i, "no explica que la contraseña del buzón sale enmascarada");
});

test("docs.html#cli ya no promete cosas que main ya trae", () => {
  const texto = seccionCli();
  assert.doesNotMatch(texto, /PR en revisi/i);
  assert.doesNotMatch(texto, /PR aparte/i);
  assert.doesNotMatch(texto, /llegan despu/i);
});

test("llms.txt menciona cada comando de primer nivel de la CLI y los buzones", () => {
  const llms = leer("./public/llms.txt");
  const { topLevel } = comandosDelCli();
  const faltan = topLevel.filter((c) => !new RegExp(`\\b${c}\\b`).test(llms));
  assert.deepEqual(faltan, []);
  for (const palabra of ["mailbox", "apple-profile", "export", "--json", "--yes"]) {
    assert.ok(llms.includes(palabra), `llms.txt no menciona ${palabra}`);
  }
});

test("docs.html#cli no repite párrafos", () => {
  const html = leer("./public/docs.html");
  const ini = html.indexOf('<h2 id="cli"');
  const parrafos = [...html.slice(ini, html.indexOf("<h2 ", ini + 10)).matchAll(/<p [^>]*>(.*?)<\/p>/gs)].map((m) => m[1].trim());
  const repetidos = parrafos.filter((p, i) => parrafos.indexOf(p) !== i);
  assert.deepEqual(repetidos, []);
});
