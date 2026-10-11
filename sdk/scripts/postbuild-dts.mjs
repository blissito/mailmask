// `tsc --emitDeclarationOnly` escribe las declaraciones como están en `src/`, y `src/index.ts`
// usa `export type * from "./types.js"`, sintaxis que llegó en TS 5.0. tsup la aplanaba, así que
// el `.d.ts` publicado no la llevaba; al emitirla tsc sí, y un consumidor con TS 4.9 truena en
// SU compilación con `TS1383: Only named exports may use 'export type'` — en silencio, porque
// aquí nada falla.
//
// Se baja a `export *`, que significa lo mismo en un `.d.ts` (no hay JS detrás: `types.ts` sólo
// declara tipos) y lo entienden todas las versiones. `export type { X } from "…"` se deja como
// está: existe desde TS 3.8. La sintaxis de TS 5+ que no se puede arreglar sola hace fallar el
// build en vez de llegar al paquete publicado.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

const DIST = new URL("../dist/", import.meta.url);
const REEXPORT = /^(\s*)export type \*/gm; // sólo `export type *` es TS 5.0+
const SIN_ARREGLO = [
  [/<const\s/, "parámetro de tipo `const` (TS 5.0)"],
  [/^\s*(await\s+)?using\s+\w/m, "declaración `using` (TS 5.2)"],
];

const archivos = readdirSync(DIST).filter((f) => f.endsWith(".d.ts") || f.endsWith(".d.cts"));
if (archivos.length === 0) throw new Error("no hay .d.ts en dist/: ¿corriste el build completo?");

let bajados = 0;
for (const f of archivos) {
  const ruta = new URL(f, DIST);
  const antes = readFileSync(ruta, "utf8");
  const despues = antes.replace(REEXPORT, "$1export *");
  if (despues !== antes) {
    writeFileSync(ruta, despues);
    bajados += (antes.match(REEXPORT) ?? []).length;
  }
}

const problemas = [];
for (const f of archivos) {
  const txt = readFileSync(new URL(f, DIST), "utf8");
  for (const [re, que] of SIN_ARREGLO) if (re.test(txt)) problemas.push(`${f}: ${que}`);
}
if (problemas.length) {
  throw new Error(
    "los tipos publicados usarían sintaxis que un consumidor con TypeScript viejo no puede leer:\n  " +
      problemas.join("\n  ") +
      "\nArréglalo en el build (o en src/ si de verdad hay que subir el mínimo de TypeScript) antes de publicar."
  );
}

console.log(`postbuild-dts: ${bajados} reexport(s) \`export type *\` bajados a \`export *\` en ${archivos.length} archivos`);
