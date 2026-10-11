// Comprueba que `dist/` sigue publicando la MISMA API que antes del cambio a TypeScript 7.
//
// El archivo que pasa por el compilador se GENERA aquí desde `exports-reference.json` (la lista
// de exports de `dist/index.d.ts` en `main`, sacada con el compilador y no con grep): una sola
// fuente, sin la copia a mano que podía divergir del JSON.
//
// Por qué así: con TS 7 tsup ya no genera los tipos, y `dist/index.d.ts` deja de ser un bundle
// con todo inline para volverse un índice que sólo reexporta (`export * from "./client.js"`).
// Comparar su texto daría falso rojo y un grep de nombres no prueba nada; que el compilador
// resuelva los tipos publicados sí: si un nombre desaparece o deja de ser valor, esto falla.
//
// Uso: `npm run check:exports` (necesita `npm run build` antes).
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";

const SCRIPTS = new URL("./", import.meta.url);
const REF = JSON.parse(readFileSync(new URL("exports-reference.json", SCRIPTS), "utf8"));

if (!Array.isArray(REF.detail) || REF.detail.length < 90) {
  throw new Error(
    `exports-reference.json trae ${REF.detail?.length ?? 0} nombres: es la referencia de la API publicada ` +
      `(90 en main, ${REF.commit?.slice(0, 7) ?? "?"}) y encogerla apaga esta comprobación a medias. ` +
      `Si de verdad se quiere sacar un export, hazlo a propósito y anota por qué en el PR.`
  );
}
const tipos = REF.detail.filter((d) => d.type).map((d) => d.name);
const valores = REF.detail.filter((d) => d.value).map((d) => d.name);
if (!tipos.includes("MailMask") || !valores.includes("verifyWebhookSignature")) {
  throw new Error("exports-reference.json está corrupta: no encuentro MailMask (tipo) y verifyWebhookSignature (valor)");
}

const lineas = [
  "// GENERADO por scripts/check-exports.mjs desde exports-reference.json — no lo edites a mano.",
  `// Referencia: ${REF.detail.length} exports de dist/index.d.ts en main (${REF.commit?.slice(0, 7)}, TypeScript ${REF.typescript}).`,
  'import * as sdk from "../../dist/index.js";',
  "",
  `/* --- Tipos publicados (${tipos.length}) --- */`,
  ...tipos.map((n) => `type T_${n} = sdk.${n};`),
  "",
  `/* --- Valores publicados (${valores.length}) --- */`,
  ...valores.map((n) => `const V_${n} = sdk.${n};`),
  "",
  "// Los alias se usan para que el compilador no los descarte.",
  "export type PublicTypes = readonly [",
  ...tipos.map((n) => `  T_${n},`),
  "];",
  `export const publicValues: readonly unknown[] = [${valores.map((n) => `V_${n}`).join(", ")}];`,
  "",
];

const GEN = new URL(".gen/", SCRIPTS);
mkdirSync(GEN, { recursive: true });
writeFileSync(new URL("check-exports.ts", GEN), lineas.join("\n"));
// Va también el proyecto (generado) porque el `tsc` de TS 7 se niega a compilar archivos sueltos
// si hay un tsconfig.json arriba en el árbol (`TS5112`): con `-p` se compila sólo este.
writeFileSync(
  new URL("tsconfig.json", GEN),
  JSON.stringify(
    {
      compilerOptions: { target: "ES2022", module: "ESNext", moduleResolution: "bundler", strict: true, skipLibCheck: false, noEmit: true },
      files: ["check-exports.ts"],
    },
    null,
    2
  ) + "\n"
);

const tsc = new URL("../node_modules/.bin/tsc", SCRIPTS).pathname;
try {
  execFileSync(tsc, ["-p", "scripts/.gen/tsconfig.json"], { cwd: new URL("../", SCRIPTS).pathname, stdio: "inherit" });
} catch {
  console.error(
    "\ncheck-exports: algún nombre de la referencia ya no está (o dejó de ser valor) en dist/index.d.ts.\n" +
      "Si el cambio de API es intencional, actualiza exports-reference.json en este mismo PR y dilo en la descripción."
  );
  process.exit(1);
}
console.log(`check-exports: ok, ${tipos.length} tipos y ${valores.length} valores siguen publicados (generado desde exports-reference.json)`);
