// Comprueba que dist/ sigue exportando EN RUNTIME los tres valores de la API pública, en las
// dos formas del paquete (ESM y CJS). Necesita `npm run build` antes.
// Los tipos los cubre scripts/check-exports.ts; esto cubre que los bundles no se vacíen.
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const esm = await import("../dist/index.js");
const cjs = require("../dist/index.cjs");
const esperados = ["MailMask", "MailMaskError", "verifyWebhookSignature"];

for (const [archivo, mod] of [["dist/index.js", esm], ["dist/index.cjs", cjs]]) {
  for (const nombre of esperados) {
    assert.equal(typeof mod[nombre], "function", `${archivo} no exporta ${nombre}`);
  }
}
console.log(`ok: dist/index.js y dist/index.cjs exportan ${esperados.join(", ")}`);
