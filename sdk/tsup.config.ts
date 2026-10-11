import { defineConfig } from "tsup";

// tsup sólo emite JS (ESM + CJS). Los tipos NO salen de aquí: `dts: true` necesita la API JS
// de TypeScript y el `tsc` de TS 7 (compilador nativo) ya no la expone. Los emite
// `tsc --emitDeclarationOnly` en el script `build` (ver docs/agents/dependencias-ci.md).
// El orden importa: tsup primero porque `clean: true` borra dist/.
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  clean: true,
});
