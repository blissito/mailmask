import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

// Lo que npm publica se decide por el campo "files" de package.json. Esta prueba
// fija la lista: sólo dist/, el README y package.json. Si alguien agrega src/,
// test/ o un .env al paquete, la suite lo rechaza antes de que salga a npm.
const cliDir = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("contenido del tarball (npm pack)", () => {
  it("trae sólo dist/, README.md y package.json", () => {
    execFileSync("npm", ["run", "build"], { cwd: cliDir, stdio: "pipe" });
    const salida = execFileSync("npm", ["pack", "--dry-run", "--json"], {
      cwd: cliDir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const [paquete] = JSON.parse(salida);
    const archivos = paquete.files.map((f: { path: string }) => f.path).sort();
    for (const esperado of ["README.md", "dist/index.js", "package.json"]) {
      assert.ok(archivos.includes(esperado), `falta ${esperado} en el tarball`);
    }
    for (const archivo of archivos) {
      const permitido = archivo === "README.md" || archivo === "package.json" || archivo.startsWith("dist/");
      assert.ok(permitido, `sobra ${archivo} en el tarball`);
    }
  });
});
