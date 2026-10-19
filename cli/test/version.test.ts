import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

// La versión sale de cli/package.json, no de un literal en el código: un
// release que sube package.json y olvida el literal publica un --version falso.
// Se prueba contra el BUILD (dist/), no contra src/: el bug posible es de rutas
// en dist, y src no lo ejercita.
const cliDir = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("mailmask --version contra el build", () => {
  it("imprime la misma versión que cli/package.json", () => {
    execFileSync("npm", ["run", "build"], { cwd: cliDir, stdio: "pipe" });
    const { version } = JSON.parse(readFileSync(join(cliDir, "package.json"), "utf8"));
    const salida = execFileSync(process.execPath, [join(cliDir, "dist", "index.js"), "--version"], {
      cwd: cliDir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    assert.equal(salida.trim(), version);
  });
});
