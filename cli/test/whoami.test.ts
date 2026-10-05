import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, test } from "node:test";

// Corre el binario de verdad (no la función run() aislada): lo que importa aquí
// es el contrato de salida del proceso completo — exit code, stderr, sin stack
// trace y sin colgarse —, no sólo que resolveAuth() devuelva null.
const cliRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const tsx = join(cliRoot, "node_modules", ".bin", "tsx");

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "mailmask-cli-whoami-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

test("whoami sin sesión activa: sale con código 2 y un mensaje claro en stderr, sin colgarse ni tronar", () => {
  const result = spawnSync(tsx, ["src/index.ts", "whoami"], {
    cwd: cliRoot,
    encoding: "utf8",
    timeout: 10_000,
    env: {
      ...process.env,
      // El `npm test` de la raíz del repo exporta NODE_OPTIONS=--import
      // ./test-setup.mjs (ruta relativa a SU cwd); heredarlo aquí tronaba el
      // proceso hijo con ERR_MODULE_NOT_FOUND antes de llegar a citty, y el
      // exit code 1 de ESE crash se confundía con un fallo real del comando.
      NODE_OPTIONS: "",
      MAILMASK_NO_KEYCHAIN: "1",
      MAILMASK_CONFIG_DIR: dir,
      MAILMASK_API_KEY: "",
    },
  });

  assert.equal(result.signal, null, "no debió matarse por timeout ni por una señal");
  assert.equal(result.status, 2);
  assert.match(result.stderr, /No hay una API key activa/);
  assert.doesNotMatch(result.stderr, /\bat .+:\d+:\d+/, "no debe imprimir un stack trace");
  assert.equal(result.stdout.trim(), "");
});
