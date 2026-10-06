import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, it, mock, test } from "node:test";
import { MailMaskError } from "@easybits.cloud/mailmask";
import { fakeClient, trapExit, ExitSignal } from "./test-helpers.js";

let currentClient: ReturnType<typeof fakeClient>["client"];

trapExit();
// Mismo motivo que en dns.test.ts/domains.test.ts: el mock tiene que estar en
// pie ANTES del import dinámico de whoami.ts, no dentro de un `before()`.
mock.module("../src/client.js", {
  namedExports: {
    requireClient: async () => ({
      client: currentClient,
      auth: { apiKey: "mk_test", baseUrl: undefined, source: "env" as const },
    }),
    buildClient: () => currentClient,
  },
});

const { default: whoamiCmd } = await import("../src/commands/whoami.js");
const whoami = whoamiCmd as Record<string, any>;

function captureStderr(): { text: () => string } {
  let text = "";
  mock.method(process.stderr, "write", (chunk: string) => {
    text += chunk;
    return true;
  });
  return { text: () => text };
}

describe("whoami --json: errores respetan el contrato --json", () => {
  it("con 401, sale con código 2 e imprime {error, status} a stderr", async () => {
    const { client } = fakeClient({ apiKeys: { list: () => { throw new MailMaskError(401, "llave inválida"); } } });
    currentClient = client;
    const out = captureStderr();
    await assert.rejects(
      () => whoami.run({ args: { json: true } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 2,
    );
    assert.deepEqual(JSON.parse(out.text()), { error: "llave inválida", status: 401 });
  });
});

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
