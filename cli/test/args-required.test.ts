import assert from "node:assert/strict";
import { describe, it, mock } from "node:test";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runCommand } from "citty";
import { fakeClient, trapExit } from "./test-helpers.js";

let currentClient: ReturnType<typeof fakeClient>["client"];

trapExit();
// Mismo motivo que en aliases.test.ts/dns.test.ts: el mock de `requireClient`
// tiene que quedar en pie ANTES del import dinámico de los comandos.
mock.module("../src/client.js", {
  namedExports: {
    requireClient: async () => ({
      client: currentClient,
      auth: { apiKey: "mk_test", baseUrl: undefined, source: "env" as const },
    }),
    buildClient: () => currentClient,
  },
});

const { default: aliases } = await import("../src/commands/aliases.js");
const { default: account } = await import("../src/commands/account.js");
const { default: apiKeys } = await import("../src/commands/api-keys.js");
const { default: webhooks } = await import("../src/commands/webhooks.js");
const { default: inbox } = await import("../src/commands/inbox.js");

type AnyCommand = { run?: (ctx: never) => unknown; subCommands?: Record<string, AnyCommand> };
const cmd = (root: unknown, ...path: string[]): AnyCommand =>
  path.reduce<AnyCommand>((node, part) => node.subCommands![part], root as AnyCommand);

/**
 * Lo que el usuario ve al olvidar un argumento obligatorio es el error de uso
 * de citty: sale con 1 y nombra el arg que falta, ANTES de tocar el SDK. Esta
 * prueba fija ese contrato para que el bump de citty 0.1 → 0.2 no lo mueva
 * sin que nadie se entere (issue #55).
 */
const CASOS: Array<{ nombre: string; c: AnyCommand; falta: string }> = [
  { nombre: "aliases create sin <domain>", c: cmd(aliases, "create"), falta: "DOMAIN" },
  { nombre: "account avatar set sin <file>", c: cmd(account, "avatar", "set"), falta: "FILE" },
  { nombre: "api-keys create sin <name>", c: cmd(apiKeys, "create"), falta: "NAME" },
  { nombre: "webhooks create sin <domain>", c: cmd(webhooks, "create"), falta: "DOMAIN" },
];

describe("positional obligatorio ausente: error de uso sin tocar el SDK", () => {
  for (const caso of CASOS) {
    it(caso.nombre, async () => {
      const { client, calls } = fakeClient();
      currentClient = client;
      await assert.rejects(
        () => runCommand(caso.c as never, { rawArgs: [] }),
        (err: Error) => {
          assert.match(err.message, /Missing required positional argument/);
          assert.match(err.message, new RegExp(`: ${caso.falta}$`));
          return true;
        },
      );
      assert.deepEqual(calls, [], "sin el positional no debe llamar al SDK");
    });
  }

  it("el positional opcional no se exige: inbox assign sin <user> desasigna", async () => {
    const { client, calls } = fakeClient({ inbox: { assign: () => ({ ok: true }) } });
    currentClient = client;
    try {
      await runCommand(cmd(inbox, "assign") as never, { rawArgs: ["dom_1", "conv_1"] });
    } catch (err) {
      assert.doesNotMatch((err as Error).message, /Missing required positional/, "el <user> es opcional");
    }
    assert.ok(
      calls.some((c) => c.method === "inbox.assign"),
      "sin <user>, assign desasigna en vez de fallar por uso",
    );
  });
});

// Y por el binario, que es donde el error se ve de verdad: exit code y texto.
const CLI_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const ENTRY = join(CLI_DIR, "src", "index.ts");

/** citty 0.2 colorea aunque stdout no sea una terminal (0.1 sólo coloreaba en TTY),
 *  así que la comparación de texto va sobre la salida sin secuencias ANSI: lo que
 *  esta prueba fija es QUÉ dice el error, no de qué color lo pinta citty. */
const sinAnsi = (s: string | null): string => (s ?? "").replace(/\u001B\[[0-9;]*m/g, "");

function runCli(argv: string[]) {
  return spawnSync(process.execPath, ["--import", "tsx", ENTRY, ...argv], {
    cwd: CLI_DIR,
    encoding: "utf8",
    timeout: 60_000,
    env: { ...process.env, MAILMASK_API_KEY: "" },
  });
}

describe("el error de uso que ve el usuario al correr el binario", () => {
  it("mailmask aliases create: exit 1, imprime el USAGE y el arg que falta", () => {
    const r = runCli(["aliases", "create"]);
    assert.equal(r.status, 1);
    assert.match(sinAnsi(r.stdout), /USAGE aliases create \[OPTIONS\] <DOMAIN> <ALIAS>/);
    assert.match(sinAnsi(r.stderr), /Missing required positional argument: DOMAIN/);
  });

  it("mailmask account avatar set: exit 1 y nombra el arg que falta", () => {
    const r = runCli(["account", "avatar", "set"]);
    assert.equal(r.status, 1);
    assert.match(sinAnsi(r.stderr), /Missing required positional argument: FILE/);
  });
});
