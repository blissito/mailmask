import assert from "node:assert/strict";
import { describe, it, mock } from "node:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fakeClient, trapExit, ExitSignal, captureWrites } from "./test-helpers.js";

let currentClient: ReturnType<typeof fakeClient>["client"];
let requireClientCalls = 0;

trapExit();
mock.module("../src/client.js", {
  namedExports: {
    requireClient: async () => {
      requireClientCalls++;
      return { client: currentClient, auth: { apiKey: "mk_test", baseUrl: undefined, source: "env" as const } };
    },
    buildClient: () => currentClient,
  },
});

import type { ArgsDef, CommandDef } from "citty";
const { default: referrals } = await import("../src/commands/referrals.js");
const { get, slug, name } = referrals.subCommands as Record<string, any>;

describe("referrals", () => {
  it("get, slug y name son 1:1 con el SDK", async () => {
    const { client, calls } = fakeClient({ referrals: { get: () => ({ slug: "ana", referrals: [] }), setSlug: () => ({ ok: true, slug: "ana-2" }), setName: () => ({ ok: true }) } });
    currentClient = client;
    await get.run({ args: {} });
    await slug.run({ args: { slug: "ana-2" } });
    await name.run({ args: { name: "Ana" } });
    assert.deepEqual(calls.map((c) => [c.method, ...c.args]), [["referrals.get"], ["referrals.setSlug", "ana-2"], ["referrals.setName", "Ana"]]);
  });
});

// Nada de esta tanda acepta un código EPP: el código llega por correo al dueño y no pasa por el CLI.
async function nombresDeArgs(cmd: CommandDef, ruta = ""): Promise<string[]> {
  const args = ((typeof cmd.args === "function" ? await (cmd.args as () => Promise<ArgsDef>)() : cmd.args) ?? {}) as ArgsDef;
  const propios = Object.keys(args).map((n) => `${ruta} ${n}`);
  const subs = (typeof cmd.subCommands === "function" ? await (cmd.subCommands as () => Promise<Record<string, CommandDef>>)() : cmd.subCommands) ?? {};
  const hijos = await Promise.all(Object.entries(subs).map(([n, c]) => nombresDeArgs(c as CommandDef, `${ruta} ${n}`)));
  return [...propios, ...hijos.flat()];
}

describe("sin código EPP", () => {
  it("ningún argumento de account, members, billing, registrations, transfers ni referrals se llama epp/auth-code/authcode", async () => {
    const mods = await Promise.all(["account", "members", "billing", "registrations", "transfers", "referrals"].map((m) => import(`../src/commands/${m}.js`)));
    const todos = (await Promise.all(mods.map((m, i) => nombresDeArgs(m.default, String(i))))).flat();
    assert.ok(todos.length > 30, `solo recorrí ${todos.length} argumentos`);
    assert.deepEqual(todos.filter((n) => /epp|auth-?code/i.test(n)), []);
  });
});
