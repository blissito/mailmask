import assert from "node:assert/strict";
import { describe, it, mock } from "node:test";
import { MailMaskError } from "@easybits.cloud/mailmask";
import { fakeClient, trapExit, ExitSignal } from "./test-helpers.js";

let currentClient: ReturnType<typeof fakeClient>["client"];

const ACTIVE = "llave-activa-de-prueba";

trapExit();
mock.module("../src/client.js", {
  namedExports: {
    requireClient: async () => ({
      client: currentClient,
      auth: { apiKey: ACTIVE, baseUrl: undefined, source: "env" as const },
    }),
    buildClient: () => currentClient,
  },
});

const { default: apiKeys } = await import("../src/commands/api-keys.js");
const { list, create, revoke } = apiKeys.subCommands as Record<string, any>;

const NEW_KEY = "llave-nueva-de-prueba";
const keys = [
  { id: "k_active", name: "mi laptop", keyPrefix: "llave-activa", lastUsedAt: "2026-10-01", createdAt: "x" },
  { id: "k_other", name: "ci", keyPrefix: "llave-otra", createdAt: "x" },
];

function capture(stream: "stdout" | "stderr"): { text: () => string; restore: () => void } {
  let text = "";
  const fn = mock.method(process[stream], "write", (chunk: string) => {
    text += chunk;
    return true;
  });
  return { text: () => text, restore: () => fn.mock.restore() };
}

describe("api-keys list", () => {
  it("muestra nombre, prefijo y marca la activa; nunca una llave completa", async () => {
    const { client } = fakeClient({ apiKeys: { list: () => keys } });
    currentClient = client;
    const out = capture("stdout");
    try {
      await list.run({ args: {} });
    } finally {
      out.restore();
    }
    const lines = out.text().split("\n");
    assert.match(lines.find((l) => l.includes("k_active"))!, /activa/i);
    assert.doesNotMatch(lines.find((l) => l.includes("k_other"))!, /activa/i);
    assert.ok(!out.text().includes(ACTIVE));
  });

  it("--json marca la activa con active: true", async () => {
    const { client } = fakeClient({ apiKeys: { list: () => keys } });
    currentClient = client;
    const out = capture("stdout");
    try {
      await list.run({ args: { json: true } });
    } finally {
      out.restore();
    }
    const parsed = JSON.parse(out.text());
    assert.equal(parsed.find((k: any) => k.id === "k_active").active, true);
    assert.equal(parsed.find((k: any) => k.id === "k_other").active, false);
  });
});

describe("api-keys create", () => {
  it("imprime la llave completa una vez, con aviso", async () => {
    const { client, calls } = fakeClient({ apiKeys: { create: () => ({ id: "k_new", name: "bot", keyPrefix: "llave-nueva", createdAt: "x", key: NEW_KEY }) } });
    currentClient = client;
    const out = capture("stdout");
    try {
      await create.run({ args: { name: "bot" } });
    } finally {
      out.restore();
    }
    assert.deepEqual(calls.find((c) => c.method === "apiKeys.create")!.args, ["bot"]);
    assert.ok(out.text().includes(NEW_KEY));
    assert.match(out.text(), /no se vuelve a mostrar/i);
  });
});

describe("api-keys revoke", () => {
  it("sin --yes y sin TTY sale con 1 y no llama a la API (ni siquiera a list)", async () => {
    const { client, calls } = fakeClient({ apiKeys: { list: () => keys, revoke: () => ({ ok: true }) } });
    currentClient = client;
    await assert.rejects(
      () => revoke.run({ args: { id: "k_other" } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 1,
    );
    assert.equal(calls.length, 0);
  });

  it("llave que no es la activa: revoca sin aviso", async () => {
    const { client, calls } = fakeClient({ apiKeys: { list: () => keys, revoke: () => ({ ok: true }) } });
    currentClient = client;
    const out = capture("stdout");
    const err = capture("stderr");
    try {
      await revoke.run({ args: { id: "k_other", yes: true, json: true } });
    } finally {
      out.restore();
      err.restore();
    }
    assert.deepEqual(calls.find((c) => c.method === "apiKeys.revoke")!.args, ["k_other"]);
    assert.doesNotMatch(err.text(), /sin llave/);
    assert.equal(JSON.parse(out.text()).activeKeyRevoked, undefined);
  });

  it("llave activa con --yes: avisa por stderr, revoca y marca activeKeyRevoked en --json", async () => {
    const { client, calls } = fakeClient({ apiKeys: { list: () => keys, revoke: () => ({ ok: true }) } });
    currentClient = client;
    const out = capture("stdout");
    const err = capture("stderr");
    try {
      await revoke.run({ args: { id: "k_active", yes: true, json: true } });
    } finally {
      out.restore();
      err.restore();
    }
    assert.match(err.text(), /sesión quedará sin llave/);
    assert.ok(calls.some((c) => c.method === "apiKeys.revoke"));
    assert.equal(JSON.parse(out.text()).activeKeyRevoked, true);
  });

  it("llave activa en texto: sugiere mailmask login", async () => {
    const { client } = fakeClient({ apiKeys: { list: () => keys, revoke: () => ({ ok: true }) } });
    currentClient = client;
    const out = capture("stdout");
    const err = capture("stderr");
    try {
      await revoke.run({ args: { id: "k_active", yes: true } });
    } finally {
      out.restore();
      err.restore();
    }
    assert.match(out.text(), /mailmask login/);
  });

  it("404 al revocar → exit 4", async () => {
    const { client } = fakeClient({ apiKeys: { list: () => keys, revoke: () => { throw new MailMaskError(404, "no existe"); } } });
    currentClient = client;
    await assert.rejects(
      () => revoke.run({ args: { id: "k_other", yes: true } }),
      (e: unknown) => e instanceof ExitSignal && e.code === 4,
    );
  });
});
