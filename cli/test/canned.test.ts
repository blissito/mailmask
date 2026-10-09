import assert from "node:assert/strict";
import { describe, it, mock } from "node:test";
import { fakeClient, trapExit, ExitSignal } from "./test-helpers.js";

let currentClient: ReturnType<typeof fakeClient>["client"];

trapExit();
mock.module("../src/client.js", {
  namedExports: {
    requireClient: async () => ({ client: currentClient, auth: { apiKey: "mk_test", baseUrl: undefined, source: "env" as const } }),
    buildClient: () => currentClient,
  },
});

const { default: canned } = await import("../src/commands/canned.js");
const { list, create, delete: del } = canned.subCommands as Record<string, any>;

describe("canned", () => {
  it("list llama canned.list con el id resuelto", async () => {
    const { client, calls } = fakeClient({ domains: { list: () => [{ id: "dom_9", domain: "acme.com" }] }, canned: { list: () => [] } });
    currentClient = client;
    await list.run({ args: { domain: "acme.com" } });
    assert.deepEqual(calls.find((c) => c.method === "canned.list")!.args, ["dom_9"]);
  });

  it("create llama canned.create con título y cuerpo", async () => {
    const { client, calls } = fakeClient({ canned: { create: () => ({ id: "k1", title: "Gracias", body: "Gracias por escribir" }) } });
    currentClient = client;
    await create.run({ args: { domain: "dom_1", title: "Gracias", body: "Gracias por escribir" } });
    assert.deepEqual(calls.find((c) => c.method === "canned.create")!.args, ["dom_1", { title: "Gracias", body: "Gracias por escribir" }]);
  });

  it("delete --yes llama canned.delete", async () => {
    const { client, calls } = fakeClient({ canned: { delete: () => ({ ok: true }) } });
    currentClient = client;
    await del.run({ args: { domain: "dom_1", id: "k1", yes: true } });
    assert.deepEqual(calls.find((c) => c.method === "canned.delete")!.args, ["dom_1", "k1"]);
  });

  it("delete sin TTY ni --yes sale con 1 sin llamar a la API (ni domains.list)", async () => {
    const { client, calls } = fakeClient({ canned: { delete: () => ({ ok: true }) } });
    currentClient = client;
    const tty = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
    try {
      await assert.rejects(() => del.run({ args: { domain: "acme.com", id: "k1" } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
    } finally {
      if (tty) Object.defineProperty(process.stdin, "isTTY", tty); else delete (process.stdin as any).isTTY;
    }
    assert.equal(calls.length, 0);
  });
});
