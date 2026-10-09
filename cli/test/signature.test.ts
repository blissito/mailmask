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

const { default: signature } = await import("../src/commands/signature.js");
const { get, set } = signature.subCommands as Record<string, any>;

describe("signature", () => {
  it("get llama signature.get con el id resuelto", async () => {
    const { client, calls } = fakeClient({ domains: { list: () => [{ id: "dom_9", domain: "acme.com" }] }, signature: { get: () => ({ signature: null }) } });
    currentClient = client;
    await get.run({ args: { domain: "acme.com" } });
    assert.deepEqual(calls.find((c) => c.method === "signature.get")!.args, ["dom_9"]);
  });

  it("set llama signature.set con el markdown", async () => {
    const { client, calls } = fakeClient({ signature: { set: () => ({ ok: true, signature: "**Ana**" }) } });
    currentClient = client;
    await set.run({ args: { domain: "dom_1", markdown: "**Ana**" } });
    assert.deepEqual(calls.find((c) => c.method === "signature.set")!.args, ["dom_1", "**Ana**"]);
  });

  it('set "" la borra (manda la cadena vacía)', async () => {
    const { client, calls } = fakeClient({ signature: { set: () => ({ ok: true, signature: null }) } });
    currentClient = client;
    await set.run({ args: { domain: "dom_1", markdown: "" } });
    assert.deepEqual(calls.find((c) => c.method === "signature.set")!.args, ["dom_1", ""]);
  });

  it("set con más de 2000 caracteres sale con 1 sin tocar la API", async () => {
    const { client, calls } = fakeClient();
    currentClient = client;
    await assert.rejects(() => set.run({ args: { domain: "dom_1", markdown: "x".repeat(2001) } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
    assert.equal(calls.length, 0);
  });

  it("set acepta justo 2000 caracteres", async () => {
    const { client, calls } = fakeClient({ signature: { set: () => ({ ok: true, signature: "x" }) } });
    currentClient = client;
    await set.run({ args: { domain: "dom_1", markdown: "x".repeat(2000) } });
    assert.equal(calls.some((c) => c.method === "signature.set"), true);
  });
});
