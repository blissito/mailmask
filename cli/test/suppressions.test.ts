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

const { default: suppressions } = await import("../src/commands/suppressions.js");
const { list, add, remove } = suppressions.subCommands as Record<string, any>;

describe("suppressions", () => {
  it("list llama suppressions.list con el id resuelto", async () => {
    const { client, calls } = fakeClient({ domains: { list: () => [{ id: "dom_9", domain: "acme.com" }] }, suppressions: { list: () => [] } });
    currentClient = client;
    await list.run({ args: { domain: "acme.com" } });
    assert.deepEqual(calls.find((c) => c.method === "suppressions.list")!.args, ["dom_9"]);
  });

  it("add llama suppressions.add con el correo", async () => {
    const { client, calls } = fakeClient({ suppressions: { add: () => ({ email: "a@x.com", reason: "manual", createdAt: "" }) } });
    currentClient = client;
    await add.run({ args: { domain: "dom_1", email: "a@x.com" } });
    assert.deepEqual(calls.find((c) => c.method === "suppressions.add")!.args, ["dom_1", "a@x.com"]);
  });

  it("remove --yes llama suppressions.remove", async () => {
    const { client, calls } = fakeClient({ suppressions: { remove: () => ({ ok: true }) } });
    currentClient = client;
    await remove.run({ args: { domain: "dom_1", email: "a@x.com", yes: true } });
    assert.deepEqual(calls.find((c) => c.method === "suppressions.remove")!.args, ["dom_1", "a@x.com"]);
  });

  it("remove sin TTY ni --yes sale con 1 sin llamar a la API (ni domains.list)", async () => {
    const { client, calls } = fakeClient({ suppressions: { remove: () => ({ ok: true }) } });
    currentClient = client;
    const tty = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
    try {
      await assert.rejects(() => remove.run({ args: { domain: "acme.com", email: "a@x.com" } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
    } finally {
      if (tty) Object.defineProperty(process.stdin, "isTTY", tty); else delete (process.stdin as any).isTTY;
    }
    assert.equal(calls.length, 0);
  });
});
