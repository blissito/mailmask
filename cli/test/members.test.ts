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

const { default: members } = await import("../src/commands/members.js");
const { list, invite, remove, "cancel-invite": cancelInvite } = members.subCommands as Record<string, any>;

const doms = () => [{ id: "dom_1", domain: "acme.com" }];

describe("members", () => {
  it("list resuelve el dominio por nombre y llama members.list con el id", async () => {
    const { client, calls } = fakeClient({ domains: { list: doms }, members: { list: () => ({ members: [], invites: [] }) } });
    currentClient = client;
    await list.run({ args: { domain: "acme.com" } });
    assert.deepEqual(calls.find((c) => c.method === "members.list")!.args, ["dom_1"]);
  });

  it("invite manda email, nombre y rol, e imprime la liga", async () => {
    const { client, calls } = fakeClient({ domains: { list: doms }, members: { invite: () => ({ ok: true, inviteUrl: "https://x/invite/abc" }) } });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await invite.run({ args: { domain: "dom_1", email: "l@acme.com", name: "Luis", role: "admin" } });
    } finally {
      out.restore();
    }
    assert.deepEqual(calls.find((c) => c.method === "members.invite")!.args, ["dom_1", { email: "l@acme.com", name: "Luis", role: "admin" }]);
    assert.match(out.text(), /https:\/\/x\/invite\/abc/);
  });

  it("invite con un rol inválido sale con 1 antes de tocar la red", async () => {
    const { client, calls } = fakeClient({});
    currentClient = client;
    requireClientCalls = 0;
    await assert.rejects(() => invite.run({ args: { domain: "dom_1", email: "l@acme.com", name: "Luis", role: "dueño" } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
    assert.equal(requireClientCalls, 0);
    assert.equal(calls.length, 0);
  });

  for (const [nombre, cmd, extra] of [["remove", remove, { member: "m1" }], ["cancel-invite", cancelInvite, { token: "tok" }]] as const) {
    it(`${nombre} sin TTY y sin --yes sale con 1 sin ninguna llamada`, async () => {
      const { client, calls } = fakeClient({});
      currentClient = client;
      requireClientCalls = 0;
      await assert.rejects(() => cmd.run({ args: { domain: "acme.com", ...extra } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
      assert.equal(requireClientCalls, 0);
      assert.equal(calls.length, 0);
    });
  }

  it("remove --yes llama members.remove", async () => {
    const { client, calls } = fakeClient({ domains: { list: doms }, members: { remove: () => ({ ok: true }) } });
    currentClient = client;
    await remove.run({ args: { domain: "acme.com", member: "m1", yes: true } });
    assert.deepEqual(calls.find((c) => c.method === "members.remove")!.args, ["dom_1", "m1"]);
  });

  it("cancel-invite --yes llama members.cancelInvite", async () => {
    const { client, calls } = fakeClient({ domains: { list: doms }, members: { cancelInvite: () => ({ ok: true }) } });
    currentClient = client;
    await cancelInvite.run({ args: { domain: "acme.com", token: "tok", yes: true } });
    assert.deepEqual(calls.find((c) => c.method === "members.cancelInvite")!.args, ["dom_1", "tok"]);
  });
});
