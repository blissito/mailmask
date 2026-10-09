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

const { default: account } = await import("../src/commands/account.js");
const { profile, avatar } = account.subCommands as Record<string, any>;
const { set, remove } = avatar.subCommands as Record<string, any>;

const dir = mkdtempSync(join(tmpdir(), "mm-avatar-"));
const png = join(dir, "yo.png");
writeFileSync(png, Buffer.from([137, 80, 78, 71]));
const big = join(dir, "grande.jpg");
writeFileSync(big, Buffer.alloc(2 * 1024 * 1024 + 1));
const gif = join(dir, "yo.gif");
writeFileSync(gif, "x");

const perfil = { email: "a@b.com", displayName: "Ana", avatarUrl: null };

describe("account profile", () => {
  it("sin flags lee el perfil", async () => {
    const { client, calls } = fakeClient({ account: { getProfile: () => perfil } });
    currentClient = client;
    await profile.run({ args: {} });
    assert.deepEqual(calls.map((c) => c.method), ["account.getProfile"]);
  });

  it("--name actualiza el nombre", async () => {
    const { client, calls } = fakeClient({ account: { updateProfile: () => perfil } });
    currentClient = client;
    await profile.run({ args: { name: "Ana" } });
    assert.deepEqual(calls[0].args, [{ displayName: "Ana" }]);
  });

  it("--name \"\" lo borra (se manda la cadena vacía)", async () => {
    const { client, calls } = fakeClient({ account: { updateProfile: () => perfil } });
    currentClient = client;
    await profile.run({ args: { name: "" } });
    assert.deepEqual(calls[0].args, [{ displayName: "" }]);
  });

  it("--name de más de 60 caracteres sale con 1 sin tocar la red", async () => {
    const { client, calls } = fakeClient({});
    currentClient = client;
    requireClientCalls = 0;
    await assert.rejects(() => profile.run({ args: { name: "x".repeat(61) } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
    assert.equal(requireClientCalls, 0);
    assert.equal(calls.length, 0);
  });
});

describe("account avatar", () => {
  it("set arma el Blob con su MIME y llama setAvatar", async () => {
    const { client, calls } = fakeClient({ account: { setAvatar: () => ({ ...perfil, ok: true }) } });
    currentClient = client;
    await set.run({ args: { file: png } });
    const call = calls.find((c) => c.method === "account.setAvatar")!;
    assert.equal((call.args[0] as Blob).type, "image/png");
    assert.equal(call.args[1], "yo.png");
  });

  for (const [nombre, file] of [["formato inválido", gif], ["más de 2 MB", big], ["archivo inexistente", join(dir, "no.png")]] as const) {
    it(`set con ${nombre} sale con 1 antes de tocar la red`, async () => {
      const { client, calls } = fakeClient({});
      currentClient = client;
      requireClientCalls = 0;
      await assert.rejects(() => set.run({ args: { file } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
      assert.equal(requireClientCalls, 0);
      assert.equal(calls.length, 0);
    });
  }

  it("set no tiene --url", () => {
    assert.equal("url" in set.args, false);
  });

  it("remove sin TTY y sin --yes sale con 1 sin pedir cliente ni llamar al SDK", async () => {
    const { client, calls } = fakeClient({});
    currentClient = client;
    requireClientCalls = 0;
    await assert.rejects(() => remove.run({ args: {} }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
    assert.equal(requireClientCalls, 0);
    assert.equal(calls.length, 0);
  });

  it("remove --yes llama removeAvatar", async () => {
    const { client, calls } = fakeClient({ account: { removeAvatar: () => ({ ...perfil, ok: true }) } });
    currentClient = client;
    await remove.run({ args: { yes: true } });
    assert.deepEqual(calls.map((c) => c.method), ["account.removeAvatar"]);
  });
});
