import assert from "node:assert/strict";
import { describe, it, mock } from "node:test";
import { MailMaskError } from "@easybits.cloud/mailmask";
import { fakeClient, trapExit, ExitSignal } from "./test-helpers.js";

let currentClient: ReturnType<typeof fakeClient>["client"];

trapExit();
mock.module("../src/client.js", {
  namedExports: {
    requireClient: async () => ({
      client: currentClient,
      auth: { apiKey: "mk_test", baseUrl: undefined, source: "env" as const },
    }),
    buildClient: () => currentClient,
  },
});

const { default: smtp } = await import("../src/commands/smtp.js");
const { list, create, revoke } = smtp.subCommands as Record<string, any>;

const PASSWORD = "password-de-prueba";
const cred = { id: "cr_1", domainId: "dom_1", label: "app", iamUsername: "usuario-de-prueba", createdAt: "now" };
const created = { id: "cr_1", label: "app", server: "smtp.mailmask.studio", port: 587, encryption: "STARTTLS", username: "usuario-de-prueba", password: PASSWORD, createdAt: "now" };

function captureStdout(): { text: () => string; restore: () => void } {
  let text = "";
  const fn = mock.method(process.stdout, "write", (chunk: string) => {
    text += chunk;
    return true;
  });
  return { text: () => text, restore: () => fn.mock.restore() };
}

describe("smtp create", () => {
  it("llama smtp.create con la etiqueta e imprime la contraseña completa una vez", async () => {
    const { client, calls } = fakeClient({ smtp: { create: () => created } });
    currentClient = client;
    const out = captureStdout();
    try {
      await create.run({ args: { domain: "dom_1", label: "app" } });
    } finally {
      out.restore();
    }
    assert.deepEqual(calls.find((c) => c.method === "smtp.create")!.args, ["dom_1", "app"]);
    const text = out.text();
    assert.ok(text.includes(PASSWORD));
    assert.match(text, /smtp\.mailmask\.studio/);
    assert.match(text, /587/);
    assert.match(text, /revoca/i, "avisa que para otra hay que revocar y crear");
  });

  it("--json devuelve la contraseña", async () => {
    const { client } = fakeClient({ smtp: { create: () => created } });
    currentClient = client;
    const out = captureStdout();
    try {
      await create.run({ args: { domain: "dom_1", label: "app", json: true } });
    } finally {
      out.restore();
    }
    assert.equal(JSON.parse(out.text()).password, PASSWORD);
  });

  it("403 (dominio sin activar) → exit 2", async () => {
    const { client } = fakeClient({ smtp: { create: () => { throw new MailMaskError(403, "dominio no activado"); } } });
    currentClient = client;
    await assert.rejects(
      () => create.run({ args: { domain: "dom_1", label: "app" } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 2,
    );
  });
});

describe("smtp list", () => {
  it("no imprime contraseñas (texto y --json)", async () => {
    const { client } = fakeClient({ smtp: { list: () => [{ ...cred, password: PASSWORD }] } });
    currentClient = client;
    for (const json of [false, true]) {
      const out = captureStdout();
      try {
        await list.run({ args: { domain: "dom_1", json } });
      } finally {
        out.restore();
      }
      assert.doesNotMatch(out.text(), /password-de-prueba/);
      assert.match(out.text(), /cr_1/);
    }
  });
});

describe("smtp revoke", () => {
  it("sin --yes y sin TTY sale con 1 y no llama a la API", async () => {
    const { client, calls } = fakeClient({ smtp: { revoke: () => ({ ok: true }) } });
    currentClient = client;
    await assert.rejects(
      () => revoke.run({ args: { domain: "dom_1", id: "cr_1" } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 1,
    );
    assert.equal(calls.length, 0);
  });

  it("con --yes llama smtp.revoke", async () => {
    const { client, calls } = fakeClient({ smtp: { revoke: () => ({ ok: true }) } });
    currentClient = client;
    const out = captureStdout();
    try {
      await revoke.run({ args: { domain: "dom_1", id: "cr_1", yes: true } });
    } finally {
      out.restore();
    }
    assert.deepEqual(calls.find((c) => c.method === "smtp.revoke")!.args, ["dom_1", "cr_1"]);
  });

  it("404 → exit 4", async () => {
    const { client } = fakeClient({ smtp: { revoke: () => { throw new MailMaskError(404, "no existe"); } } });
    currentClient = client;
    await assert.rejects(
      () => revoke.run({ args: { domain: "dom_1", id: "cr_x", yes: true } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 4,
    );
  });
});
