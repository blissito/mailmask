import assert from "node:assert/strict";
import { describe, it, mock } from "node:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MailMaskError } from "@easybits.cloud/mailmask";
import { fakeClient, trapExit, ExitSignal, captureWrites } from "./test-helpers.js";

let currentClient: ReturnType<typeof fakeClient>["client"];

trapExit();
// Mismo motivo que en dns.test.ts/domains.test.ts: el mock tiene que estar en
// pie ANTES del import dinámico de abajo, no dentro de un `before()`.
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
const { list, create, update, delete: del, mailbox, "apple-profile": appleProfile, export: exportMailbox } = aliases.subCommands as Record<string, any>;
const { create: mailboxCreate, delete: mailboxDelete, "reset-password": resetPassword } = mailbox.subCommands as Record<string, any>;

// Mismo patrón que `captureStderr` en whoami.test.ts, pero sobre stdout: el
// aviso de "cómo copiar la contraseña completa" vive ahí, no en un valor de
// retorno, así que hay que leerlo de lo que el comando imprimió de verdad.
function captureStdout() {
  return captureWrites(process.stdout);
}

describe("aliases list: llamada al SDK", () => {
  it("llama aliases.list con el id resuelto", async () => {
    const { client, calls } = fakeClient({ aliases: { list: () => [] } });
    currentClient = client;
    await list.run({ args: { domain: "dom_1" } });
    const call = calls.find((c) => c.method === "aliases.list");
    assert.deepEqual(call!.args, ["dom_1"]);
  });
});

describe("aliases create: llamada al SDK y errores", () => {
  it("llama aliases.create con alias y destinos", async () => {
    const { client, calls } = fakeClient({
      aliases: { create: () => ({ alias: "hola", domainId: "dom_1", destinations: ["yo@gmail.com"], enabled: true, forwardCount: 0, createdAt: "now" }) },
    });
    currentClient = client;
    await create.run({ args: { domain: "dom_1", alias: "hola", _: ["dom_1", "hola", "yo@gmail.com"] } });
    const call = calls.find((c) => c.method === "aliases.create");
    assert.deepEqual(call!.args, ["dom_1", { alias: "hola", destinations: ["yo@gmail.com"] }]);
  });

  it("--mailbox sin destinos se permite: llama aliases.create con destinations vacío y mailbox:true", async () => {
    const { client, calls } = fakeClient({
      aliases: {
        create: () => ({
          alias: "hola", domainId: "dom_1", destinations: [], enabled: true, forwardCount: 0, createdAt: "now",
          buzon: { email: "hola@acme.com", password: "s3cr3t-password-123", quotaBytes: 0, imap: { host: "imap", port: 993, security: "ssl" }, smtp: { host: "smtp", port: 587, security: "starttls" } },
        }),
      },
    });
    currentClient = client;
    await create.run({ args: { domain: "dom_1", alias: "hola", mailbox: true, _: ["dom_1", "hola"] } });
    const call = calls.find((c) => c.method === "aliases.create");
    assert.deepEqual(call!.args, ["dom_1", { alias: "hola", destinations: [], mailbox: true }]);
  });

  it("--mailbox en texto: nunca imprime la contraseña completa y manda a reset-password --json para copiarla", async () => {
    const { client } = fakeClient({
      aliases: {
        create: () => ({
          alias: "hola", domainId: "dom_1", destinations: [], enabled: true, forwardCount: 0, createdAt: "now",
          buzon: { email: "hola@acme.com", password: "s3cr3t-password-123", quotaBytes: 0, imap: { host: "imap", port: 993, security: "ssl" }, smtp: { host: "smtp", port: 587, security: "starttls" } },
        }),
      },
    });
    currentClient = client;
    const out = captureStdout();
    try {
      await create.run({ args: { domain: "dom_1", alias: "hola", mailbox: true, _: ["dom_1", "hola"] } });
    } finally {
      out.restore();
    }
    const text = out.text();
    assert.doesNotMatch(text, /s3cr3t-password-123/, "la contraseña completa nunca debe salir en modo texto");
    assert.match(text, /mailbox reset-password dom_1 hola --yes --json/, "debe apuntar a reset-password, no a repetir create (409)");
  });

  it("sin destinos y sin --mailbox sale con error SIN llamar al SDK", async () => {
    const { client, calls } = fakeClient({});
    currentClient = client;
    await assert.rejects(
      () => create.run({ args: { domain: "dom_1", alias: "hola", _: ["dom_1", "hola"] } }),
      ExitSignal,
    );
    assert.equal(calls.length, 0);
  });

  it("si aliases.create falla, sale con el exit code de error (409 → conflicto, 3)", async () => {
    const { client } = fakeClient({ aliases: { create: () => { throw new MailMaskError(409, "ya existe"); } } });
    currentClient = client;
    await assert.rejects(
      () => create.run({ args: { domain: "dom_1", alias: "hola", _: ["dom_1", "hola", "yo@gmail.com"] } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 3,
    );
  });
});

describe("aliases update: llamada al SDK y errores", () => {
  it("--enable con destinos nuevos llama aliases.update con ambos campos", async () => {
    const { client, calls } = fakeClient({
      aliases: { update: () => ({ alias: "hola", domainId: "dom_1", destinations: ["otro@gmail.com"], enabled: true, forwardCount: 0, createdAt: "now" }) },
    });
    currentClient = client;
    await update.run({ args: { domain: "dom_1", alias: "hola", enable: true, _: ["dom_1", "hola", "otro@gmail.com"] } });
    const call = calls.find((c) => c.method === "aliases.update");
    assert.deepEqual(call!.args, ["dom_1", "hola", { enabled: true, destinations: ["otro@gmail.com"] }]);
  });

  it("sin --enable/--disable ni destinos sale con error SIN llamar al SDK", async () => {
    const { client, calls } = fakeClient({});
    currentClient = client;
    await assert.rejects(
      () => update.run({ args: { domain: "dom_1", alias: "hola", _: ["dom_1", "hola"] } }),
      ExitSignal,
    );
    assert.equal(calls.length, 0);
  });

  it("--enable y --disable juntos sale con error SIN llamar al SDK", async () => {
    const { client, calls } = fakeClient({});
    currentClient = client;
    await assert.rejects(
      () => update.run({ args: { domain: "dom_1", alias: "hola", enable: true, disable: true, _: ["dom_1", "hola"] } }),
      ExitSignal,
    );
    assert.equal(calls.length, 0);
  });
});

describe("aliases delete: contrato de confirmación", () => {
  it("con --yes llama aliases.delete con el id resuelto", async () => {
    const { client, calls } = fakeClient({ aliases: { delete: () => ({ ok: true }) } });
    currentClient = client;
    await del.run({ args: { domain: "dom_1", alias: "hola", yes: true } });
    const call = calls.find((c) => c.method === "aliases.delete");
    assert.deepEqual(call!.args, ["dom_1", "hola"]);
  });

  it("sin --yes y sin TTY sale con 1 y no llama al SDK", async () => {
    const { client, calls } = fakeClient({ aliases: { delete: () => ({ ok: true }) } });
    currentClient = client;
    await assert.rejects(
      () => del.run({ args: { domain: "dom_1", alias: "hola" } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 1,
    );
    assert.equal(calls.length, 0);
  });
});

describe("aliases mailbox create/delete/reset-password", () => {
  it("mailbox create llama aliases.createMailbox con el id resuelto", async () => {
    const { client, calls } = fakeClient({
      aliases: { createMailbox: () => ({ email: "hola@acme.com", password: "pw", quotaBytes: 0, imap: { host: "imap", port: 993, security: "ssl" }, smtp: { host: "smtp", port: 587, security: "starttls" } }) },
    });
    currentClient = client;
    await mailboxCreate.run({ args: { domain: "dom_1", alias: "hola" } });
    const call = calls.find((c) => c.method === "aliases.createMailbox");
    assert.deepEqual(call!.args, ["dom_1", "hola"]);
  });

  it("mailbox create en texto: nunca imprime la contraseña completa y manda a reset-password --json para copiarla", async () => {
    const { client } = fakeClient({
      aliases: { createMailbox: () => ({ email: "hola@acme.com", password: "s3cr3t-password-123", quotaBytes: 0, imap: { host: "imap", port: 993, security: "ssl" }, smtp: { host: "smtp", port: 587, security: "starttls" } }) },
    });
    currentClient = client;
    const out = captureStdout();
    try {
      await mailboxCreate.run({ args: { domain: "dom_1", alias: "hola" } });
    } finally {
      out.restore();
    }
    const text = out.text();
    assert.doesNotMatch(text, /s3cr3t-password-123/, "la contraseña completa nunca debe salir en modo texto");
    assert.match(text, /mailbox reset-password dom_1 hola --yes --json/, "debe apuntar a reset-password, no a repetir create (409)");
  });

  it("mailbox delete sin --yes y sin TTY sale con 1 y no llama al SDK", async () => {
    const { client, calls } = fakeClient({ aliases: { deleteMailbox: () => ({ ok: true }) } });
    currentClient = client;
    await assert.rejects(
      () => mailboxDelete.run({ args: { domain: "dom_1", alias: "hola" } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 1,
    );
    assert.equal(calls.length, 0);
  });

  it("mailbox delete con --yes llama aliases.deleteMailbox con el id resuelto", async () => {
    const { client, calls } = fakeClient({ aliases: { deleteMailbox: () => ({ ok: true }) } });
    currentClient = client;
    await mailboxDelete.run({ args: { domain: "dom_1", alias: "hola", yes: true } });
    const call = calls.find((c) => c.method === "aliases.deleteMailbox");
    assert.deepEqual(call!.args, ["dom_1", "hola"]);
  });

  it("reset-password sin --yes y sin TTY sale con 1 y no llama al SDK", async () => {
    const { client, calls } = fakeClient({ aliases: { resetMailboxPassword: () => ({ password: "pw" }) } });
    currentClient = client;
    await assert.rejects(
      () => resetPassword.run({ args: { domain: "dom_1", alias: "hola" } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 1,
    );
    assert.equal(calls.length, 0);
  });

  it("reset-password con --yes llama aliases.resetMailboxPassword con el id resuelto", async () => {
    const { client, calls } = fakeClient({ aliases: { resetMailboxPassword: () => ({ password: "pw" }) } });
    currentClient = client;
    await resetPassword.run({ args: { domain: "dom_1", alias: "hola", yes: true } });
    const call = calls.find((c) => c.method === "aliases.resetMailboxPassword");
    assert.deepEqual(call!.args, ["dom_1", "hola"]);
  });
});

describe("aliases apple-profile / export: escriben archivo", () => {
  it("apple-profile -o escribe el .mobileconfig devuelto por el SDK", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mailmask-cli-"));
    const output = join(dir, "perfil.mobileconfig");
    const { client, calls } = fakeClient({ aliases: { appleProfile: () => "<plist>contenido</plist>" } });
    currentClient = client;
    try {
      await appleProfile.run({ args: { domain: "dom_1", alias: "hola", output } });
      const call = calls.find((c) => c.method === "aliases.appleProfile");
      assert.deepEqual(call!.args, ["dom_1", "hola"]);
      assert.equal(await readFile(output, "utf8"), "<plist>contenido</plist>");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("apple-profile sin -o sale con error SIN llamar al SDK", async () => {
    const { client, calls } = fakeClient({});
    currentClient = client;
    await assert.rejects(
      () => appleProfile.run({ args: { domain: "dom_1", alias: "hola" } }),
      ExitSignal,
    );
    assert.equal(calls.length, 0);
  });

  it("export -o escribe el mbox devuelto por el SDK", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mailmask-cli-"));
    const output = join(dir, "buzon.mbox");
    const mboxContent = "From - Mon Jan  1 00:00:00 2024\nSubject: hola\n\n";
    const { client, calls } = fakeClient({
      aliases: { exportMbox: () => ({ arrayBuffer: async () => new TextEncoder().encode(mboxContent).buffer }) },
    });
    currentClient = client;
    try {
      await exportMailbox.run({ args: { domain: "dom_1", alias: "hola", output } });
      const call = calls.find((c) => c.method === "aliases.exportMbox");
      assert.deepEqual(call!.args, ["dom_1", "hola"]);
      assert.equal(await readFile(output, "utf8"), mboxContent);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
