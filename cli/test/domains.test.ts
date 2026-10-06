import assert from "node:assert/strict";
import { describe, it, mock } from "node:test";
import { MailMaskError } from "@easybits.cloud/mailmask";
import { fakeClient, trapExit, ExitSignal } from "./test-helpers.js";

let currentClient: ReturnType<typeof fakeClient>["client"];

trapExit();
// Mismo motivo que en dns.test.ts: el mock tiene que estar en pie ANTES del
// import dinámico de domains.ts, no dentro de un `before()`.
mock.module("../src/client.js", {
  namedExports: {
    requireClient: async () => ({
      client: currentClient,
      auth: { apiKey: "mk_test", baseUrl: undefined, source: "env" as const },
    }),
    buildClient: () => currentClient,
  },
});

const { default: domains } = await import("../src/commands/domains.js");
const { create, delete: del } = domains.subCommands as Record<string, any>;

const createdDomain = {
  domain: { id: "dom_1", domain: "acme.com" },
  requiereActivacion: false,
  dnsRecords: {
    mx: { name: "acme.com", value: "mx.mailmask.studio" },
    verification: { name: "_mailmask.acme.com", value: "tok-123" },
    spf: { name: "acme.com", value: "v=spf1 include:mailmask.studio ~all" },
    dkim: [{ name: "dkim._domainkey.acme.com", value: "v=DKIM1; p=..." }],
  },
};

describe("domains create: llamada al SDK y errores", () => {
  it("llama domains.create con el dominio pedido", async () => {
    const { client, calls } = fakeClient({ domains: { create: () => createdDomain } });
    currentClient = client;
    await create.run({ args: { domain: "acme.com" } });
    const call = calls.find((c) => c.method === "domains.create");
    assert.deepEqual(call!.args, ["acme.com"]);
  });

  it("con --preset, aplica dns.preset tras crear con los argumentos esperados", async () => {
    const { client, calls } = fakeClient({
      domains: { create: () => createdDomain },
      dns: { preset: () => ({ changeId: "c1", propagacion: "menos de un minuto" }) },
    });
    currentClient = client;
    await create.run({ args: { domain: "acme.com", preset: "vercel", target: "proyecto.vercel.app" } });
    const call = calls.find((c) => c.method === "dns.preset");
    assert.deepEqual(call!.args, ["dom_1", "vercel", "proyecto.vercel.app", undefined]);
  });

  it("con un --preset desconocido, sale con error SIN llamar al SDK", async () => {
    const { client, calls } = fakeClient({});
    currentClient = client;
    await assert.rejects(
      () => create.run({ args: { domain: "acme.com", preset: "wix-no-existe" } }),
      ExitSignal,
    );
    assert.equal(calls.length, 0);
  });

  it("si domains.create falla, sale con el exit code de error (409 → conflicto, 3)", async () => {
    const { client } = fakeClient({ domains: { create: () => { throw new MailMaskError(409, "el dominio ya existe"); } } });
    currentClient = client;
    await assert.rejects(
      () => create.run({ args: { domain: "acme.com" } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 3,
    );
  });
});

describe("domains delete: llamada al SDK y errores", () => {
  it("llama domains.delete con el id resuelto", async () => {
    const { client, calls } = fakeClient({ domains: { delete: () => ({ ok: true }) } });
    currentClient = client;
    await del.run({ args: { domain: "dom_1", yes: true } });
    const call = calls.find((c) => c.method === "domains.delete");
    assert.deepEqual(call!.args, ["dom_1"]);
  });

  it("si domains.delete falla, sale con el exit code de error (401 → auth, 2)", async () => {
    const { client } = fakeClient({ domains: { delete: () => { throw new MailMaskError(401, "llave inválida"); } } });
    currentClient = client;
    await assert.rejects(
      () => del.run({ args: { domain: "dom_1", yes: true } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 2,
    );
  });

  it("sin --yes y sin TTY sale con 1 y no llama al SDK (calls vacío)", async () => {
    const { client, calls } = fakeClient({ domains: { delete: () => ({ ok: true }) } });
    currentClient = client;
    await assert.rejects(
      () => del.run({ args: { domain: "dom_1" } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 1,
    );
    assert.equal(calls.length, 0);
  });
});
