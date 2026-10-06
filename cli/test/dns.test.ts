import assert from "node:assert/strict";
import { describe, it, mock } from "node:test";
import { MailMaskError } from "@easybits.cloud/mailmask";
import { fakeClient, trapExit, ExitSignal } from "./test-helpers.js";

let currentClient: ReturnType<typeof fakeClient>["client"];

trapExit();
// `requireClient` normalmente construye un `MailMask` real contra la red;
// aquí se sustituye por el cliente simulado que cada test deja en
// `currentClient` justo antes de correr el comando. Tiene que pasar ANTES
// del import dinámico de abajo: un `before()` corre demasiado tarde, cuando
// dns.ts ya resolvió "../client.js" contra la versión real.
mock.module("../src/client.js", {
  namedExports: {
    requireClient: async () => ({
      client: currentClient,
      auth: { apiKey: "mk_test", baseUrl: undefined, source: "env" as const },
    }),
    buildClient: () => currentClient,
  },
});

const { default: dns, refuseIfManaged } = await import("../src/commands/dns.js");
const { upsert, delete: del, preset, "create-zone": createZone } = dns.subCommands as Record<string, any>;

const managedRecord = { name: "@", type: "MX" as const, ttl: 300, values: ["mail.mailmask.studio"], managed: true, managedReason: "correo de MailMask", editable: false };

describe("dns upsert/delete: convención managed (falla cerrado)", () => {
  it("upsert sobre un registro managed:true sale con código ≠0 y no llama dns.upsert", async () => {
    const { client, calls } = fakeClient({ dns: { list: () => ({ zone: { status: "active" }, records: [managedRecord] }) } });
    currentClient = client;
    await assert.rejects(
      () => upsert.run({ args: { domain: "dom_1", name: "@", type: "MX", _: ["dom_1", "@", "MX", "otro.mail.com"] } }),
      ExitSignal,
    );
    assert.equal(calls.some((c) => c.method === "dns.upsert"), false);
  });

  it("delete sobre un registro managed:true sale con código ≠0 y no llama dns.delete", async () => {
    const { client, calls } = fakeClient({ dns: { list: () => ({ zone: { status: "active" }, records: [managedRecord] }) } });
    currentClient = client;
    await assert.rejects(
      () => del.run({ args: { domain: "dom_1", name: "@", type: "MX", yes: true } }),
      ExitSignal,
    );
    assert.equal(calls.some((c) => c.method === "dns.delete"), false);
  });

  it("si dns.list lanza, upsert falla CERRADO (no deja pasar la mutación)", async () => {
    const { client, calls } = fakeClient({ dns: { list: () => { throw new Error("red caída"); } } });
    currentClient = client;
    await assert.rejects(
      () => upsert.run({ args: { domain: "dom_1", name: "app", type: "A", _: ["dom_1", "app", "A", "1.2.3.4"] } }),
      ExitSignal,
    );
    assert.equal(calls.some((c) => c.method === "dns.upsert"), false);
  });

  it("si dns.list lanza, delete falla CERRADO (no deja pasar la mutación)", async () => {
    const { client, calls } = fakeClient({ dns: { list: () => { throw new Error("red caída"); } } });
    currentClient = client;
    await assert.rejects(
      () => del.run({ args: { domain: "dom_1", name: "app", type: "A", yes: true } }),
      ExitSignal,
    );
    assert.equal(calls.some((c) => c.method === "dns.delete"), false);
  });

  it("delete sin --yes y sin TTY sale con 1 y no llama al SDK (ni siquiera dns.list)", async () => {
    const { client, calls } = fakeClient({ dns: { list: () => ({ zone: { status: "active" }, records: [] }) } });
    currentClient = client;
    await assert.rejects(
      () => del.run({ args: { domain: "dom_1", name: "app", type: "A" } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 1,
    );
    assert.equal(calls.length, 0);
  });

  it("refuseIfManaged deja pasar un (nombre, tipo) que no es managed", async () => {
    const { client, calls } = fakeClient({ dns: { list: () => ({ zone: { status: "active" }, records: [] }) } });
    await refuseIfManaged(client, "dom_1", "app", "A");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].method, "dns.list");
  });
});

describe("dns upsert/delete/preset/create-zone: llamada al SDK y errores", () => {
  it("upsert (sin managed) llama dns.upsert con los argumentos esperados", async () => {
    const { client, calls } = fakeClient({
      dns: {
        list: () => ({ zone: { status: "active" }, records: [] }),
        upsert: () => ({ changeId: "c1", propagacion: "menos de un minuto" }),
      },
    });
    currentClient = client;
    await upsert.run({ args: { domain: "dom_1", name: "app", type: "A", ttl: "600", _: ["dom_1", "app", "A", "1.2.3.4"] } });
    const call = calls.find((c) => c.method === "dns.upsert");
    assert.ok(call, "debió llamar dns.upsert");
    assert.deepEqual(call!.args, ["dom_1", { name: "app", type: "A", values: ["1.2.3.4"], ttl: 600 }]);
  });

  it("upsert propaga el error del SDK como exit code de error (500 → transitorio, 5)", async () => {
    const { client } = fakeClient({
      dns: {
        list: () => ({ zone: { status: "active" }, records: [] }),
        upsert: () => { throw new MailMaskError(500, "falló Route 53"); },
      },
    });
    currentClient = client;
    await assert.rejects(
      () => upsert.run({ args: { domain: "dom_1", name: "app", type: "A", _: ["dom_1", "app", "A", "1.2.3.4"] } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 5,
    );
  });

  it("delete (sin managed) llama dns.delete con los argumentos esperados", async () => {
    const { client, calls } = fakeClient({
      dns: {
        list: () => ({ zone: { status: "active" }, records: [] }),
        delete: () => ({ ok: true, changeId: "c1" }),
      },
    });
    currentClient = client;
    await del.run({ args: { domain: "dom_1", name: "app", type: "A", yes: true } });
    const call = calls.find((c) => c.method === "dns.delete");
    assert.ok(call, "debió llamar dns.delete");
    assert.deepEqual(call!.args, ["dom_1", "app", "A"]);
  });

  it("delete propaga el error del SDK como exit code de error (404 → no encontrado, 4)", async () => {
    const { client } = fakeClient({
      dns: {
        list: () => ({ zone: { status: "active" }, records: [] }),
        delete: () => { throw new MailMaskError(404, "no existe"); },
      },
    });
    currentClient = client;
    await assert.rejects(
      () => del.run({ args: { domain: "dom_1", name: "app", type: "A", yes: true } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 4,
    );
  });

  it("preset llama dns.preset con los argumentos esperados", async () => {
    const { client, calls } = fakeClient({
      dns: { preset: () => ({ changeId: "c1", propagacion: "menos de un minuto" }) },
    });
    currentClient = client;
    await preset.run({ args: { domain: "dom_1", preset: "vercel", target: "proyecto.vercel.app", subdomain: undefined } });
    const call = calls.find((c) => c.method === "dns.preset");
    assert.deepEqual(call!.args, ["dom_1", "vercel", "proyecto.vercel.app", undefined]);
  });

  it("preset con un nombre desconocido sale con error SIN llamar al SDK", async () => {
    const { client, calls } = fakeClient({});
    currentClient = client;
    await assert.rejects(
      () => preset.run({ args: { domain: "dom_1", preset: "wix-no-existe" } }),
      ExitSignal,
    );
    assert.equal(calls.length, 0);
  });

  it("create-zone llama dns.createZone y propaga su error como exit code de error (409 → conflicto, 3)", async () => {
    const { client } = fakeClient({
      dns: { createZone: () => { throw new MailMaskError(409, "la zona ya existe"); } },
    });
    currentClient = client;
    await assert.rejects(
      () => createZone.run({ args: { domain: "dom_1" } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 3,
    );
  });
});
