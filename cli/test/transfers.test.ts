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

const { default: transfers } = await import("../src/commands/transfers.js");
const { check, dns, "set-dns": setDns, "approve-dns": approveDns, "resend-email": resendEmail } = transfers.subCommands as Record<string, any>;

const reg = { id: "reg_1", domainName: "acme.com" };
const dir = mkdtempSync(join(tmpdir(), "mm-transfers-"));
const ok = join(dir, "ok.json");
writeFileSync(ok, JSON.stringify([{ name: "acme.com", type: "A", ttl: 300, values: ["1.2.3.4"] }]));
const malo = join(dir, "malo.json");
writeFileSync(malo, JSON.stringify([{ name: "acme.com", type: "A", values: [] }]));
const noArreglo = join(dir, "obj.json");
writeFileSync(noArreglo, "{}");
const roto = join(dir, "roto.json");
writeFileSync(roto, "[");

describe("transfers", () => {
  it("check usa el nombre del dominio, sin resolver registros", async () => {
    const { client, calls } = fakeClient({ transfers: { check: () => ({ domain: "acme.com", price: 29900, currency: "MXN", requisitos: [], dns: { found: [] } }) } });
    currentClient = client;
    await check.run({ args: { domain: "acme.com" } });
    assert.deepEqual(calls.map((c) => c.method), ["transfers.check"]);
    assert.deepEqual(calls[0].args, ["acme.com"]);
  });

  for (const clave of ["domainName", "id"] as const) {
    it(`dns resuelve por ${clave}`, async () => {
      const { client, calls } = fakeClient({ registrations: { list: () => [reg] }, transfers: { dns: () => ({ records: [], status: "pending", takenAt: null }) } });
      currentClient = client;
      await dns.run({ args: { registration: reg[clave] } });
      assert.deepEqual(calls.find((c) => c.method === "transfers.dns")!.args, ["reg_1"]);
    });
  }

  it("resend-email resuelve y llama sin pedir confirmación", async () => {
    const { client, calls } = fakeClient({ registrations: { list: () => [reg] }, transfers: { resendEmail: () => ({ ok: true }) } });
    currentClient = client;
    await resendEmail.run({ args: { registration: "acme.com" } });
    assert.deepEqual(calls.find((c) => c.method === "transfers.resendEmail")!.args, ["reg_1"]);
  });

  for (const [nombre, cmd, extra] of [["set-dns", setDns, { file: ok }], ["approve-dns", approveDns, {}]] as const) {
    it(`${nombre} sin TTY y sin --yes sale con 1 sin ninguna llamada`, async () => {
      const { client, calls } = fakeClient({});
      currentClient = client;
      requireClientCalls = 0;
      await assert.rejects(() => cmd.run({ args: { registration: "acme.com", ...extra } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
      assert.equal(requireClientCalls, 0);
      assert.equal(calls.length, 0);
    });
  }

  it("set-dns --yes manda el arreglo del archivo tal cual", async () => {
    const { client, calls } = fakeClient({ registrations: { list: () => [reg] }, transfers: { setDns: () => ({ records: [{}] }) } });
    currentClient = client;
    await setDns.run({ args: { registration: "acme.com", file: ok, yes: true } });
    assert.deepEqual(calls.find((c) => c.method === "transfers.setDns")!.args, ["reg_1", [{ name: "acme.com", type: "A", ttl: 300, values: ["1.2.3.4"] }]]);
  });

  for (const [nombre, file] of [["un registro sin values", malo], ["un JSON que no es arreglo", noArreglo], ["un JSON roto", roto], ["un archivo inexistente", join(dir, "no.json")]] as const) {
    it(`set-dns con ${nombre} sale con 1 antes de tocar la red, incluso con --yes`, async () => {
      const { client, calls } = fakeClient({});
      currentClient = client;
      requireClientCalls = 0;
      await assert.rejects(() => setDns.run({ args: { registration: "acme.com", file, yes: true } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
      assert.equal(requireClientCalls, 0);
      assert.equal(calls.length, 0);
    });
  }

  it("approve-dns --yes resuelve y aprueba", async () => {
    const { client, calls } = fakeClient({ registrations: { list: () => [reg] }, transfers: { approveDns: () => ({ ok: true }) } });
    currentClient = client;
    await approveDns.run({ args: { registration: "reg_1", yes: true } });
    assert.deepEqual(calls.find((c) => c.method === "transfers.approveDns")!.args, ["reg_1"]);
  });
});
