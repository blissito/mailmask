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

const { default: registrations } = await import("../src/commands/registrations.js");
const { register, list, renewal, "cancel-renewal": cancelRenewal, "transfer-out": transferOut } = registrations.subCommands as Record<string, any>;

const reg = { id: "reg_1", domainName: "acme.com", kind: "register", status: "active", expiresAt: null, renewalStatus: "none", transferAuthCodeHint: "ab****" };

describe("registrations", () => {
  it("register imprime la liga una vez y llama sólo register", async () => {
    const { client, calls } = fakeClient({ registrations: { register: () => ({ initPoint: "https://mp/reg/1", registrationId: "reg_1" }) } });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await register.run({ args: { domain: "acme.com" } });
    } finally {
      out.restore();
    }
    assert.deepEqual(calls.map((c) => c.method), ["registrations.register"]);
    assert.equal(out.text().split("https://mp/reg/1").length - 1, 1);
  });

  for (const clave of ["domainName", "id"] as const) {
    it(`renewal resuelve por ${clave}, imprime la liga una vez y no hace más llamadas`, async () => {
      const { client, calls } = fakeClient({ registrations: { list: () => [reg], renewal: () => ({ init_point: "https://mp/ren/1", nextChargeAt: "2027-01-01" }) } });
      currentClient = client;
      const out = captureWrites(process.stdout);
      try {
        await renewal.run({ args: { registration: reg[clave], "payer-email": "p@x.com" } });
      } finally {
        out.restore();
      }
      assert.deepEqual(calls.map((c) => c.method), ["registrations.list", "registrations.renewal"]);
      assert.deepEqual(calls[1].args, ["reg_1", { payerEmail: "p@x.com" }]);
      assert.equal(out.text().split("https://mp/ren/1").length - 1, 1);
    });
  }

  it("list no imprime transferAuthCodeHint ni en texto ni en --json", async () => {
    const { client } = fakeClient({ registrations: { list: () => [reg] } });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await list.run({ args: {} });
      await list.run({ args: { json: true } });
    } finally {
      out.restore();
    }
    assert.doesNotMatch(out.text(), /transferAuthCodeHint|ab\*\*\*\*/);
    assert.match(out.text(), /acme\.com/);
  });

  for (const [nombre, cmd] of [["cancel-renewal", cancelRenewal], ["transfer-out", transferOut]] as const) {
    it(`${nombre} sin TTY y sin --yes sale con 1 sin ninguna llamada`, async () => {
      const { client, calls } = fakeClient({});
      currentClient = client;
      requireClientCalls = 0;
      await assert.rejects(() => cmd.run({ args: { registration: "acme.com" } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
      assert.equal(requireClientCalls, 0);
      assert.equal(calls.length, 0);
    });
  }

  it("transfer-out --yes imprime el aviso y nada más del resultado (ni código EPP)", async () => {
    const { client, calls } = fakeClient({ registrations: { list: () => [reg], transferOut: () => ({ ok: true, aviso: "El código llega por correo", authCode: "SECRETO-EPP" }) } });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await transferOut.run({ args: { registration: "acme.com", yes: true } });
      await transferOut.run({ args: { registration: "acme.com", yes: true, json: true } });
    } finally {
      out.restore();
    }
    assert.deepEqual(calls.filter((c) => c.method === "registrations.transferOut").map((c) => c.args), [["reg_1"], ["reg_1"]]);
    assert.match(out.text(), /llega por correo/);
    assert.doesNotMatch(out.text(), /SECRETO-EPP/);
  });

  it("cancel-renewal --yes resuelve por dominio y llama cancelRenewal", async () => {
    const { client, calls } = fakeClient({ registrations: { list: () => [reg], cancelRenewal: () => ({ ok: true, aviso: "Listo" }) } });
    currentClient = client;
    await cancelRenewal.run({ args: { registration: "acme.com", yes: true } });
    assert.deepEqual(calls.find((c) => c.method === "registrations.cancelRenewal")!.args, ["reg_1"]);
  });
});
