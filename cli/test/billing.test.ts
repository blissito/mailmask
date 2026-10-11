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

const { default: billing } = await import("../src/commands/billing.js");
const { checkout, orders, "cancel-addon": cancelAddon } = billing.subCommands as Record<string, any>;

const link = { init_point: "https://mp/checkout/123", addonId: "ad_1" };

describe("billing", () => {
  it("checkout imprime la liga una vez y no hace más llamadas que resolver el dominio y pedirla", async () => {
    const { client, calls } = fakeClient({ domains: { list: () => [{ id: "dom_1", domain: "acme.com" }] }, billing: { checkout: () => link } });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await checkout.run({ args: { domain: "acme.com", kind: "storage50", period: "annual", "payer-email": "p@x.com" } });
    } finally {
      out.restore();
    }
    assert.deepEqual(calls.map((c) => c.method), ["domains.list", "billing.checkout"]);
    assert.deepEqual(calls[1].args, ["dom_1", "storage50", { payerEmail: "p@x.com", period: "annual" }]);
    assert.equal(out.text().split("https://mp/checkout/123").length - 1, 1);
  });

  for (const [flag, valor] of [["kind", "gratis"], ["period", "semanal"]] as const) {
    it(`checkout con --${flag} inválido sale con 1 antes de tocar la red`, async () => {
      const { client, calls } = fakeClient({});
      currentClient = client;
      requireClientCalls = 0;
      await assert.rejects(() => checkout.run({ args: { domain: "dom_1", [flag]: valor } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
      assert.equal(requireClientCalls, 0);
      assert.equal(calls.length, 0);
    });
  }

  it("orders pasa limit como número y before", async () => {
    const { client, calls } = fakeClient({ billing: { orders: () => ({ orders: [], nextCursor: null, invoiceNote: "" }) } });
    currentClient = client;
    await orders.run({ args: { limit: "5", before: "cur" } });
    assert.deepEqual(calls[0].args, [{ limit: 5, before: "cur" }]);
  });

  it("orders con --limit no entero sale con 1", async () => {
    const { client, calls } = fakeClient({});
    currentClient = client;
    await assert.rejects(() => orders.run({ args: { limit: "abc" } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
    assert.equal(calls.length, 0);
  });

  it("cancel-addon sin TTY y sin --yes sale con 1 sin ninguna llamada", async () => {
    const { client, calls } = fakeClient({});
    currentClient = client;
    requireClientCalls = 0;
    await assert.rejects(() => cancelAddon.run({ args: { addon: "ad_1" } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
    assert.equal(requireClientCalls, 0);
    assert.equal(calls.length, 0);
  });

  it("cancel-addon --yes llama billing.cancelAddon", async () => {
    const { client, calls } = fakeClient({ billing: { cancelAddon: () => ({ ok: true, activeUntil: null }) } });
    currentClient = client;
    await cancelAddon.run({ args: { addon: "ad_1", yes: true } });
    assert.deepEqual(calls.map((c) => c.method), ["billing.cancelAddon"]);
  });
});
