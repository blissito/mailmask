import assert from "node:assert/strict";
import { describe, it, mock } from "node:test";
import { MailMaskError } from "@easybits.cloud/mailmask";
import { fakeClient, trapExit, ExitSignal, captureWrites } from "./test-helpers.js";

let currentClient: ReturnType<typeof fakeClient>["client"];

trapExit();
mock.module("../src/client.js", {
  namedExports: {
    requireClient: async () => ({ client: currentClient, auth: { apiKey: "mk_test", baseUrl: undefined, source: "env" as const } }),
    buildClient: () => currentClient,
  },
});

const { default: dns } = await import("../src/commands/dns.js");
const { import: importCmd } = dns.subCommands as Record<string, any>;

const result = {
  found: [{ name: "acme.com", type: "A", ttl: 300, values: ["1.2.3.4"] }],
  nameservers: ["ns-1.awsdns.com"],
  warning: "Revisa antes de cambiar los nameservers.",
};

function capture() {
  const cap = captureWrites(process.stdout);
  return () => { const texto = cap.text(); cap.restore(); return texto; };
}

describe("dns import", () => {
  it("imprime registros encontrados, nameservers y aviso, y sólo llama dns.import", async () => {
    const { client, calls } = fakeClient({ dns: { import: () => result } });
    currentClient = client;
    const done = capture();
    await importCmd.run({ args: { domain: "dom_1" } });
    const texto = done();
    assert.deepEqual(calls.map((c) => c.method), ["domains.list", "dns.import"]);
    assert.match(texto, /1 registro/);
    assert.match(texto, /A\s+acme\.com\s+1\.2\.3\.4/);
    assert.match(texto, /ns-1\.awsdns\.com/);
    assert.match(texto, /Revisa antes de cambiar/);
  });

  it("--json imprime el resultado crudo", async () => {
    const { client } = fakeClient({ dns: { import: () => result } });
    currentClient = client;
    const done = capture();
    await importCmd.run({ args: { domain: "dom_1", json: true } });
    assert.deepEqual(JSON.parse(done()), result);
  });

  it("el rate limit (429) sale con exit 5", async () => {
    const { client } = fakeClient({ dns: { import: () => { throw new MailMaskError(429, "Demasiados intentos"); } } });
    currentClient = client;
    await assert.rejects(() => importCmd.run({ args: { domain: "dom_1" } }), (e: unknown) => e instanceof ExitSignal && e.code === 5);
  });
});
