import assert from "node:assert/strict";
import { describe, it, mock } from "node:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fakeClient, trapExit, ExitSignal } from "./test-helpers.js";

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

const { default: domains } = await import("../src/commands/domains.js");
const { "dns-setup": dnsSetup, logo } = domains.subCommands as Record<string, any>;
const { set, remove } = logo.subCommands as Record<string, any>;

const dir = mkdtempSync(join(tmpdir(), "mm-logo-"));
const png = join(dir, "logo.png");
writeFileSync(png, Buffer.from([137, 80, 78, 71]));
const big = join(dir, "grande.jpg");
writeFileSync(big, Buffer.alloc(500 * 1024 + 1));
const gif = join(dir, "logo.gif");
writeFileSync(gif, "x");

describe("domains logo", () => {
  it("set arma el Blob con su MIME y llama setLogo", async () => {
    const { client, calls } = fakeClient({ domains: { setLogo: () => ({ ok: true, logoUrl: "https://x/logo.png" }) } });
    currentClient = client;
    await set.run({ args: { domain: "dom_1", file: png } });
    const call = calls.find((c) => c.method === "domains.setLogo")!;
    assert.equal(call.args[0], "dom_1");
    assert.equal((call.args[1] as Blob).type, "image/png");
    assert.equal(call.args[2], "logo.png");
  });

  for (const [nombre, file] of [["extensión inválida", gif], ["más de 500 KB", big], ["archivo inexistente", join(dir, "no.png")]] as const) {
    it(`set con ${nombre} sale con 1 sin pedir cliente`, async () => {
      const { client, calls } = fakeClient({});
      currentClient = client;
      requireClientCalls = 0;
      await assert.rejects(() => set.run({ args: { domain: "dom_1", file } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
      assert.equal(requireClientCalls, 0);
      assert.equal(calls.length, 0);
    });
  }

  it("remove --yes llama removeLogo", async () => {
    const { client, calls } = fakeClient({ domains: { removeLogo: () => ({ ok: true }) } });
    currentClient = client;
    await remove.run({ args: { domain: "dom_1", yes: true } });
    assert.deepEqual(calls.find((c) => c.method === "domains.removeLogo")!.args, ["dom_1"]);
  });

  it("remove sin TTY ni --yes sale con 1 sin llamar a la API (ni domains.list)", async () => {
    const { client, calls } = fakeClient({ domains: { removeLogo: () => ({ ok: true }) } });
    currentClient = client;
    const tty = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
    try {
      await assert.rejects(() => remove.run({ args: { domain: "acme.com" } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
    } finally {
      if (tty) Object.defineProperty(process.stdin, "isTTY", tty); else delete (process.stdin as any).isTTY;
    }
    assert.equal(calls.length, 0);
  });
});

describe("domains dns-setup", () => {
  it("pasa live al SDK e imprime tipo, nombre, valor, ok y el registrador", async () => {
    const out: string[] = [];
    mock.method(process.stdout, "write", ((s: string) => { out.push(String(s)); return true; }) as never);
    const { client, calls } = fakeClient({
      domains: {
        dnsSetup: () => ({
          domain: "acme.com", live: true,
          records: [{ id: "mx", type: "MX", name: "@", fqdn: "acme.com", value: "mx.mailmask.studio", level: "requerido", purpose: "", hints: [], ok: false }],
          registrarHint: { provider: "godaddy", label: "GoDaddy", note: "DNS → Agregar" },
        }),
      },
    });
    currentClient = client;
    await dnsSetup.run({ args: { domain: "dom_1", live: true } });
    mock.restoreAll();
    trapExit();
    assert.deepEqual(calls.find((c) => c.method === "domains.dnsSetup")!.args, ["dom_1", { live: true }]);
    const texto = out.join("");
    assert.match(texto, /MX\s+@\s+mx\.mailmask\.studio/);
    assert.match(texto, /falta/);
    assert.match(texto, /GoDaddy/);
  });
});
