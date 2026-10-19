import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it, mock, before, after } from "node:test";
import { fakeClient, trapExit, ExitSignal, captureWrites } from "./test-helpers.js";

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

const { default: domains } = await import("../src/commands/domains.js");
const { default: registrations } = await import("../src/commands/registrations.js");
const easybits = (domains.subCommands as Record<string, any>).easybits.subCommands as Record<string, any>;
const { status, publish, unpublish } = easybits;
const { lock } = registrations.subCommands as Record<string, any>;

const reg = { id: "reg_1", domainName: "acme.com", kind: "register", status: "active", expiresAt: null, renewalStatus: "none" };
const published = {
  dryRun: false,
  url: "https://acme.com",
  site: { id: "web_1", name: "Sitio", slug: "sitio", status: "live", url: "https://acme.com" },
  records: [{ name: "acme.com", type: "A", ttl: 300, values: ["1.2.3.4"] }],
  verified: true,
};

// Sin TTY, como en CI: confirmOrExit debe negarse sin --yes.
let originalIsTTY: unknown;
before(() => { originalIsTTY = process.stdin.isTTY; Object.defineProperty(process.stdin, "isTTY", { value: undefined, configurable: true }); });
after(() => { Object.defineProperty(process.stdin, "isTTY", { value: originalIsTTY, configurable: true }); });

describe("domains easybits: el subgrupo expone status, publish y unpublish", () => {
  it("existe con sus tres subcomandos", () => {
    assert.deepEqual(Object.keys(easybits).sort(), ["publish", "status", "unpublish"]);
  });

  it("status --json devuelve el resultado del SDK tal cual", async () => {
    const payload = { linked: true, sites: [], published: false, publication: null };
    const { client, calls } = fakeClient({ domains: { list: () => [{ id: "dom_1", domain: "acme.com" }], easyBitsSiteStatus: () => payload } });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await status.run({ args: { domain: "acme.com", json: true } });
    } finally {
      out.restore();
    }
    assert.deepEqual(calls.map((c) => c.method), ["domains.list", "domains.easyBitsSiteStatus"]);
    assert.deepEqual(JSON.parse(out.text()), payload);
  });

  it("publish llama publishEasyBitsSite con dryRun:false y placement", async () => {
    const { client, calls } = fakeClient({ domains: { list: () => [{ id: "dom_1", domain: "acme.com" }], publishEasyBitsSite: () => published } });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await publish.run({ args: { domain: "acme.com", site: "web_1", placement: "apex" } });
    } finally {
      out.restore();
    }
    const call = calls.find((c) => c.method === "domains.publishEasyBitsSite");
    assert.deepEqual(call?.args, ["dom_1", { websiteId: "web_1", placement: "apex", dryRun: false }]);
    assert.match(out.text(), /publicado en https:\/\/acme\.com/);
  });

  it("publish --dry-run pide sólo la vista previa: dryRun:true y ninguna llamada con dryRun:false", async () => {
    const preview = { ...published, dryRun: true };
    const { client, calls } = fakeClient({ domains: { list: () => [{ id: "dom_1", domain: "acme.com" }], publishEasyBitsSite: () => preview } });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await publish.run({ args: { domain: "acme.com", site: "web_1", placement: "apex", "dry-run": true } });
    } finally {
      out.restore();
    }
    const mutations = calls.filter((c) => c.method === "domains.publishEasyBitsSite");
    assert.equal(mutations.length, 1);
    assert.equal((mutations[0].args[1] as { dryRun: boolean }).dryRun, true);
    assert.match(out.text(), /no se publicó nada/);
    assert.match(out.text(), /acme\.com  A  1\.2\.3\.4/);
  });

  it("publish con --placement inválido sale con 1 antes de tocar el SDK", async () => {
    const { client, calls } = fakeClient({});
    currentClient = client;
    const out = captureWrites(process.stderr);
    try {
      await assert.rejects(() => publish.run({ args: { domain: "acme.com", site: "web_1", placement: "todo" } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
    } finally {
      out.restore();
    }
    assert.deepEqual(calls, []);
  });

  it("publish con --json y error del SDK devuelve el error como JSON con exit 1 (failFromError)", async () => {
    const { client } = fakeClient({ domains: { list: () => [{ id: "dom_1", domain: "acme.com" }], publishEasyBitsSite: () => { throw new Error("boom"); } } });
    currentClient = client;
    const err = captureWrites(process.stderr);
    try {
      await assert.rejects(() => publish.run({ args: { domain: "acme.com", site: "web_1", placement: "apex", json: true } }), ExitSignal);
    } finally {
      err.restore();
    }
    assert.match(err.text(), /boom/);
  });

  it("unpublish sin TTY y sin --yes sale con 1 sin llamar al SDK (ni a domains.list)", async () => {
    const { client, calls } = fakeClient({});
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await assert.rejects(() => unpublish.run({ args: { domain: "acme.com" } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
    } finally {
      out.restore();
    }
    assert.deepEqual(calls, []);
  });

  it("unpublish con --yes llama unpublishEasyBitsSite y reporta lo restaurado y lo omitido", async () => {
    const result = {
      ok: true,
      restored: [{ name: "acme.com", type: "A", to: null }],
      skipped: [{ name: "www.acme.com", type: "CNAME", current: null }],
      easybits: { apexCleared: true, domainDeleted: true },
    };
    const { client, calls } = fakeClient({ domains: { list: () => [{ id: "dom_1", domain: "acme.com" }], unpublishEasyBitsSite: () => result } });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await unpublish.run({ args: { domain: "acme.com", yes: true } });
    } finally {
      out.restore();
    }
    assert.ok(calls.some((c) => c.method === "domains.unpublishEasyBitsSite" && c.args[0] === "dom_1"));
    assert.match(out.text(), /acme\.com A se borró/);
    assert.match(out.text(), /www\.acme\.com CNAME cambiado después de publicar/);
  });
});

describe("registrations lock: pone el candado, nunca lo quita", () => {
  it("sin TTY y sin --yes sale con 1 sin llamar al SDK", async () => {
    const { client, calls } = fakeClient({ registrations: { list: () => [reg], lock: () => ({ ok: true }) } });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await assert.rejects(() => lock.run({ args: { registration: "acme.com" } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
    } finally {
      out.restore();
    }
    assert.deepEqual(calls, []);
  });

  it("con --yes resuelve el registro y llama lock(id) una vez", async () => {
    const { client, calls } = fakeClient({ registrations: { list: () => [reg], lock: () => ({ ok: true, transferLock: true, transferUnlockedUntil: null }) } });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await lock.run({ args: { registration: "acme.com", yes: true } });
    } finally {
      out.restore();
    }
    assert.deepEqual(calls.map((c) => c.method), ["registrations.list", "registrations.lock"]);
    assert.deepEqual(calls[1].args, ["reg_1"]);
  });

  it("la ayuda de registrations no ofrece ningún comando para quitar el candado", () => {
    const names = Object.keys(registrations.subCommands as Record<string, unknown>);
    assert.ok(names.includes("lock"));
    assert.ok(!names.some((n) => /unlock|unlock-transfer|quitar/i.test(n)));
  });

  it("el módulo no llama al método de quitar candado del SDK", () => {
    const src = readFileSync(new URL("../src/commands/registrations.ts", import.meta.url), "utf8");
    assert.doesNotMatch(src, /unlock/i);
  });
});
