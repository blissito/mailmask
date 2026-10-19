import assert from "node:assert/strict";
import { describe, it, mock } from "node:test";
import { fakeClient, trapExit, ExitSignal, captureWrites } from "./test-helpers.js";

let currentClient: ReturnType<typeof fakeClient>["client"];

trapExit();
// Mismo patrón que dns.test.ts: el cliente simulado se inyecta antes del import dinámico.
mock.module("../src/client.js", {
  namedExports: {
    requireClient: async () => ({
      client: currentClient,
      auth: { apiKey: "mk_test", baseUrl: undefined, source: "env" as const },
    }),
    buildClient: () => currentClient,
  },
});

const { default: dns } = await import("../src/commands/dns.js");
const { preset, website } = dns.subCommands as Record<string, any>;

const sitio = {
  domain: "acme.com",
  editable: true,
  hosts: [
    {
      name: "acme.com",
      label: "@",
      records: [{ type: "A" as const, values: ["76.76.21.21"] }],
      platform: { id: "vercel", label: "Vercel" },
      issues: [],
      https: { ok: true, status: 200 },
    },
    {
      name: "www.acme.com",
      label: "www",
      records: [{ type: "CNAME" as const, values: ["cname.vercel-dns.com"] }],
      platform: null,
      issues: ["el CNAME apunta a un destino que no responde"],
      https: { ok: false, status: 404 },
    },
  ],
};

const vistaPrevia = {
  dryRun: true as const,
  records: [{ name: "@", type: "A" as const, ttl: 300, values: ["76.76.21.21"] }],
  current: [{ name: "@", type: "A" as const, ttl: 300, values: ["1.2.3.4"] }],
};

describe("dns website: estado del sitio de un dominio", () => {
  it("llama dns.website con el id del dominio y no toca nada más", async () => {
    const { client, calls } = fakeClient({
      domains: { list: () => [{ id: "dom_1", domain: "acme.com" }] },
      dns: { website: () => sitio },
    });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await website.run({ args: { domain: "acme.com" } });
    } finally {
      out.restore();
    }
    const call = calls.find((c) => c.method === "dns.website");
    assert.ok(call, "debió llamar dns.website");
    assert.deepEqual(call!.args, ["dom_1"]);
    assert.equal(calls.some((c) => c.method === "dns.upsert" || c.method === "dns.delete"), false);
  });

  it("en texto muestra cada host con su plataforma, sus registros y sus problemas", async () => {
    const { client } = fakeClient({ domains: { list: () => [{ id: "dom_1", domain: "acme.com" }] }, dns: { website: () => sitio } });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await website.run({ args: { domain: "acme.com" } });
    } finally {
      out.restore();
    }
    const texto = out.text();
    assert.match(texto, /acme\.com/);
    assert.match(texto, /Vercel/);
    assert.match(texto, /76\.76\.21\.21/);
    assert.match(texto, /www\.acme\.com/);
    assert.match(texto, /sin plataforma/);
    assert.match(texto, /el CNAME apunta a un destino que no responde/);
  });

  it("con --json imprime el objeto del SDK tal cual", async () => {
    const { client } = fakeClient({ domains: { list: () => [{ id: "dom_1", domain: "acme.com" }] }, dns: { website: () => sitio } });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await website.run({ args: { domain: "acme.com", json: true } });
    } finally {
      out.restore();
    }
    assert.deepEqual(JSON.parse(out.text()), sitio);
  });

  it("si el SDK falla, sale con el código del error (404 → 4)", async () => {
    const { client } = fakeClient({
      domains: { list: () => [{ id: "dom_1", domain: "acme.com" }] },
      dns: { website: () => { throw Object.assign(new Error("no existe"), { status: 404 }); } },
    });
    currentClient = client;
    await assert.rejects(
      () => website.run({ args: { domain: "acme.com" } }),
      (err: unknown) => err instanceof ExitSignal && err.code !== 0,
    );
  });
});

describe("dns preset --preview: vista previa sin aplicar", () => {
  it("llama presetPreview y NUNCA a preset", async () => {
    const { client, calls } = fakeClient({
      domains: { list: () => [{ id: "dom_1", domain: "acme.com" }] },
      dns: { presetPreview: () => vistaPrevia, preset: () => { throw new Error("preset no debe llamarse"); } },
    });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await preset.run({ args: { domain: "acme.com", preset: "vercel", target: "proyecto.vercel.app", preview: true } });
    } finally {
      out.restore();
    }
    const previews = calls.filter((c) => c.method === "dns.presetPreview");
    const aplicados = calls.filter((c) => c.method === "dns.preset");
    assert.equal(previews.length, 1);
    assert.deepEqual(previews[0].args, ["dom_1", "vercel", "proyecto.vercel.app", undefined]);
    assert.equal(aplicados.length, 0);
  });

  it("no pide confirmación: funciona sin --yes y sin terminal", async () => {
    const { client } = fakeClient({
      domains: { list: () => [{ id: "dom_1", domain: "acme.com" }] },
      dns: { presetPreview: () => vistaPrevia },
    });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await preset.run({ args: { domain: "acme.com", preset: "vercel", target: "proyecto.vercel.app", preview: true } });
    } finally {
      out.restore();
    }
    assert.match(out.text(), /no se aplicó nada/);
  });

  it("en texto muestra lo que se escribiría y lo que hay hoy", async () => {
    const { client } = fakeClient({
      domains: { list: () => [{ id: "dom_1", domain: "acme.com" }] },
      dns: { presetPreview: () => vistaPrevia },
    });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await preset.run({ args: { domain: "acme.com", preset: "vercel", target: "proyecto.vercel.app", preview: true } });
    } finally {
      out.restore();
    }
    assert.match(out.text(), /76\.76\.21\.21/);
    assert.match(out.text(), /1\.2\.3\.4/);
  });

  it("con --json imprime la vista previa del SDK", async () => {
    const { client } = fakeClient({
      domains: { list: () => [{ id: "dom_1", domain: "acme.com" }] },
      dns: { presetPreview: () => vistaPrevia },
    });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await preset.run({ args: { domain: "acme.com", preset: "vercel", target: "proyecto.vercel.app", preview: true, json: true } });
    } finally {
      out.restore();
    }
    assert.deepEqual(JSON.parse(out.text()), vistaPrevia);
  });

  it("un preset inválido falla ANTES de cualquier llamada de red, también con --preview", async () => {
    const { client, calls } = fakeClient({});
    currentClient = client;
    await assert.rejects(
      () => preset.run({ args: { domain: "acme.com", preset: "wix-no-existe", preview: true } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 1,
    );
    assert.equal(calls.length, 0);
  });
});
