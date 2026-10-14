import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { sqlite } from "./pg.ts";
import * as eb from "./easybits-link.ts";
import type { RRSet } from "./dns-records.ts";

const REDIRECT = "http://localhost:8000/api/integrations/easybits/callback";
const EMAIL = "eb-test@example.com";

type Call = { url: string; method: string; body: string };
let calls: Call[] = [];
let handlers: Record<string, (c: Call) => Response> = {};
const realFetch = globalThis.fetch;

function route(method: string, path: string, fn: (c: Call) => Response) { handlers[`${method} ${path}`] = fn; }
const json = (data: unknown, status = 200) => Response.json(data, { status });

beforeEach(() => {
  calls = [];
  handlers = {};
  sqlite.prepare("DELETE FROM easybits_links").run();
  sqlite.prepare("DELETE FROM easybits_oauth_clients").run();
  globalThis.fetch = (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const c = { url, method: init?.method ?? "GET", body: init?.body ? String(init.body) : "" };
    calls.push(c);
    const path = new URL(url).pathname.replace(/^\/api\/v2/, "");
    const h = handlers[`${c.method} ${path}`];
    if (!h) throw new Error(`fetch sin mock: ${c.method} ${url}`);
    return h(c);
  }) as typeof fetch;
  route("POST", "/oauth/register", () => json({ client_id: "cid_1", client_secret: "sec_1" }, 201));
});
afterEach(() => { globalThis.fetch = realFetch; });

describe("easybits-link: OAuth", () => {
  it("PKCE S256 y URL de authorize con resource y scope", async () => {
    const { verifier, challenge } = eb.pkcePair();
    assert.equal(challenge, createHash("sha256").update(verifier).digest("base64url"));
    const client = await eb.getOAuthClient(REDIRECT);
    const u = new URL(eb.authorizeUrl(client, REDIRECT, "st", challenge));
    assert.equal(u.searchParams.get("code_challenge_method"), "S256");
    assert.equal(u.searchParams.get("client_id"), "cid_1");
    assert.equal(u.searchParams.get("resource"), eb.EASYBITS_ORIGIN);
    // El cliente se registra UNA vez y queda guardado.
    await eb.getOAuthClient(REDIRECT);
    assert.equal(calls.filter((c) => c.url.endsWith("/oauth/register")).length, 1);
  });

  it("canje: tokens guardados cifrados, no en claro", async () => {
    route("POST", "/oauth/token", (c) => {
      const f = new URLSearchParams(c.body);
      assert.equal(f.get("grant_type"), "authorization_code");
      assert.equal(f.get("code_verifier"), "ver");
      assert.equal(f.get("client_secret"), "sec_1");
      return json({ access_token: "at_secreto", refresh_token: "rt_secreto", expires_in: 3600 });
    });
    await eb.exchangeCode(EMAIL, REDIRECT, "code", "ver");
    const row = sqlite.prepare("SELECT access_token, refresh_token FROM easybits_links WHERE user_email = ?").get(EMAIL) as { access_token: string; refresh_token: string };
    assert.ok(!row.access_token.includes("at_secreto"));
    assert.equal(eb.unseal(row.access_token), "at_secreto");
    assert.ok(eb.isConnected(EMAIL));
  });

  it("token vencido se refresca; refresh rechazado desconecta", async () => {
    route("POST", "/oauth/token", () => json({ access_token: "at_1", refresh_token: "rt_1", expires_in: 0 }));
    await eb.exchangeCode(EMAIL, REDIRECT, "code", "ver");
    route("POST", "/oauth/token", (c) => {
      assert.equal(new URLSearchParams(c.body).get("grant_type"), "refresh_token");
      return json({ access_token: "at_2", expires_in: 3600 });
    });
    route("GET", "/websites", (c) => { assert.ok(c.url.includes("limit=100")); return json({ items: [{ id: "w1", name: "Contador", slug: "contador", status: "ACTIVE", url: "x" }] }); });
    assert.equal((await eb.listSites(EMAIL, REDIRECT))[0].slug, "contador");

    sqlite.prepare("UPDATE easybits_links SET expires_at = 0").run();
    route("POST", "/oauth/token", () => json({ error: "invalid_grant" }, 400));
    await assert.rejects(() => eb.listSites(EMAIL, REDIRECT), eb.EasyBitsDisconnected);
    assert.equal(eb.isConnected(EMAIL), false);
  });
});

describe("easybits-link: publicar un sitio", () => {
  async function connected() {
    route("POST", "/oauth/token", () => json({ access_token: "at", refresh_token: "rt", expires_in: 3600 }));
    await eb.exchangeCode(EMAIL, REDIRECT, "code", "ver");
    route("GET", "/websites", () => json({ items: [{ id: "w1", name: "Contador", slug: "contador", status: "ACTIVE", url: "x" }] }));
  }
  const dnsMock = (fail = false) => {
    const applied: RRSet[][] = [];
    return {
      applied,
      ops: {
        current: () => null,
        async apply(r: RRSet[]) { if (fail) throw new Error("conflicto DNS"); applied.push(r); },
      },
    };
  };

  it("vista previa: no toca EasyBits ni el DNS", async () => {
    await connected();
    const dns = dnsMock();
    const r = await eb.publishSite({ email: EMAIL, redirectUri: REDIRECT, domain: "ej.com", websiteId: "w1", placement: "subdomain", dryRun: true }, dns.ops);
    assert.equal(r.url, "https://contador.ej.com");
    assert.deepEqual(r.records.map((x) => `${x.type} ${x.name}`), ["TXT _easybits-verify.ej.com", "CNAME *.ej.com", "CNAME contador.ej.com"]);
    assert.equal(dns.applied.length, 0);
    assert.ok(!calls.some((c) => c.url.includes("/domains")));
  });

  it("raíz: alta del dominio, DNS en un solo cambio, verify y apex", async () => {
    await connected();
    route("GET", "/domains", () => json({ domains: [] }));
    route("POST", "/domains", () => json({ domain: { id: "d1", domain: "ej.com", txtToken: "easybits-verify-abc", verified: false } }, 201));
    route("POST", "/domains/d1/verify", () => json({ domain: { id: "d1", verified: true } }));
    route("POST", "/domains/d1/apex", (c) => { assert.equal(JSON.parse(c.body).websiteId, "w1"); return json({ domain: {} }); });
    const dns = dnsMock();
    const r = await eb.publishSite({ email: EMAIL, redirectUri: REDIRECT, domain: "ej.com", websiteId: "w1", placement: "apex", verifyDelays: [0] }, dns.ops);
    assert.equal(r.verified, true);
    assert.equal(dns.applied.length, 1, "un solo cambio");
    const names = dns.applied[0].map((x) => `${x.type} ${x.name}`);
    assert.deepEqual(names, ["TXT _easybits-verify.ej.com", "CNAME *.ej.com", "A ej.com", "CNAME www.ej.com"]);
    assert.deepEqual(dns.applied[0][0].values, ['"easybits-verify-abc"']);
    assert.ok(calls.some((c) => c.url.endsWith("/domains/d1/apex")));
  });

  it("si el DNS falla, el dominio que creamos en EasyBits se quita", async () => {
    await connected();
    route("GET", "/domains", () => json({ domains: [] }));
    route("POST", "/domains", () => json({ domain: { id: "d2", domain: "ej.com", txtToken: "t", verified: false } }, 201));
    route("DELETE", "/domains", (c) => { assert.equal(JSON.parse(c.body).domainId, "d2"); return json({ ok: true }); });
    await assert.rejects(
      () => eb.publishSite({ email: EMAIL, redirectUri: REDIRECT, domain: "ej.com", websiteId: "w1", placement: "subdomain", verifyDelays: [0] }, dnsMock(true).ops),
      /conflicto DNS/,
    );
    assert.ok(calls.some((c) => c.method === "DELETE" && c.url.endsWith("/domains")));
  });

  it("ya verificado: igual se llama verify (registra el host en el borde)", async () => {
    await connected();
    route("GET", "/domains", () => json({ domains: [{ id: "d4", domain: "ej.com", txtToken: "t", verified: true }] }));
    route("POST", "/domains/d4/verify", () => json({ domain: { id: "d4", verified: true } }));
    const r = await eb.publishSite({ email: EMAIL, redirectUri: REDIRECT, domain: "ej.com", websiteId: "w1", placement: "subdomain", verifyDelays: [0] }, dnsMock().ops);
    assert.equal(r.verified, true);
    assert.ok(calls.some((c) => c.url.endsWith("/domains/d4/verify")));
  });

  it("un dominio que ya existía en EasyBits no se borra al fallar", async () => {
    await connected();
    route("GET", "/domains", () => json({ domains: [{ id: "d3", domain: "ej.com", txtToken: "t", verified: true }] }));
    await assert.rejects(() => eb.publishSite({ email: EMAIL, redirectUri: REDIRECT, domain: "ej.com", websiteId: "w1", placement: "subdomain" }, dnsMock(true).ops));
    assert.ok(!calls.some((c) => c.method === "DELETE"));
  });
});

describe("easybits-link: quitar un sitio (bitácora y restauración)", () => {
  const DOMAIN_ID = "dom-eb-unpub";
  // Zona en memoria, llaveada por `nombre|tipo`, con las mismas reglas que Route 53.
  let zona: Map<string, RRSet>;
  const k = (n: string, t: string) => `${n}|${t}`;
  const cambios: { action: string; rrset: RRSet }[][] = [];
  const ops = {
    current: (name: string, type: string) => zona.get(k(name, type)) ?? null,
    async apply(records: RRSet[]) { for (const r of records) zona.set(k(r.name, r.type), r); return records; },
  };
  const restoreOps = {
    current: (name: string, type: string) => zona.get(k(name, type)) ?? null,
    async apply(changes: { action: "UPSERT" | "DELETE"; rrset: RRSet }[]) {
      cambios.push(changes);
      for (const c of changes) {
        if (c.action === "UPSERT") zona.set(k(c.rrset.name, c.rrset.type), c.rrset);
        else zona.delete(k(c.rrset.name, c.rrset.type));
      }
    },
  };

  async function connected(domains: unknown[] = []) {
    route("POST", "/oauth/token", () => json({ access_token: "at", refresh_token: "rt", expires_in: 3600 }));
    await eb.exchangeCode(EMAIL, REDIRECT, "code", "ver");
    route("GET", "/websites", () => json({ items: [
      { id: "w1", name: "Contador", slug: "contador", status: "ACTIVE", url: "x" },
      { id: "w2", name: "Blog", slug: "blog", status: "ACTIVE", url: "y" },
    ] }));
    route("GET", "/domains", () => json({ domains }));
    route("POST", "/domains", () => json({ domain: { id: "d9", domain: "ej.com", txtToken: "tok", verified: false } }, 201));
    route("POST", "/domains/d9/verify", () => json({ domain: { id: "d9", verified: true } }));
    route("POST", "/domains/d9/apex", () => json({ domain: {} }));
    route("DELETE", "/domains", () => json({ ok: true }));
  }
  const publish = (placement: "apex" | "subdomain", websiteId = "w1") =>
    eb.publishSite({ email: EMAIL, redirectUri: REDIRECT, domain: "ej.com", domainId: DOMAIN_ID, websiteId, placement, verifyDelays: [0] }, ops);

  beforeEach(() => {
    sqlite.prepare("DELETE FROM easybits_publications").run();
    cambios.length = 0;
    zona = new Map([
      // Lo que el usuario tenía antes: raíz y www en Vercel, y su correo.
      [k("ej.com", "A"), { name: "ej.com", type: "A", ttl: 300, values: ["76.76.21.21"] }],
      [k("www.ej.com", "CNAME"), { name: "www.ej.com", type: "CNAME", ttl: 300, values: ["cname.vercel-dns.com"] }],
      [k("ej.com", "MX"), { name: "ej.com", type: "MX", ttl: 300, values: ["10 inbound-smtp.us-east-1.amazonaws.com"] }],
    ]);
  });

  it("publicar anota lo de antes; quitar restaura www y la raíz y borra lo que no existía", async () => {
    await connected();
    await publish("apex");
    const pub = eb.getPublication(DOMAIN_ID)!;
    assert.equal(pub.ebDomainCreated, true);
    assert.deepEqual(pub.previous["www.ej.com|CNAME"]?.values, ["cname.vercel-dns.com"]);
    assert.deepEqual(pub.previous["ej.com|A"]?.values, ["76.76.21.21"]);
    assert.equal(pub.previous["*.ej.com|CNAME"], null);
    assert.deepEqual(zona.get(k("ej.com", "A"))!.values, [eb.EASYBITS_EDGE.v4]);

    calls = [];
    const r = await eb.unpublishSite(DOMAIN_ID, REDIRECT, restoreOps);
    assert.equal(cambios.length, 1, "un solo cambio de Route 53");
    assert.deepEqual(zona.get(k("ej.com", "A"))!.values, ["76.76.21.21"]);
    assert.deepEqual(zona.get(k("www.ej.com", "CNAME"))!.values, ["cname.vercel-dns.com"]);
    assert.ok(!zona.has(k("*.ej.com", "CNAME")) && !zona.has(k("_easybits-verify.ej.com", "TXT")), "lo que no existía se borra");
    assert.ok(zona.has(k("ej.com", "MX")), "el correo ni se toca");
    assert.ok(!cambios[0].some((c) => c.rrset.type === "MX"));
    assert.equal(r.restored.length, 4);
    assert.equal(r.skipped.length, 0);
    // EasyBits: se suelta la raíz y se borra el dominio que dimos de alta.
    const apex = calls.find((c) => c.url.endsWith("/domains/d9/apex"))!;
    assert.equal(JSON.parse(apex.body).websiteId, null);
    assert.ok(calls.some((c) => c.method === "DELETE" && JSON.parse(c.body).domainId === "d9"));
    assert.deepEqual(r.easybits, { apexCleared: true, domainDeleted: true });
    assert.equal(eb.getPublication(DOMAIN_ID), null);

    // Idempotente.
    const otra = await eb.unpublishSite(DOMAIN_ID, REDIRECT, restoreOps);
    assert.equal(otra.nothing, true);
  });

  it("re-publicar conserva el `previous` original y no olvida la raíz al pasar a subdominio", async () => {
    await connected();
    await publish("apex");
    await publish("subdomain", "w2");
    const pub = eb.getPublication(DOMAIN_ID)!;
    assert.deepEqual(pub.previous["ej.com|A"]?.values, ["76.76.21.21"], "no se pisa con lo nuestro");
    assert.equal(pub.previous["blog.ej.com|CNAME"], null);
    assert.ok(pub.records.some((r) => r.name === "ej.com" && r.type === "A"), "la raíz sigue anotada");
    assert.equal(pub.placement, "subdomain");

    await eb.unpublishSite(DOMAIN_ID, REDIRECT, restoreOps);
    assert.deepEqual(zona.get(k("ej.com", "A"))!.values, ["76.76.21.21"]);
    assert.ok(!zona.has(k("blog.ej.com", "CNAME")));
  });

  it("un registro que el usuario cambió después se deja y sale en `skipped`", async () => {
    await connected();
    await publish("apex");
    zona.set(k("www.ej.com", "CNAME"), { name: "www.ej.com", type: "CNAME", ttl: 300, values: ["mi-nuevo.netlify.app"] });
    const r = await eb.unpublishSite(DOMAIN_ID, REDIRECT, restoreOps);
    assert.deepEqual(zona.get(k("www.ej.com", "CNAME"))!.values, ["mi-nuevo.netlify.app"], "no se pisa");
    assert.deepEqual(r.skipped.map((x) => x.name), ["www.ej.com"]);
    assert.deepEqual(zona.get(k("ej.com", "A"))!.values, ["76.76.21.21"], "lo demás sí vuelve");
  });

  it("un dominio que ya existía en EasyBits no se borra al quitar", async () => {
    await connected([{ id: "d9", domain: "ej.com", txtToken: "tok", verified: true }]);
    await publish("subdomain");
    calls = [];
    const r = await eb.unpublishSite(DOMAIN_ID, REDIRECT, restoreOps);
    assert.ok(!calls.some((c) => c.method === "DELETE"));
    assert.deepEqual(r.easybits, { apexCleared: false, domainDeleted: false });
  });

  it("si EasyBits falla, el DNS ya volvió y la fila se queda para reintentar", async () => {
    await connected();
    await publish("apex");
    route("POST", "/domains/d9/apex", () => json({ error: "boom" }, 500));
    await assert.rejects(() => eb.unpublishSite(DOMAIN_ID, REDIRECT, restoreOps), /DNS ya volvió/);
    assert.deepEqual(zona.get(k("ej.com", "A"))!.values, ["76.76.21.21"]);
    assert.ok(eb.getPublication(DOMAIN_ID));
    route("POST", "/domains/d9/apex", () => json({ domain: {} }));
    const r = await eb.unpublishSite(DOMAIN_ID, REDIRECT, restoreOps);
    assert.equal(r.skipped.length, 0, "lo ya restaurado cuenta como restaurado");
    assert.equal(eb.getPublication(DOMAIN_ID), null);
  });
});
