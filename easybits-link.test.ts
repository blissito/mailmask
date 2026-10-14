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
    assert.deepEqual(names, ["TXT _easybits-verify.ej.com", "CNAME *.ej.com", "A ej.com", "AAAA ej.com", "CNAME www.ej.com"]);
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

  it("un dominio que ya existía en EasyBits no se borra al fallar", async () => {
    await connected();
    route("GET", "/domains", () => json({ domains: [{ id: "d3", domain: "ej.com", txtToken: "t", verified: true }] }));
    await assert.rejects(() => eb.publishSite({ email: EMAIL, redirectUri: REDIRECT, domain: "ej.com", websiteId: "w1", placement: "subdomain" }, dnsMock(true).ops));
    assert.ok(!calls.some((c) => c.method === "DELETE"));
  });
});
