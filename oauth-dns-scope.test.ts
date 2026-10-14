// Scope OAuth `dns` (14-oct-2026): EasyBits se conecta como cliente OAuth para escribir los
// registros de sus dominios propios, sin ver el correo. Un `mo_` con `dns` a secas sólo alcanza
// la lista de dominios, un dominio, su DNS y sus registros a pegar; todo lo demás es 403 y el
// MCP lo rechaza. También el lote atómico `POST /dns/batch`, que es lo que usa ese cliente.
//
// Va aparte porque el mock de route53.ts tiene que instalarse antes de que main.ts lo cargue.
import { describe, it, before, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";

const suffix = Date.now().toString(36);
const REDIRECT = "https://easybits.example/callback";
const zona = new Map<string, { name: string; type: string; ttl: number; values: string[] }>();
let lotes = 0;

describe("OAuth: scope dns", () => {
  // deno-lint-ignore no-explicit-any
  let app: any, sqlite: any, dbmod: any;
  let cookie = "";
  let domainId = "";
  const email = `oauth-dns-${suffix}@example.com`;
  const dominio = `oauth-dns-${suffix}.com`;

  const req = (path: string, init: RequestInit = {}) => app.fetch(new Request(`http://localhost${path}`, init));
  const form = (data: Record<string, string>) => ({
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(data).toString(),
  });
  const bearer = (token: string, init: RequestInit = {}) => ({ ...init, headers: { "content-type": "application/json", authorization: `Bearer ${token}`, ...(init.headers ?? {}) } });

  /** DCR → authorize con sesión → consentimiento → token. Devuelve el `mo_` y el HTML del consentimiento. */
  async function token(scope: string): Promise<{ access: string; consent: string }> {
    const reg = await req("/oauth/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ client_name: "EasyBits", logo_uri: "https://www.easybits.cloud/logo.svg", redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" }),
    });
    const clientId = (await reg.json()).client_id;
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT, state: "s", code_challenge: challenge, code_challenge_method: "S256", resource: "http://localhost/mcp", scope });
    const page = await req(`/oauth/authorize?${q}`, { headers: { cookie } });
    const consent = await page.text();
    const fields = Object.fromEntries([...consent.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)].map((m) => [m[1], m[2].replace(/&amp;/g, "&")]));
    const res = await req("/oauth/authorize", { ...form({ ...fields, decision: "allow" }), headers: { "content-type": "application/x-www-form-urlencoded", cookie } });
    const code = new URL(res.headers.get("location")!).searchParams.get("code")!;
    const t = await (await req("/oauth/token", form({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier }))).json();
    assert.equal(t.scope, scope);
    return { access: t.access_token, consent };
  }

  before(async () => {
    const real = await import("./route53.ts");
    mock.module("./route53.ts", {
      namedExports: {
        ...real,
        listRecordSets: async () => [...zona.values()],
        // deno-lint-ignore no-explicit-any
        applyRecordChanges: async (_z: string, cambios: any[]) => {
          lotes++;
          for (const c of cambios) {
            const k = `${c.rrset.name}|${c.rrset.type}`;
            if (c.action === "DELETE") zona.delete(k); else zona.set(k, c.rrset);
          }
          return { changeId: `C${lotes}` };
        },
      },
    });
    ({ app } = await import("./main.ts"));
    dbmod = await import("./db.ts");
    ({ sqlite } = await import("./pg.ts"));
    const { hashPassword, signJwt } = await import("./auth.ts");
    dbmod.createUser(email, await hashPassword("password123"));
    cookie = `token=${await signJwt({ email })}`;
    domainId = dbmod.createDomain(email, dominio, ["dk1"], "vf1").id;
    sqlite.prepare("UPDATE domains SET hosted_zone_id = 'ZDNS' WHERE id = ?").run(domainId);
  });
  beforeEach(() => {
    sqlite.prepare("DELETE FROM rate_limits").run();
    zona.clear();
    zona.set(`${dominio}|MX`, { name: dominio, type: "MX", ttl: 300, values: ["10 inbound-smtp.us-east-1.amazonaws.com"] });
    zona.set(`www.${dominio}|A`, { name: `www.${dominio}`, type: "A", ttl: 300, values: ["1.2.3.4"] });
  });

  it("la metadata anuncia los dos scopes y sin scope se concede la cuenta completa", async () => {
    const as = await (await req("/.well-known/oauth-authorization-server")).json();
    assert.deepEqual(as.scopes_supported, ["mailmask", "dns"]);
    const { consent } = await token("dns");
    assert.match(consent, /crear o borrar registros DNS/);
    assert.match(consent, /No podrá leer tu correo ni tus buzones/);
    assert.match(consent, /<img src="https:\/\/www\.easybits\.cloud\/logo\.svg"/);
    assert.doesNotMatch(consent, /Enviar correo desde tus dominios/);
  });

  it("un token dns ve dominios y escribe DNS, pero nada más", async () => {
    const { access } = await token("dns");
    const lista = await req("/api/domains", bearer(access));
    assert.equal(lista.status, 200);
    assert.ok((await lista.json()).some((d: { id: string }) => d.id === domainId));
    assert.equal((await req(`/api/domains/${domainId}`, bearer(access))).status, 200);
    assert.equal((await req(`/api/domains/${domainId}/dns`, bearer(access))).status, 200);

    const put = await req(`/api/domains/${domainId}/dns/records`, bearer(access, { method: "PUT", body: JSON.stringify({ name: "_easybits-verify", type: "TXT", values: ["abc"] }) }));
    assert.equal(put.status, 200);
    assert.ok(zona.has(`_easybits-verify.${dominio}|TXT`));

    for (const [method, path] of [
      ["GET", `/api/domains/${domainId}/alias`],
      ["GET", `/api/domains/${domainId}/addresses`],
      ["GET", "/api/auth/me"],
      ["DELETE", `/api/domains/${domainId}`],
      ["GET", `/api/domains/${domainId}/website`],
    ]) {
      const r = await req(path, bearer(access, { method }));
      assert.equal(r.status, 403, `${method} ${path}`);
      assert.equal((await r.json()).code, "insufficient_scope");
    }
    assert.ok(sqlite.prepare("SELECT 1 FROM domains WHERE id = ?").get(domainId), "el DELETE no pasó");
  });

  it("el MCP rechaza un token sólo-dns; con mailmask entra", async () => {
    const { access } = await token("dns");
    const r = await req("/mcp", bearer(access, { method: "POST", headers: { accept: "application/json, text/event-stream" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }) }));
    assert.equal(r.status, 403);
    assert.match(r.headers.get("www-authenticate")!, /insufficient_scope/);

    const full = await token("mailmask dns");
    const ok = await req("/mcp", bearer(full.access, { method: "POST", headers: { accept: "application/json, text/event-stream" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }) }));
    assert.equal(ok.status, 200);
    // `mailmask` vale la cuenta completa aunque traiga `dns`.
    assert.equal((await req(`/api/domains/${domainId}/alias`, bearer(full.access))).status, 200);
  });

  it("batch: todo en un cambio, con lo de antes por paso; dryRun no escribe", async () => {
    const { access } = await token("dns");
    const changes = [
      { action: "DELETE", name: "www", type: "A" },
      // Borrar el A y poner el CNAME en el mismo lote: la convivencia se mide con el lote aplicado.
      { action: "UPSERT", name: "www", type: "CNAME", values: ["cname.sandboxes.easybits.cloud"] },
      { action: "UPSERT", name: "_easybits-verify", type: "TXT", values: ["tok"] },
    ];
    const antes = lotes;
    const prev = await (await req(`/api/domains/${domainId}/dns/batch`, bearer(access, { method: "POST", body: JSON.stringify({ changes, dryRun: true }) }))).json();
    assert.equal(prev.dryRun, true);
    assert.equal(lotes, antes, "la vista previa no escribe");
    assert.ok(zona.has(`www.${dominio}|A`));

    const r = await req(`/api/domains/${domainId}/dns/batch`, bearer(access, { method: "POST", body: JSON.stringify({ changes }) }));
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.equal(lotes, antes + 1, "un solo cambio de Route 53");
    assert.deepEqual(j.changes.map((c: { action: string; type: string }) => `${c.action} ${c.type}`), ["DELETE A", "UPSERT CNAME", "UPSERT TXT"]);
    assert.deepEqual(j.changes[0].before.values, ["1.2.3.4"]);
    assert.equal(j.changes[1].before, null);
    assert.equal(j.changes[2].after.values[0], '"tok"');
    assert.ok(!zona.has(`www.${dominio}|A`) && zona.has(`www.${dominio}|CNAME`));
  });

  it("batch atómico: un cambio inválido o que toca el correo no deja escribir ninguno", async () => {
    const { access } = await token("dns");
    const antes = lotes;
    for (const changes of [
      [{ action: "UPSERT", name: "app", type: "A", values: ["9.9.9.9"] }, { action: "DELETE", name: "@", type: "MX" }],
      [{ action: "UPSERT", name: "app", type: "A", values: ["9.9.9.9"] }, { action: "UPSERT", name: "www", type: "CNAME", values: ["x.example.com"] }],
      [{ action: "UPSERT", name: "app", type: "A", values: ["no-es-ip"] }],
      [{ action: "DELETE", name: "nada", type: "A" }],
    ]) {
      const r = await req(`/api/domains/${domainId}/dns/batch`, bearer(access, { method: "POST", body: JSON.stringify({ changes }) }));
      assert.equal(r.status, 409, JSON.stringify(changes));
    }
    assert.equal(lotes, antes);
    assert.ok(!zona.has(`app.${dominio}|A`), "nada entró");
    assert.ok(zona.has(`${dominio}|MX`), "el correo sigue");
  });
});
