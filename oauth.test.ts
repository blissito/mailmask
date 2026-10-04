// OAuth 2.1 del MCP de punta a punta contra la app real (in-process, como mcp.test.ts):
// descubrimiento → DCR → consentimiento con sesión → token → /mcp con `mo_` → refresh con
// rotación y detección de reuso → revocación. Y que `mk_` siga igual.
import { describe, it, before, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";

const suffix = Date.now().toString(36);
const REDIRECT = "https://cliente.example/callback";

describe("OAuth del MCP", () => {
  // deno-lint-ignore no-explicit-any
  let app: any, sqlite: any;
  let cookie = "";
  let apiKey = "";
  const email = `oauth-${suffix}@example.com`;

  const req = (path: string, init: RequestInit = {}) => app.fetch(new Request(`http://localhost${path}`, init));
  const form = (data: Record<string, string>) => ({
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(data).toString(),
  });
  const pkce = () => {
    const verifier = randomBytes(32).toString("base64url");
    return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
  };
  const mcp = (token: string, method = "tools/list") => req("/mcp", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: {} }),
  });

  async function register(): Promise<string> {
    const r = await req("/oauth/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ client_name: "Ghosty", redirect_uris: [REDIRECT], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }),
    });
    assert.equal(r.status, 201);
    return (await r.json()).client_id;
  }

  /** authorize (con sesión) → consentimiento → code. */
  async function getCode(clientId: string, challenge: string, state = "s1"): Promise<string> {
    const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT, state, code_challenge: challenge, code_challenge_method: "S256", resource: "http://localhost/mcp", scope: "mailmask" });
    const page = await req(`/oauth/authorize?${q}`, { headers: { cookie } });
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.match(html, /Ghosty/);
    const fields = Object.fromEntries([...html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)].map((m) => [m[1], m[2].replace(/&amp;/g, "&")]));
    const res = await req("/oauth/authorize", { ...form({ ...fields, decision: "allow" }), headers: { "content-type": "application/x-www-form-urlencoded", cookie } });
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.get("location")!);
    assert.equal(loc.origin + loc.pathname, REDIRECT);
    assert.equal(loc.searchParams.get("state"), state);
    assert.equal(loc.searchParams.get("iss"), "http://localhost");
    return loc.searchParams.get("code")!;
  }

  before(async () => {
    ({ app } = await import("./main.ts"));
    const dbmod = await import("./db.ts");
    ({ sqlite } = await import("./pg.ts"));
    const { hashPassword, signJwt } = await import("./auth.ts");
    dbmod.createUser(email, await hashPassword("password123"));
    cookie = `token=${await signJwt({ email })}`;
    apiKey = (await dbmod.createApiKey(email, "oauth-test")).plaintextKey;
  });
  beforeEach(() => sqlite.prepare("DELETE FROM rate_limits").run());

  it("/mcp sin credencial anuncia la metadata OAuth", async () => {
    const r = await req("/mcp", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    assert.equal(r.status, 401);
    assert.equal(r.headers.get("www-authenticate"), 'Bearer resource_metadata="http://localhost/.well-known/oauth-protected-resource"');
  });

  it("well-known: recurso protegido (con y sin /mcp) y servidor de autorización", async () => {
    for (const p of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]) {
      const r = await req(p);
      assert.equal(r.status, 200);
      const j = await r.json();
      assert.equal(j.resource, "http://localhost/mcp");
      assert.deepEqual(j.authorization_servers, ["http://localhost"]);
      assert.deepEqual(j.bearer_methods_supported, ["header"]);
      assert.equal(r.headers.get("access-control-allow-origin"), "*");
    }
    const as = await (await req("/.well-known/oauth-authorization-server")).json();
    assert.equal(as.issuer, "http://localhost");
    assert.equal(as.registration_endpoint, "http://localhost/oauth/register");
    assert.deepEqual(as.code_challenge_methods_supported, ["S256"]);
    assert.deepEqual(as.grant_types_supported, ["authorization_code", "refresh_token"]);
    assert.deepEqual(as.token_endpoint_auth_methods_supported, ["none", "client_secret_post"]);
  });

  it("DCR rechaza redirect_uris inseguras", async () => {
    for (const uris of [["http://evil.example/cb"], ["javascript:alert(1)"], [], ["https://a.example/cb#x"]]) {
      const r = await req("/oauth/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: uris }) });
      assert.equal(r.status, 400, JSON.stringify(uris));
    }
    const local = await req("/oauth/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["http://127.0.0.1:3333/cb"] }) });
    assert.equal(local.status, 201);
  });

  it("authorize sin sesión manda al login con next; con datos malos no redirige al cliente", async () => {
    const clientId = await register();
    const { challenge } = pkce();
    const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: "S256" });
    const r = await req(`/oauth/authorize?${q}`);
    assert.equal(r.status, 302);
    assert.equal(r.headers.get("location"), `/login?next=${encodeURIComponent(`/oauth/authorize?${q}`)}`);
    // Un Bearer no es sesión.
    const conBearer = await req(`/oauth/authorize?${q}`, { headers: { authorization: `Bearer ${apiKey}` } });
    assert.equal(conBearer.status, 302);
    assert.match(conBearer.headers.get("location")!, /^\/login\?next=/);
    // redirect_uri distinto: página de error, nunca redirect.
    const malo = new URLSearchParams(q); malo.set("redirect_uri", "https://evil.example/cb");
    assert.equal((await req(`/oauth/authorize?${malo}`, { headers: { cookie } })).status, 400);
    // Sin PKCE: error de vuelta al cliente.
    const sinPkce = new URLSearchParams(q); sinPkce.delete("code_challenge");
    const e = await req(`/oauth/authorize?${sinPkce}`, { headers: { cookie } });
    assert.equal(e.status, 302);
    assert.match(e.headers.get("location")!, /error=invalid_request/);
    // resource ajeno: invalid_target.
    const otro = new URLSearchParams(q); otro.set("resource", "https://otro.example/mcp");
    assert.match((await req(`/oauth/authorize?${otro}`, { headers: { cookie } })).headers.get("location")!, /error=invalid_target/);
  });

  it("el consentimiento exige su ticket y la misma sesión", async () => {
    const clientId = await register();
    const { challenge } = pkce();
    const base = { response_type: "code", client_id: clientId, redirect_uri: REDIRECT, state: "x", code_challenge: challenge, code_challenge_method: "S256", resource: "http://localhost/mcp", scope: "mailmask" };
    const sinTicket = await req("/oauth/authorize", { ...form({ ...base, decision: "allow" }), headers: { "content-type": "application/x-www-form-urlencoded", cookie } });
    assert.equal(sinTicket.status, 400);
    // Cancelar devuelve access_denied.
    const html = await (await req(`/oauth/authorize?${new URLSearchParams(base)}`, { headers: { cookie } })).text();
    const ticket = /name="ticket" value="([^"]+)"/.exec(html)![1];
    const cancel = await req("/oauth/authorize", { ...form({ ...base, ticket, decision: "deny" }), headers: { "content-type": "application/x-www-form-urlencoded", cookie } });
    assert.match(cancel.headers.get("location")!, /error=access_denied/);
    // El ticket era de un solo uso.
    const otra = await req("/oauth/authorize", { ...form({ ...base, ticket, decision: "allow" }), headers: { "content-type": "application/x-www-form-urlencoded", cookie } });
    assert.equal(otra.status, 400);
  });

  it("flujo completo: code → mo_ en /mcp → refresh con rotación → reuso corta la familia → revoke", async () => {
    const clientId = await register();
    const { verifier, challenge } = pkce();
    const code = await getCode(clientId, challenge);

    // PKCE equivocado: invalid_grant (y el código queda quemado).
    const code2 = await getCode(clientId, pkce().challenge);
    const bad = await req("/oauth/token", form({ grant_type: "authorization_code", code: code2, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier }));
    assert.equal(bad.status, 400);
    assert.equal((await bad.json()).error, "invalid_grant");

    const tok = await req("/oauth/token", form({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: verifier, resource: "http://localhost/mcp" }));
    assert.equal(tok.status, 200);
    assert.equal(tok.headers.get("cache-control"), "no-store");
    const t1 = await tok.json();
    assert.match(t1.access_token, /^mo_/);
    assert.match(t1.refresh_token, /^mr_/);
    assert.equal(t1.token_type, "Bearer");
    assert.equal(t1.expires_in, 3600);
    // Nada se guarda en claro.
    assert.equal(sqlite.prepare("SELECT count(*) n FROM oauth_tokens WHERE token_hash = ?").get(t1.access_token).n, 0);

    const list = await mcp(t1.access_token);
    assert.equal(list.status, 200);
    const tools = (await list.json()).result.tools;
    assert.ok(tools.some((t: { name: string }) => t.name === "create_alias"));
    // Mismo alcance que mk_ salvo fabricar llaves.
    assert.equal((await req("/api/api-keys", { headers: { authorization: `Bearer ${t1.access_token}` } })).status, 403);
    assert.equal((await req("/api/domains", { headers: { authorization: `Bearer ${t1.access_token}` } })).status, 200);

    // Refresh: rota.
    const r2 = await req("/oauth/token", form({ grant_type: "refresh_token", refresh_token: t1.refresh_token, client_id: clientId, resource: "http://localhost/mcp" }));
    assert.equal(r2.status, 200);
    const t2 = await r2.json();
    assert.notEqual(t2.refresh_token, t1.refresh_token);
    assert.equal((await mcp(t2.access_token)).status, 200);

    // Reuso del refresh viejo: invalid_grant y la familia entera muere.
    const reuse = await req("/oauth/token", form({ grant_type: "refresh_token", refresh_token: t1.refresh_token, client_id: clientId }));
    assert.equal((await reuse.json()).error, "invalid_grant");
    const dead = await mcp(t2.access_token);
    assert.equal(dead.status, 401);
    assert.match(dead.headers.get("www-authenticate")!, /error="invalid_token"/);
    assert.equal((await req("/oauth/token", form({ grant_type: "refresh_token", refresh_token: t2.refresh_token, client_id: clientId }))).status, 400);

    // Un permiso nuevo y revocación (RFC 7009).
    const p3 = pkce();
    const code3 = await getCode(clientId, p3.challenge);
    const t3 = await (await req("/oauth/token", form({ grant_type: "authorization_code", code: code3, redirect_uri: REDIRECT, client_id: clientId, code_verifier: p3.verifier }))).json();
    assert.equal((await mcp(t3.access_token)).status, 200);
    // Reusar el código: invalid_grant y lo emitido con él se revoca.
    const again = await req("/oauth/token", form({ grant_type: "authorization_code", code: code3, redirect_uri: REDIRECT, client_id: clientId, code_verifier: p3.verifier }));
    assert.equal((await again.json()).error, "invalid_grant");
    assert.equal((await mcp(t3.access_token)).status, 401);

    const p4 = pkce();
    const t4 = await (await req("/oauth/token", form({ grant_type: "authorization_code", code: await getCode(clientId, p4.challenge), redirect_uri: REDIRECT, client_id: clientId, code_verifier: p4.verifier }))).json();
    assert.equal((await mcp(t4.access_token)).status, 200);
    // Otro cliente no puede revocar lo ajeno.
    const otro = await register();
    assert.equal((await req("/oauth/revoke", form({ token: t4.refresh_token, client_id: otro }))).status, 200);
    assert.equal((await mcp(t4.access_token)).status, 200);
    const rv = await req("/oauth/revoke", form({ token: t4.refresh_token, token_type_hint: "refresh_token", client_id: clientId }));
    assert.equal(rv.status, 200);
    assert.equal((await mcp(t4.access_token)).status, 401);
    assert.equal((await req("/oauth/revoke", form({ token: "mo_inexistente", client_id: clientId }))).status, 200);
  });

  it("un code de otro cliente no se canjea", async () => {
    const a = await register();
    const b = await register();
    const { verifier, challenge } = pkce();
    const code = await getCode(a, challenge);
    const r = await req("/oauth/token", form({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: b, code_verifier: verifier }));
    assert.equal((await r.json()).error, "invalid_grant");
    const desconocido = await req("/oauth/token", form({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: "mmc_nadie", code_verifier: verifier }));
    assert.equal(desconocido.status, 401);
  });

  it("client_secret_post exige el secreto", async () => {
    const reg = await (await req("/oauth/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Ghosty", redirect_uris: [REDIRECT], token_endpoint_auth_method: "client_secret_post" }) })).json();
    assert.match(reg.client_secret, /^mcs_/);
    const { verifier, challenge } = pkce();
    const code = await getCode(reg.client_id, challenge);
    const sin = await req("/oauth/token", form({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: reg.client_id, code_verifier: verifier }));
    assert.equal(sin.status, 401);
    const con = await req("/oauth/token", form({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: reg.client_id, client_secret: reg.client_secret, code_verifier: verifier }));
    assert.equal(con.status, 200);
  });

  it("mk_ sigue funcionando en /mcp", async () => {
    assert.equal((await mcp(apiKey)).status, 200);
  });
});
