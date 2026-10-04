// E2E del OAuth del MCP contra un servidor que YA corre (local). Uso:
//   DATABASE_PATH=./data/e2e.db JWT_SECRET=e2e PORT=8011 npx tsx main.ts &
//   DATABASE_PATH=./data/e2e.db JWT_SECRET=e2e npx tsx scripts/oauth-e2e.ts http://localhost:8011
// La sesión de prueba se acuña aquí con el mismo JWT_SECRET (misma base que el servidor).
import { createHash, randomBytes } from "node:crypto";
import { createUser, getUser } from "../db.js";
import { hashPassword, signJwt } from "../auth.js";

const BASE = (process.argv[2] ?? "http://localhost:8011").replace(/\/$/, "");
const REDIRECT = "http://127.0.0.1:9/callback";
const email = "oauth-e2e@example.com";
const ok = (cond: unknown, msg: string) => { if (!cond) { console.error(`✗ ${msg}`); process.exit(1); } console.log(`✓ ${msg}`); };
const form = (d: Record<string, string>) => ({ method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(d).toString() });
const mcp = (token: string) => fetch(`${BASE}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }) });

if (!getUser(email)) createUser(email, await hashPassword(randomBytes(12).toString("hex")));
const cookie = `token=${await signJwt({ email })}`;

// 1) Descubrimiento como lo hace un cliente MCP.
const probe = await fetch(`${BASE}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
const www = probe.headers.get("www-authenticate") ?? "";
ok(probe.status === 401 && /resource_metadata="/.test(www), `401 con ${www}`);
const prm = await (await fetch(/resource_metadata="([^"]+)"/.exec(www)![1])).json();
const as = await (await fetch(`${prm.authorization_servers[0]}/.well-known/oauth-authorization-server`)).json();
ok(as.registration_endpoint, `metadata: ${as.registration_endpoint}`);

// 2) DCR.
const reg = await (await fetch(as.registration_endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "E2E", redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" }) })).json();
ok(reg.client_id, `cliente ${reg.client_id}`);

// 3) authorize con sesión → consentimiento → code.
const verifier = randomBytes(32).toString("base64url");
const challenge = createHash("sha256").update(verifier).digest("base64url");
const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: REDIRECT, state: "e2e", code_challenge: challenge, code_challenge_method: "S256", resource: prm.resource, scope: prm.scopes_supported.join(" ") });
const html = await (await fetch(`${as.authorization_endpoint}?${q}`, { headers: { cookie }, redirect: "manual" })).text();
const fields = Object.fromEntries([...html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)].map((m) => [m[1], m[2].replace(/&amp;/g, "&")]));
ok(fields.ticket, "pantalla de consentimiento");
const consent = await fetch(as.authorization_endpoint, { ...form({ ...fields, decision: "allow" }), headers: { "content-type": "application/x-www-form-urlencoded", cookie }, redirect: "manual" });
const code = new URL(consent.headers.get("location")!).searchParams.get("code");
ok(consent.status === 302 && code, "code de un solo uso");

// 4) token → /mcp tools/list con mo_.
const t1 = await (await fetch(as.token_endpoint, form({ grant_type: "authorization_code", code: code!, redirect_uri: REDIRECT, client_id: reg.client_id, code_verifier: verifier, resource: prm.resource }))).json();
ok(t1.access_token?.startsWith("mo_"), "access token mo_");
const list = await (await mcp(t1.access_token)).json();
ok(list.result?.tools?.length > 0, `tools/list con mo_: ${list.result?.tools?.length} herramientas`);

// 5) refresh (rota) → 6) revoke.
const t2 = await (await fetch(as.token_endpoint, form({ grant_type: "refresh_token", refresh_token: t1.refresh_token, client_id: reg.client_id }))).json();
ok(t2.access_token && t2.refresh_token !== t1.refresh_token, "refresh rotado");
ok((await mcp(t2.access_token)).status === 200, "mo_ nuevo sirve");
const rv = await fetch(as.revocation_endpoint, form({ token: t2.refresh_token, client_id: reg.client_id }));
ok(rv.status === 200, "revoke 200");
ok((await mcp(t2.access_token)).status === 401, "tras revocar, /mcp da 401");
console.log("E2E OK");
