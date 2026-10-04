// Servidor de autorización OAuth 2.1 para el MCP (spec MCP de autorización 2025-06-18/2025-11-25).
//
// Un cliente MCP (Ghosty Studio, Claude, etc.) conecta `/mcp` sin que la persona copie una `mk_`:
//   401 de /mcp con `WWW-Authenticate: Bearer resource_metadata=…`
//   → `/.well-known/oauth-protected-resource` (RFC 9728) → `/.well-known/oauth-authorization-server` (RFC 8414)
//   → `POST /oauth/register` (DCR, RFC 7591) → `GET /oauth/authorize` (sesión + consentimiento, PKCE S256)
//   → `POST /oauth/token` (code / refresh con rotación) → `Bearer mo_…` en /mcp. `POST /oauth/revoke` (RFC 7009).
//
// Decisiones:
// - Tokens OPACOS y guardados con SHA-256 (como `api_keys`): `mo_` acceso 1 h, `mr_` refresh 60 días.
// - Refresh con ROTACIÓN: cada uso invalida el anterior; presentar uno ya rotado (= robado o
//   duplicado) revoca toda la familia (todo lo que nació del mismo permiso).
// - Un `mo_` vale lo mismo que una `mk_` (no hay scopes finos todavía), salvo fabricar llaves o
//   entrar al admin (lo bloquea `main.ts`): revocar el permiso tiene que bastar para cortar el acceso.
// - La cookie de sesión es SameSite=Strict, así que al llegar desde otro sitio /oauth/authorize no
//   la ve: se manda a `/login?next=…`, que detecta la sesión con un fetch y vuelve ya en mismo sitio.
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { sqlite } from "./pg.js";
import { getUser } from "./db.js";
import { checkRateLimit } from "./rate-limit.js";

export const OAUTH_SCOPES = ["mailmask"];
const ACCESS_TTL_S = 3600;
const REFRESH_TTL_S = 60 * 86400;
const CODE_TTL_S = 600;
const CONSENT_TTL_S = 600;

// --- Identidad del servidor ---

/** En producción el issuer es el dominio canónico; en local, el origen de la petición. */
export function issuerFor(request: Request): string {
  if (process.env.FLY_APP_NAME) {
    const raw = process.env.MAIN_DOMAIN ?? "www.mailmask.studio";
    return `https://${raw.replace(/^https?:\/\//, "").replace(/\/+$/, "")}`;
  }
  return new URL(request.url).origin;
}
const resourceFor = (request: Request) => `${issuerFor(request)}/mcp`;

export function protectedResourceMetadataUrl(request: Request): string {
  return `${issuerFor(request)}/.well-known/oauth-protected-resource`;
}

// --- Helpers ---

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
const randomToken = (prefix: string) => `${prefix}${randomBytes(32).toString("base64url")}`;
const nowIso = () => new Date().toISOString();
const isoIn = (s: number) => new Date(Date.now() + s * 1000).toISOString();

function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", pragma: "no-cache", "access-control-allow-origin": "*", ...extra },
  });
}
const oauthError = (error: string, description: string, status = 400) => json({ error, error_description: description }, status);

function redirect(location: string): Response {
  // No Response.redirect(): sus headers son inmutables y onAfterHandle revienta.
  return new Response(null, { status: 302, headers: { location, "cache-control": "no-store" } });
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v.length > 0 ? v : undefined);

/** Canónico RFC 8707: sin fragmento ni barra final. */
function canonicalResource(r: string): string | null {
  try {
    const u = new URL(r);
    u.hash = "";
    return u.toString().replace(/\/$/, "");
  } catch {
    return null;
  }
}

function safeEqualHex(a: string, b: string): boolean {
  const ba = Buffer.from(a), bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

/** https en cualquier host, o http sólo a loopback (clientes de escritorio y desarrollo). */
export function validRedirectUri(raw: unknown): boolean {
  if (typeof raw !== "string" || raw.length > 2000) return false;
  let u: URL;
  try { u = new URL(raw); } catch { return false; }
  if (u.hash || u.username || u.password) return false;
  if (u.protocol === "https:") return true;
  return u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
}

function parseScope(raw: unknown): string | null {
  const s = str(raw);
  if (!s) return OAUTH_SCOPES.join(" ");
  const parts = s.split(/\s+/).filter(Boolean);
  if (!parts.length || parts.some((p) => !OAUTH_SCOPES.includes(p))) return null;
  return [...new Set(parts)].join(" ");
}

// --- Metadata (well-known) ---

export function protectedResourceMetadata(request: Request): Response {
  const iss = issuerFor(request);
  return json({
    resource: `${iss}/mcp`,
    authorization_servers: [iss],
    scopes_supported: OAUTH_SCOPES,
    bearer_methods_supported: ["header"],
    resource_name: "MailMask MCP",
    resource_documentation: `${iss}/docs#mcp`,
  });
}

export function authorizationServerMetadata(request: Request): Response {
  const iss = issuerFor(request);
  return json({
    issuer: iss,
    authorization_endpoint: `${iss}/oauth/authorize`,
    token_endpoint: `${iss}/oauth/token`,
    registration_endpoint: `${iss}/oauth/register`,
    revocation_endpoint: `${iss}/oauth/revoke`,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
    revocation_endpoint_auth_methods_supported: ["none", "client_secret_post"],
    scopes_supported: OAUTH_SCOPES,
    authorization_response_iss_parameter_supported: true,
    service_documentation: `${iss}/docs#mcp`,
  });
}

// --- Clientes (DCR) ---

type ClientRow = {
  client_id: string; client_secret_hash: string | null; client_name: string; client_uri: string | null;
  redirect_uris: string; token_endpoint_auth_method: string;
};

function getClient(clientId: string | undefined): (ClientRow & { redirectUris: string[] }) | null {
  if (!clientId || clientId.length > 100) return null;
  const row = sqlite.prepare("SELECT * FROM oauth_clients WHERE client_id = ?").get(clientId) as ClientRow | undefined;
  if (!row) return null;
  return { ...row, redirectUris: JSON.parse(row.redirect_uris) as string[] };
}

export function registerClient(body: unknown, ip: string): Response {
  // Registro abierto (cualquiera puede registrar un cliente), así que el tope por IP es la defensa.
  if (!checkRateLimit(`oauth-register:${ip}`, 20, 3600_000).allowed) return oauthError("too_many_requests", "Demasiados registros; intenta en una hora.", 429);
  const b = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const uris = b.redirect_uris;
  if (!Array.isArray(uris) || uris.length === 0 || uris.length > 10 || !uris.every(validRedirectUri)) {
    return oauthError("invalid_redirect_uri", "redirect_uris: lista de 1 a 10 URLs https (o http://localhost).");
  }
  const method = str(b.token_endpoint_auth_method) ?? "none";
  if (method !== "none" && method !== "client_secret_post") {
    return oauthError("invalid_client_metadata", "token_endpoint_auth_method: none o client_secret_post.");
  }
  const grants = Array.isArray(b.grant_types) ? b.grant_types : ["authorization_code", "refresh_token"];
  if (!grants.every((g) => g === "authorization_code" || g === "refresh_token")) {
    return oauthError("invalid_client_metadata", "grant_types: authorization_code y/o refresh_token.");
  }
  const responseTypes = Array.isArray(b.response_types) ? b.response_types : ["code"];
  if (!responseTypes.every((r) => r === "code")) return oauthError("invalid_client_metadata", "response_types: code.");
  const httpsOrNull = (v: unknown) => {
    const s = str(v);
    if (!s || s.length > 500) return null;
    try { return new URL(s).protocol === "https:" ? s : null; } catch { return null; }
  };
  const name = (str(b.client_name) ?? "Cliente MCP").replace(/[\u0000-\u001f]/g, "").slice(0, 80);
  const clientId = `mmc_${randomBytes(16).toString("base64url")}`;
  const secret = method === "client_secret_post" ? randomToken("mcs_") : null;
  const createdAt = nowIso();
  sqlite.prepare(`INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, client_uri, logo_uri, redirect_uris, token_endpoint_auth_method, created_ip, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(clientId, secret ? sha256(secret) : null, name, httpsOrNull(b.client_uri), httpsOrNull(b.logo_uri), JSON.stringify(uris), method, ip, createdAt);
  return json({
    client_id: clientId,
    ...(secret ? { client_secret: secret, client_secret_expires_at: 0 } : {}),
    client_id_issued_at: Math.floor(Date.parse(createdAt) / 1000),
    client_name: name,
    redirect_uris: uris,
    grant_types: grants,
    response_types: ["code"],
    token_endpoint_auth_method: method,
    scope: OAUTH_SCOPES.join(" "),
  }, 201);
}

/** Autentica al cliente en /token y /revoke: `none` sólo con client_id; `client_secret_post` (o Basic) con secreto. */
function authenticateClient(request: Request, b: Record<string, unknown>): ClientRow | null {
  let clientId = str(b.client_id);
  let secret = str(b.client_secret);
  const basic = request.headers.get("authorization");
  if (basic?.startsWith("Basic ")) {
    try {
      const [id, sec] = Buffer.from(basic.slice(6), "base64").toString().split(":");
      clientId = decodeURIComponent(id);
      secret = decodeURIComponent(sec ?? "");
    } catch { return null; }
  }
  const client = getClient(clientId);
  if (!client) return null;
  if (client.client_secret_hash) {
    if (!secret || !safeEqualHex(sha256(secret), client.client_secret_hash)) return null;
  }
  return client;
}

// --- Autorización (pantalla de consentimiento) ---

type AuthorizeParams = {
  clientId: string; redirectUri: string; state?: string; codeChallenge: string; scope: string; resource: string;
};

type Checked =
  | { ok: true; client: ClientRow & { redirectUris: string[] }; p: AuthorizeParams }
  | { ok: false; res: Response };

function errorRedirect(redirectUri: string, error: string, description: string, state: string | undefined, iss: string): Response {
  const u = new URL(redirectUri);
  u.searchParams.set("error", error);
  u.searchParams.set("error_description", description);
  if (state) u.searchParams.set("state", state);
  u.searchParams.set("iss", iss);
  return redirect(u.toString());
}

/** Valida la petición de autorización. Un client_id o redirect_uri malo NO redirige (spec). */
function checkAuthorize(request: Request, q: Record<string, unknown>): Checked {
  const iss = issuerFor(request);
  const client = getClient(str(q.client_id));
  if (!client) return { ok: false, res: page("No reconocemos esta aplicación", "<p>El enlace no trae un cliente válido (client_id). Vuelve a la aplicación y empieza la conexión de nuevo.</p>", 400) };
  const redirectUri = str(q.redirect_uri) ?? (client.redirectUris.length === 1 ? client.redirectUris[0] : undefined);
  if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
    return { ok: false, res: page("Dirección de regreso inválida", "<p>La dirección de regreso (redirect_uri) no coincide con la que registró la aplicación.</p>", 400) };
  }
  const state = str(q.state);
  const fail = (e: string, d: string): Checked => ({ ok: false, res: errorRedirect(redirectUri, e, d, state, iss) });
  if (q.response_type !== "code") return fail("unsupported_response_type", "Sólo response_type=code.");
  const challenge = str(q.code_challenge);
  if (!challenge || q.code_challenge_method !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) {
    return fail("invalid_request", "PKCE obligatorio: code_challenge con code_challenge_method=S256.");
  }
  const scope = parseScope(q.scope);
  if (!scope) return fail("invalid_scope", `Scopes válidos: ${OAUTH_SCOPES.join(" ")}.`);
  const expected = resourceFor(request);
  const resource = str(q.resource) ? canonicalResource(q.resource as string) : expected;
  if (resource !== expected) return fail("invalid_target", `resource debe ser ${expected}.`);
  return { ok: true, client, p: { clientId: client.client_id, redirectUri, state, codeChallenge: challenge, scope, resource } };
}

const paramsHash = (p: AuthorizeParams) => sha256(JSON.stringify([p.clientId, p.redirectUri, p.state ?? "", p.codeChallenge, p.scope, p.resource]));

export function authorizeGet(request: Request, query: Record<string, unknown>, userEmail: string | null, ip: string): Response {
  if (!checkRateLimit(`oauth-authorize:${ip}`, 60, 60_000).allowed) return page("Demasiadas solicitudes", "<p>Espera un minuto e inténtalo de nuevo.</p>", 429);
  const c = checkAuthorize(request, query);
  if (!c.ok) return c.res;
  if (!userEmail) {
    const url = new URL(request.url);
    return redirect(`/login?next=${encodeURIComponent(url.pathname + url.search)}`);
  }
  // El ticket ata el POST a ESTA sesión y a ESTOS parámetros; un solo uso, 10 min. Con la cookie
  // SameSite=Strict además ningún otro sitio puede mandar el formulario con la sesión.
  const ticket = randomBytes(24).toString("base64url");
  sqlite.prepare("INSERT INTO tokens (token, kind, value, expires_at) VALUES (?, 'oauth-consent', ?, ?)")
    .run(ticket, JSON.stringify({ email: userEmail, h: paramsHash(c.p) }), isoIn(CONSENT_TTL_S));
  const host = new URL(c.p.redirectUri).host;
  const hidden = Object.entries({
    client_id: c.p.clientId, redirect_uri: c.p.redirectUri, state: c.p.state ?? "", code_challenge: c.p.codeChallenge,
    code_challenge_method: "S256", scope: c.p.scope, resource: c.p.resource, response_type: "code", ticket,
  }).map(([k, v]) => `<input type="hidden" name="${k}" value="${esc(v)}">`).join("");
  return page("Conectar con MailMask", `
    <p class="text-fg-muted leading-relaxed"><strong class="text-fg">${esc(c.client.client_name)}</strong> quiere usar tu cuenta de MailMask (<span class="break-all">${esc(userEmail)}</span>).</p>
    <p class="text-sm text-fg-muted mt-4 mb-2">Podrá, en tu nombre:</p>
    <ul class="list-disc pl-5 space-y-1 text-sm text-fg-muted">
      <li>Ver y administrar tus dominios, máscaras, buzones y reglas.</li>
      <li>Enviar correo desde tus dominios.</li>
      <li>Revisar el DNS y generar ligas de pago que tú abres.</li>
    </ul>
    <p class="text-xs text-fg-subtle mt-4">No podrá crear llaves de API. Al permitir te regresamos a <span class="break-all">${esc(host)}</span>. Puedes cortar el acceso cuando quieras desde la aplicación.</p>
    <form method="post" action="/oauth/authorize" class="mt-6 space-y-3">${hidden}
      <button type="submit" name="decision" value="allow" class="btn-primary w-full">Permitir</button>
      <button type="submit" name="decision" value="deny" class="btn-secondary w-full">Cancelar</button>
    </form>`);
}

export function authorizePost(request: Request, body: Record<string, unknown>, userEmail: string | null): Response {
  const c = checkAuthorize(request, body);
  if (!c.ok) return c.res;
  const ticket = str(body.ticket);
  const row = ticket
    ? sqlite.prepare("DELETE FROM tokens WHERE token = ? AND kind = 'oauth-consent' RETURNING value, expires_at").get(ticket) as { value: string; expires_at: string } | undefined
    : undefined;
  const t = row ? JSON.parse(row.value) as { email: string; h: string } : null;
  if (!userEmail || !row || row.expires_at < nowIso() || !t || t.email !== userEmail || t.h !== paramsHash(c.p)) {
    return page("La solicitud caducó", "<p>Vuelve a la aplicación y empieza la conexión de nuevo.</p>", 400);
  }
  const iss = issuerFor(request);
  if (body.decision !== "allow") return errorRedirect(c.p.redirectUri, "access_denied", "La persona canceló.", c.p.state, iss);
  const code = randomBytes(32).toString("base64url");
  sqlite.prepare("DELETE FROM oauth_codes WHERE expires_at < ?").run(nowIso());
  sqlite.prepare(`INSERT INTO oauth_codes (code_hash, client_id, user_email, redirect_uri, code_challenge, scope, resource, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(sha256(code), c.p.clientId, userEmail, c.p.redirectUri, c.p.codeChallenge, c.p.scope, c.p.resource, isoIn(CODE_TTL_S));
  const u = new URL(c.p.redirectUri);
  u.searchParams.set("code", code);
  if (c.p.state) u.searchParams.set("state", c.p.state);
  u.searchParams.set("iss", iss);
  return redirect(u.toString());
}

// --- Tokens ---

function issuePair(clientId: string, email: string, scope: string, resource: string, familyId: string): Response {
  const access = randomToken("mo_");
  const refresh = randomToken("mr_");
  const now = nowIso();
  const ins = sqlite.prepare(`INSERT INTO oauth_tokens (id, token_hash, kind, client_id, user_email, scope, resource, family_id, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  ins.run(crypto.randomUUID(), sha256(access), "access", clientId, email, scope, resource, familyId, isoIn(ACCESS_TTL_S), now);
  ins.run(crypto.randomUUID(), sha256(refresh), "refresh", clientId, email, scope, resource, familyId, isoIn(REFRESH_TTL_S), now);
  return json({ access_token: access, token_type: "Bearer", expires_in: ACCESS_TTL_S, refresh_token: refresh, scope });
}

const revokeFamily = (familyId: string) =>
  sqlite.prepare("UPDATE oauth_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL").run(nowIso(), familyId);

/** ¿La contraseña cambió después de emitir esto? Igual que la cookie: cambiarla corta todo. */
function staleForUser(email: string, createdAt: string): boolean {
  const user = getUser(email);
  if (!user) return true;
  return !!user.passwordChangedAt && user.passwordChangedAt > createdAt;
}

export function tokenEndpoint(request: Request, body: unknown, ip: string): Response {
  if (!checkRateLimit(`oauth-token:${ip}`, 60, 60_000).allowed) return oauthError("too_many_requests", "Demasiadas solicitudes.", 429);
  const b = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const client = authenticateClient(request, b);
  if (!client) return oauthError("invalid_client", "Cliente desconocido o secreto incorrecto.", 401);
  sqlite.prepare("DELETE FROM oauth_tokens WHERE expires_at < ?").run(nowIso());

  if (b.grant_type === "authorization_code") {
    const code = str(b.code);
    const verifier = str(b.code_verifier);
    if (!code || !verifier) return oauthError("invalid_request", "Faltan code y code_verifier.");
    const codeHash = sha256(code);
    const row = sqlite.prepare("SELECT * FROM oauth_codes WHERE code_hash = ?").get(codeHash) as
      { client_id: string; user_email: string; redirect_uri: string; code_challenge: string; scope: string; resource: string; expires_at: string; used_at: string | null } | undefined;
    if (!row) return oauthError("invalid_grant", "Código inválido.");
    // Un solo uso, atómico. Si se presenta dos veces, lo emitido con él se revoca (RFC 6749 §4.1.2).
    const claimed = sqlite.prepare("UPDATE oauth_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL").run(nowIso(), codeHash).changes === 1;
    if (!claimed) {
      revokeFamily(codeHash);
      return oauthError("invalid_grant", "El código ya se usó.");
    }
    if (row.expires_at < nowIso()) return oauthError("invalid_grant", "El código caducó.");
    if (row.client_id !== client.client_id) return oauthError("invalid_grant", "El código es de otro cliente.");
    if (str(b.redirect_uri) !== row.redirect_uri) return oauthError("invalid_grant", "redirect_uri no coincide.");
    if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return oauthError("invalid_grant", "code_verifier inválido.");
    const computed = createHash("sha256").update(verifier).digest("base64url");
    if (!safeEqualHex(computed, row.code_challenge)) return oauthError("invalid_grant", "PKCE no coincide.");
    if (str(b.resource) && canonicalResource(b.resource as string) !== row.resource) return oauthError("invalid_target", "resource no coincide.");
    if (!getUser(row.user_email)) return oauthError("invalid_grant", "La cuenta ya no existe.");
    return issuePair(client.client_id, row.user_email, row.scope, row.resource, codeHash);
  }

  if (b.grant_type === "refresh_token") {
    const token = str(b.refresh_token);
    if (!token?.startsWith("mr_")) return oauthError("invalid_grant", "refresh_token inválido.");
    const row = sqlite.prepare("SELECT * FROM oauth_tokens WHERE token_hash = ? AND kind = 'refresh'").get(sha256(token)) as
      { id: string; client_id: string; user_email: string; scope: string; resource: string; family_id: string; expires_at: string; revoked_at: string | null; created_at: string } | undefined;
    if (!row || row.client_id !== client.client_id) return oauthError("invalid_grant", "refresh_token inválido.");
    // Rotación: el viejo se invalida al usarse. Si llega uno ya invalidado, alguien más lo tiene:
    // se corta la familia entera (el cliente legítimo tendrá que volver a pedir permiso).
    const rotated = sqlite.prepare("UPDATE oauth_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").run(nowIso(), row.id).changes === 1;
    if (!rotated) {
      revokeFamily(row.family_id);
      return oauthError("invalid_grant", "refresh_token ya usado o revocado.");
    }
    if (row.expires_at < nowIso()) return oauthError("invalid_grant", "refresh_token caducó.");
    if (staleForUser(row.user_email, row.created_at)) {
      revokeFamily(row.family_id);
      return oauthError("invalid_grant", "La cuenta cambió de contraseña; vuelve a conectar.");
    }
    if (str(b.resource) && canonicalResource(b.resource as string) !== row.resource) return oauthError("invalid_target", "resource no coincide.");
    let scope = row.scope;
    if (str(b.scope)) {
      const asked = parseScope(b.scope);
      const granted = row.scope.split(" ");
      if (!asked || !asked.split(" ").every((s) => granted.includes(s))) return oauthError("invalid_scope", "No se puede ampliar el scope.");
      scope = asked;
    }
    return issuePair(client.client_id, row.user_email, scope, row.resource, row.family_id);
  }

  return oauthError("unsupported_grant_type", "grant_type: authorization_code o refresh_token.");
}

/** RFC 7009: siempre 200 (no revela si el token existía). Un refresh revocado se lleva su familia. */
export function revokeEndpoint(request: Request, body: unknown, ip: string): Response {
  if (!checkRateLimit(`oauth-revoke:${ip}`, 60, 60_000).allowed) return oauthError("too_many_requests", "Demasiadas solicitudes.", 429);
  const b = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const client = authenticateClient(request, b);
  if (!client) return oauthError("invalid_client", "Cliente desconocido o secreto incorrecto.", 401);
  const token = str(b.token);
  if (!token) return oauthError("invalid_request", "Falta token.");
  const row = sqlite.prepare("SELECT id, kind, client_id, family_id FROM oauth_tokens WHERE token_hash = ?").get(sha256(token)) as
    { id: string; kind: string; client_id: string; family_id: string } | undefined;
  if (row && row.client_id === client.client_id) {
    if (row.kind === "refresh") revokeFamily(row.family_id);
    else sqlite.prepare("UPDATE oauth_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").run(nowIso(), row.id);
  }
  return new Response(null, { status: 200, headers: { "cache-control": "no-store", "access-control-allow-origin": "*" } });
}

/** Valida un `mo_…` sin gastar rate limit. Devuelve el correo y el id del token, o null. */
export function verifyOAuthAccessToken(token: string): { email: string; tokenId: string } | null {
  if (!token.startsWith("mo_")) return null;
  const row = sqlite.prepare("SELECT id, user_email, expires_at, revoked_at, created_at FROM oauth_tokens WHERE token_hash = ? AND kind = 'access'").get(sha256(token)) as
    { id: string; user_email: string; expires_at: string; revoked_at: string | null; created_at: string } | undefined;
  if (!row || row.revoked_at || row.expires_at < nowIso()) return null;
  if (staleForUser(row.user_email, row.created_at)) return null;
  return { email: row.user_email, tokenId: row.id };
}

// --- HTML ---

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}

function page(title: string, inner: string, status = 200): Response {
  const html = `<!DOCTYPE html>
<html lang="es-MX">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex">
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <title>${esc(title)} | MailMask</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,700;12..96,800&family=Inter:wght@400;500;600;700&display=swap" />
  <link rel="stylesheet" href="/css/styles.css">
  <script src="/js/theme.js"></script>
</head>
<body class="site bg-bg text-fg antialiased min-h-screen flex items-center justify-center px-4 py-10">
  <div class="w-full max-w-sm card p-7 sm:p-9">
    <div class="text-center mb-6">
      <a href="/" class="inline-block">
        <svg class="w-12 h-12 mx-auto" viewBox="0 0 80 80" fill="none" aria-hidden="true"><ellipse cx="40" cy="42" rx="28" ry="24" fill="rgb(var(--mascara-sombra))"/><ellipse cx="40" cy="38" rx="28" ry="22" fill="rgb(var(--mascara))"/><ellipse cx="28" cy="36" rx="8" ry="6.3" fill="#ffffff" stroke="rgb(var(--gold))" stroke-width="1.8"/><ellipse cx="52" cy="36" rx="8" ry="6.3" fill="#ffffff" stroke="rgb(var(--gold))" stroke-width="1.8"/><circle cx="28.6" cy="36.4" r="5.2" fill="#a97142"/><circle cx="52.6" cy="36.4" r="5.2" fill="#a97142"/><circle cx="28.6" cy="36.4" r="2.6" fill="#3b2412"/><circle cx="52.6" cy="36.4" r="2.6" fill="#3b2412"/><path d="M40 18 L40 26" stroke="rgb(var(--gold))" stroke-width="2" stroke-linecap="round"/><path d="M36 19 L40 26 L44 19" stroke="rgb(var(--gold))" stroke-width="1.5" fill="none" stroke-linecap="round"/></svg>
      </a>
      <h1 class="text-2xl font-semibold tracking-tight mt-4">${esc(title)}</h1>
    </div>
    ${inner}
  </div>
</body>
</html>`;
  return new Response(html, { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}
