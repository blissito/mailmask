// Conexión con EasyBits (Sitios: «Describe tu sitio y un agente lo construye») por OAuth 2.1,
// para publicar un sitio en el dominio del cliente sin que copie un solo registro.
//
// MailMask es cliente OAuth de EasyBits: se registra solo por DCR, pide el code con PKCE
// S256 y guarda los tokens cifrados. Con ellos lista los sitios, da de alta el dominio en
// EasyBits y escribe en NUESTRA zona los registros que EasyBits pide. El dominio en EasyBits
// es por cuenta, no por sitio: verificado una vez, cada sitio responde en `<slug>.<dominio>`
// y la raíz se asigna aparte (`/apex`).
import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from "node:crypto";
import { sqlite } from "./pg.js";
import { log } from "./logger.js";
import type { RRSet } from "./dns-records.js";

export const EASYBITS_ORIGIN = (process.env.EASYBITS_ORIGIN ?? "https://www.easybits.cloud").replace(/\/+$/, "");

/**
 * El borde de EasyBits desde que salió de Fly (8-oct-2026): la caja de sandbox-host, con TLS
 * bajo demanda. El panel viejo de EasyBits pedía `easybits.fly.dev` / `66.241.125.82`, que ya
 * no existen; si EasyBits vuelve a mudarse, cambia aquí.
 */
export const EASYBITS_EDGE = {
  v4: "54.38.94.14",
  cnameTarget: "cname.sandboxes.easybits.cloud",
} as const;

// --- Cifrado de tokens (misma receta que el código EPP en domain-transfer.ts) ---

function key(): Buffer {
  const explicit = process.env.EASYBITS_LINK_KEY;
  if (explicit) return createHash("sha256").update(explicit).digest();
  const jwt = process.env.JWT_SECRET;
  if (!jwt) throw new Error("Falta EASYBITS_LINK_KEY (o JWT_SECRET) para cifrar los tokens de EasyBits");
  return Buffer.from(hkdfSync("sha256", jwt, "mailmask", "easybits-link", 32));
}

export function seal(text: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key(), iv);
  const body = Buffer.concat([c.update(text, "utf8"), c.final()]);
  return [iv, c.getAuthTag(), body].map((b) => b.toString("base64")).join(".");
}

export function unseal(box: string): string | null {
  try {
    const [iv, tag, body] = box.split(".").map((p) => Buffer.from(p, "base64"));
    const d = createDecipheriv("aes-256-gcm", key(), iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(body), d.final()]).toString("utf8");
  } catch {
    return null;
  }
}

// --- PKCE ---

export function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

// --- Cliente OAuth (DCR perezoso) ---

type OAuthClient = { clientId: string; clientSecret: string | null };

export async function getOAuthClient(redirectUri: string): Promise<OAuthClient> {
  const row = sqlite.prepare(`SELECT client_id, client_secret FROM easybits_oauth_clients WHERE redirect_uri = ?`)
    .get(redirectUri) as { client_id: string; client_secret: string | null } | undefined;
  if (row) return { clientId: row.client_id, clientSecret: row.client_secret ? unseal(row.client_secret) : null };

  const res = await fetch(`${EASYBITS_ORIGIN}/oauth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "MailMask", redirect_uris: [redirectUri], token_endpoint_auth_method: "client_secret_post" }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`EasyBits no registró el cliente OAuth (HTTP ${res.status})`);
  const data = await res.json() as { client_id: string; client_secret?: string };
  sqlite.prepare(`INSERT OR REPLACE INTO easybits_oauth_clients (redirect_uri, client_id, client_secret, created_at) VALUES (?, ?, ?, ?)`)
    .run(redirectUri, data.client_id, data.client_secret ? seal(data.client_secret) : null, new Date().toISOString());
  return { clientId: data.client_id, clientSecret: data.client_secret ?? null };
}

export function authorizeUrl(client: OAuthClient, redirectUri: string, state: string, challenge: string): string {
  const q = new URLSearchParams({
    response_type: "code",
    client_id: client.clientId,
    redirect_uri: redirectUri,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state,
    scope: "mcp",
    resource: EASYBITS_ORIGIN,
  });
  return `${EASYBITS_ORIGIN}/oauth/authorize?${q}`;
}

type TokenResponse = { access_token: string; refresh_token?: string; expires_in?: number };

async function tokenRequest(client: OAuthClient, params: Record<string, string>): Promise<TokenResponse> {
  const form = new URLSearchParams({ ...params, client_id: client.clientId, resource: EASYBITS_ORIGIN });
  if (client.clientSecret) form.set("client_secret", client.clientSecret);
  const res = await fetch(`${EASYBITS_ORIGIN}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form,
    signal: AbortSignal.timeout(10_000),
  });
  const data = await res.json().catch(() => ({})) as TokenResponse & { error?: string };
  if (!res.ok || !data.access_token) throw new Error(`EasyBits rechazó el token: ${data.error ?? res.status}`);
  return data;
}

function saveTokens(email: string, t: TokenResponse, previousRefresh?: string | null) {
  const refresh = t.refresh_token ?? previousRefresh ?? null;
  sqlite.prepare(`
    INSERT INTO easybits_links (user_email, access_token, refresh_token, expires_at, updated_at) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT (user_email) DO UPDATE SET access_token = excluded.access_token, refresh_token = excluded.refresh_token,
      expires_at = excluded.expires_at, updated_at = excluded.updated_at
  `).run(email, seal(t.access_token), refresh ? seal(refresh) : null, Date.now() + (t.expires_in ?? 3600) * 1000, new Date().toISOString());
}

export async function exchangeCode(email: string, redirectUri: string, code: string, verifier: string): Promise<void> {
  const client = await getOAuthClient(redirectUri);
  const t = await tokenRequest(client, { grant_type: "authorization_code", code, redirect_uri: redirectUri, code_verifier: verifier });
  saveTokens(email, t);
}

export function isConnected(email: string): boolean {
  return !!sqlite.prepare(`SELECT 1 FROM easybits_links WHERE user_email = ?`).get(email);
}

export class EasyBitsDisconnected extends Error {}

/** Token vigente; refresca si vence en menos de un minuto. Un refresh rechazado desconecta. */
async function accessToken(email: string, redirectUri: string): Promise<string> {
  const row = sqlite.prepare(`SELECT access_token, refresh_token, expires_at FROM easybits_links WHERE user_email = ?`)
    .get(email) as { access_token: string; refresh_token: string | null; expires_at: number } | undefined;
  if (!row) throw new EasyBitsDisconnected("No has conectado tu cuenta de EasyBits.");
  if (row.expires_at - Date.now() > 60_000) {
    const tok = unseal(row.access_token);
    if (tok) return tok;
  }
  const refresh = row.refresh_token ? unseal(row.refresh_token) : null;
  if (!refresh) { disconnect(email); throw new EasyBitsDisconnected("La conexión con EasyBits venció; vuelve a conectarla."); }
  try {
    const t = await tokenRequest(await getOAuthClient(redirectUri), { grant_type: "refresh_token", refresh_token: refresh });
    saveTokens(email, t, refresh);
    return t.access_token;
  } catch (err) {
    log("warn", "easybits", "Refresh de EasyBits rechazado", { email, error: String(err) });
    disconnect(email);
    throw new EasyBitsDisconnected("La conexión con EasyBits venció; vuelve a conectarla.");
  }
}

export function disconnect(email: string): void {
  sqlite.prepare(`DELETE FROM easybits_links WHERE user_email = ?`).run(email);
}

/** Llama a la API v2 de EasyBits como el usuario. Un error sale con el mensaje de EasyBits. */
export async function ebFetch<T>(email: string, redirectUri: string, path: string, init: RequestInit = {}): Promise<T> {
  const token = await accessToken(email, redirectUri);
  const res = await fetch(`${EASYBITS_ORIGIN}/api/v2${path}`, {
    ...init,
    headers: { authorization: `Bearer ${token}`, ...(init.body ? { "content-type": "application/json" } : {}), ...(init.headers ?? {}) },
    signal: AbortSignal.timeout(15_000),
  });
  const data = await res.json().catch(() => ({})) as T & { error?: string };
  if (res.status === 401) { disconnect(email); throw new EasyBitsDisconnected("EasyBits ya no acepta la conexión; vuelve a conectarla."); }
  if (!res.ok) throw new Error(data.error ?? `EasyBits respondió ${res.status}`);
  return data;
}

// --- Sitios y dominio ---

export type EasyBitsSite = { id: string; name: string; slug: string; status: string; url: string; subdomainUrl?: string | null };
export type EasyBitsDomain = { id: string; domain: string; txtToken: string; verified: boolean; apexWebsite?: { id: string; slug: string } | null };

export async function listSites(email: string, redirectUri: string): Promise<EasyBitsSite[]> {
  const r = await ebFetch<{ items: EasyBitsSite[] }>(email, redirectUri, "/websites?limit=100");
  return r.items ?? [];
}

/** Los registros que pide EasyBits para su dominio; con `apex`, también raíz y www. */
export function easybitsRecords(domain: string, txtToken: string, opts: { apex: boolean; slug?: string }): RRSet[] {
  const d = domain.toLowerCase();
  const out: RRSet[] = [
    { name: `_easybits-verify.${d}`, type: "TXT", ttl: 300, values: [`"${txtToken}"`] },
    { name: `*.${d}`, type: "CNAME", ttl: 300, values: [EASYBITS_EDGE.cnameTarget] },
  ];
  // El comodín no gana si el nombre ya tiene registro propio: se escribe explícito también.
  if (opts.slug && !opts.apex) out.push({ name: `${opts.slug}.${d}`, type: "CNAME", ttl: 300, values: [EASYBITS_EDGE.cnameTarget] });
  if (opts.apex) {
    out.push(
      { name: d, type: "A", ttl: 300, values: [EASYBITS_EDGE.v4] },
      { name: `www.${d}`, type: "CNAME", ttl: 300, values: [EASYBITS_EDGE.cnameTarget] },
    );
  }
  return out;
}

/** El dominio en EasyBits: lo busca y, si no está, lo da de alta. `created` sirve para deshacer. */
export async function ensureEasyBitsDomain(email: string, redirectUri: string, domain: string): Promise<{ domain: EasyBitsDomain; created: boolean }> {
  const list = await ebFetch<{ domains: EasyBitsDomain[] }>(email, redirectUri, "/domains");
  const found = (list.domains ?? []).find((x) => x.domain.toLowerCase() === domain.toLowerCase());
  if (found) return { domain: found, created: false };
  const r = await ebFetch<{ domain: EasyBitsDomain }>(email, redirectUri, "/domains", { method: "POST", body: JSON.stringify({ domain }) });
  return { domain: r.domain, created: true };
}

// --- Publicar un sitio en el dominio ---

export type DnsOps = {
  /** Valida y aplica todos los RRSets en un solo cambio (UPSERT). Lanza con mensaje para el usuario. */
  apply(records: RRSet[]): Promise<void>;
  /** Lo que hay hoy en ese (nombre, tipo), o null. */
  current(name: string, type: string): RRSet | null;
};

export type PublishInput = {
  email: string;
  redirectUri: string;
  domain: string;
  websiteId: string;
  placement: "apex" | "subdomain";
  dryRun?: boolean;
  /** Esperas entre intentos de verificación (ms); en pruebas, 0. */
  verifyDelays?: number[];
};

export async function publishSite(input: PublishInput, dns: DnsOps) {
  const { email, redirectUri, domain, placement } = input;
  const sites = await listSites(email, redirectUri);
  const site = sites.find((s) => s.id === input.websiteId);
  if (!site) throw new Error("Ese sitio no está en tu cuenta de EasyBits.");
  const url = placement === "apex" ? `https://${domain}` : `https://${site.slug}.${domain}`;

  if (input.dryRun) {
    // Sin tocar EasyBits: el TXT real sale al aplicar; aquí sólo se enseña su forma.
    const records = easybitsRecords(domain, "easybits-verify-…", { apex: placement === "apex", slug: site.slug });
    return { dryRun: true as const, url, site, records, current: records.map((r) => dns.current(r.name, r.type)) };
  }

  const { domain: ebDomain, created } = await ensureEasyBitsDomain(email, redirectUri, domain);
  const records = easybitsRecords(domain, ebDomain.txtToken, { apex: placement === "apex", slug: site.slug });
  try {
    await dns.apply(records);
  } catch (err) {
    // Sin medias conexiones: si lo dimos de alta nosotros y el DNS no entró, se quita.
    if (created) {
      await ebFetch(email, redirectUri, "/domains", { method: "DELETE", body: JSON.stringify({ domainId: ebDomain.id }) })
        .catch((e) => log("warn", "easybits", "No se pudo deshacer el dominio en EasyBits", { domain, error: String(e) }));
    }
    throw err;
  }

  let verified = ebDomain.verified;
  for (const wait of verified ? [] : input.verifyDelays ?? [3000, 6000, 10_000]) {
    if (wait) await new Promise((r) => setTimeout(r, wait));
    try {
      const v = await ebFetch<{ domain: EasyBitsDomain }>(email, redirectUri, `/domains/${ebDomain.id}/verify`, { method: "POST" });
      if (v.domain?.verified) { verified = true; break; }
    } catch (err) {
      log("info", "easybits", "Verificación de EasyBits todavía no pasa", { domain, error: String(err) });
    }
  }

  if (verified && placement === "apex") {
    await ebFetch(email, redirectUri, `/domains/${ebDomain.id}/apex`, { method: "POST", body: JSON.stringify({ websiteId: site.id }) });
  }
  return { dryRun: false as const, url, site, records, verified, easybitsDomainId: ebDomain.id };
}

/** Reintento manual desde la UI: verifica y, si es raíz, asigna el sitio. */
export async function retryVerify(email: string, redirectUri: string, domain: string, apexWebsiteId?: string) {
  const { domain: d } = await ensureEasyBitsDomain(email, redirectUri, domain);
  const v = await ebFetch<{ domain: EasyBitsDomain }>(email, redirectUri, `/domains/${d.id}/verify`, { method: "POST" });
  if (v.domain?.verified && apexWebsiteId) {
    await ebFetch(email, redirectUri, `/domains/${d.id}/apex`, { method: "POST", body: JSON.stringify({ websiteId: apexWebsiteId }) });
  }
  return { verified: !!v.domain?.verified };
}
