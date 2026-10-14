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
  /**
   * Valida y aplica todos los RRSets en un solo cambio (UPSERT). Lanza con mensaje para el
   * usuario. Devuelve lo que de verdad escribió (ya validado), que es lo que se anota.
   */
  apply(records: RRSet[]): Promise<RRSet[] | void>;
  /** Lo que hay hoy en ese (nombre, tipo), o null. */
  current(name: string, type: string): RRSet | null;
};

export type PublishInput = {
  email: string;
  redirectUri: string;
  domain: string;
  websiteId: string;
  placement: "apex" | "subdomain";
  /** Dominio de MailMask: con él se anota la publicación para poder quitarla. */
  domainId?: string;
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
  // Lo que había ANTES, tomado antes de escribir: es lo que restaura `unpublishSite`.
  const before = records.map((r) => dns.current(r.name, r.type));
  let written: RRSet[];
  try {
    written = (await dns.apply(records)) || records;
  } catch (err) {
    // Sin medias conexiones: si lo dimos de alta nosotros y el DNS no entró, se quita.
    if (created) {
      await ebFetch(email, redirectUri, "/domains", { method: "DELETE", body: JSON.stringify({ domainId: ebDomain.id }) })
        .catch((e) => log("warn", "easybits", "No se pudo deshacer el dominio en EasyBits", { domain, error: String(e) }));
    }
    throw err;
  }

  // Se verifica SIEMPRE, aunque EasyBits ya lo diera por verificado: su verify es lo que
  // registra el host en el borde (antes de oct-2026 lo hacía en Fly, que ya no existe).
  let verified = false;
  for (const wait of input.verifyDelays ?? [0, 3000, 6000, 10_000]) {
    if (wait) await new Promise((r) => setTimeout(r, wait));
    try {
      const v = await ebFetch<{ domain: EasyBitsDomain }>(email, redirectUri, `/domains/${ebDomain.id}/verify`, { method: "POST" });
      if (v.domain?.verified) { verified = true; break; }
    } catch (err) {
      log("info", "easybits", "Verificación de EasyBits todavía no pasa", { domain, error: String(err) });
    }
  }

  if (input.domainId) {
    savePublication({
      domainId: input.domainId, ownerEmail: email, ebDomainId: ebDomain.id, ebDomainCreated: created,
      websiteId: site.id, placement, url, written, before,
    });
  }

  if (verified && placement === "apex") {
    await ebFetch(email, redirectUri, `/domains/${ebDomain.id}/apex`, { method: "POST", body: JSON.stringify({ websiteId: site.id }) });
  }
  return { dryRun: false as const, url, site, records, verified, easybitsDomainId: ebDomain.id };
}

// --- Bitácora de publicaciones (para deshacer) ---

export type Publication = {
  domainId: string;
  ownerEmail: string;
  ebDomainId: string;
  ebDomainCreated: boolean;
  websiteId: string;
  placement: "apex" | "subdomain";
  url: string;
  /** Lo que escribimos, por (nombre, tipo). */
  records: RRSet[];
  /** Lo que había antes en cada `nombre|tipo` de `records`; null = nada. */
  previous: Record<string, RRSet | null>;
  createdAt: string;
  updatedAt: string;
};

const keyOf = (r: { name: string; type: string }) => `${r.name.toLowerCase()}|${r.type.toUpperCase()}`;

type PubRow = {
  domain_id: string; owner_email: string; eb_domain_id: string; eb_domain_created: number; website_id: string;
  placement: string; url: string; records: string; previous: string; created_at: string; updated_at: string;
};

export function getPublication(domainId: string): Publication | null {
  const r = sqlite.prepare(`SELECT * FROM easybits_publications WHERE domain_id = ?`).get(domainId) as PubRow | undefined;
  if (!r) return null;
  return {
    domainId: r.domain_id, ownerEmail: r.owner_email, ebDomainId: r.eb_domain_id, ebDomainCreated: !!r.eb_domain_created,
    websiteId: r.website_id, placement: r.placement === "apex" ? "apex" : "subdomain", url: r.url,
    records: JSON.parse(r.records), previous: JSON.parse(r.previous), createdAt: r.created_at, updatedAt: r.updated_at,
  };
}

/**
 * Anota la publicación. Al re-publicar se conserva el `previous` ORIGINAL de cada nombre ya
 * anotado (lo de hoy ahí ya es nuestro) y los registros viejos que esta vez no se tocaron
 * (p. ej. la raíz al pasar de raíz a subdominio) siguen en la lista, porque siguen escritos.
 */
function savePublication(p: {
  domainId: string; ownerEmail: string; ebDomainId: string; ebDomainCreated: boolean; websiteId: string;
  placement: "apex" | "subdomain"; url: string; written: RRSet[]; before: (RRSet | null)[];
}) {
  const old = getPublication(p.domainId);
  const records = new Map<string, RRSet>((old?.records ?? []).map((r) => [keyOf(r), r]));
  const previous: Record<string, RRSet | null> = { ...(old?.previous ?? {}) };
  p.written.forEach((r, i) => {
    const k = keyOf(r);
    records.set(k, r);
    if (!(k in previous)) previous[k] = p.before[i] ?? null;
  });
  const now = new Date().toISOString();
  // Si el dominio de EasyBits ya lo habíamos creado nosotros en la primera, sigue siendo nuestro.
  const created = old && old.ebDomainId === p.ebDomainId ? old.ebDomainCreated : p.ebDomainCreated;
  sqlite.prepare(`
    INSERT INTO easybits_publications (domain_id, owner_email, eb_domain_id, eb_domain_created, website_id, placement, url, records, previous, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (domain_id) DO UPDATE SET owner_email = excluded.owner_email, eb_domain_id = excluded.eb_domain_id,
      eb_domain_created = excluded.eb_domain_created, website_id = excluded.website_id, placement = excluded.placement,
      url = excluded.url, records = excluded.records, previous = excluded.previous, updated_at = excluded.updated_at
  `).run(p.domainId, p.ownerEmail, p.ebDomainId, created ? 1 : 0, p.websiteId, p.placement, p.url,
    JSON.stringify([...records.values()]), JSON.stringify(previous), old?.createdAt ?? now, now);
}

/** Mismo RRSet para fines de "¿sigue siendo el nuestro?": tipo y valores, sin TTL ni punto final. */
function sameRecord(a: RRSet | null, b: RRSet | null): boolean {
  if (!a || !b) return a === b;
  const norm = (r: RRSet) => r.values.map((v) => v.trim().toLowerCase().replace(/\.$/, "")).sort().join("\n");
  return a.type.toUpperCase() === b.type.toUpperCase() && norm(a) === norm(b);
}

export type DnsRestoreOps = {
  current(name: string, type: string): RRSet | null;
  /** Aplica todos los cambios en UN solo lote de Route 53. Lanza con mensaje para el usuario. */
  apply(changes: { action: "UPSERT" | "DELETE"; rrset: RRSet }[]): Promise<void>;
};

export type UnpublishResult = {
  ok: true;
  nothing?: true;
  /** Volvió a lo que había antes (o ya estaba así). */
  restored: { name: string; type: string; to: RRSet | null }[];
  /** No era ya lo que escribimos: el usuario lo cambió después y se deja como está. */
  skipped: { name: string; type: string; current: RRSet | null }[];
  easybits: { apexCleared: boolean; domainDeleted: boolean; error?: string };
};

/**
 * Deshace `publishSite`: restaura el DNS anotado en un solo cambio y limpia EasyBits (quita
 * la raíz y, si el dominio lo dimos de alta nosotros, lo borra). Idempotente: sin fila,
 * no hay nada que hacer. Si EasyBits falla (no por desconexión), la fila se queda para
 * reintentar; el DNS ya restaurado sale como `restored` la segunda vez.
 */
export async function unpublishSite(domainId: string, redirectUri: string, dns: DnsRestoreOps): Promise<UnpublishResult> {
  const pub = getPublication(domainId);
  const easybits: UnpublishResult["easybits"] = { apexCleared: false, domainDeleted: false };
  if (!pub) return { ok: true, nothing: true, restored: [], skipped: [], easybits };

  const restored: UnpublishResult["restored"] = [];
  const skipped: UnpublishResult["skipped"] = [];
  const changes: { action: "UPSERT" | "DELETE"; rrset: RRSet }[] = [];
  for (const ours of pub.records) {
    const prev = pub.previous[keyOf(ours)] ?? null;
    const cur = dns.current(ours.name, ours.type);
    if (sameRecord(cur, ours)) {
      // DELETE exige el RRSet exacto que hay hoy (TTL incluido).
      changes.push(prev ? { action: "UPSERT", rrset: prev } : { action: "DELETE", rrset: cur! });
      restored.push({ name: ours.name, type: ours.type, to: prev });
    } else if (sameRecord(cur, prev)) {
      restored.push({ name: ours.name, type: ours.type, to: prev });
    } else {
      skipped.push({ name: ours.name, type: ours.type, current: cur });
    }
  }
  if (changes.length) await dns.apply(changes);

  const ebErrors: string[] = [];
  try {
    if (pub.placement === "apex") {
      await ebFetch(pub.ownerEmail, redirectUri, `/domains/${pub.ebDomainId}/apex`, { method: "POST", body: JSON.stringify({ websiteId: null }) })
        .then(() => { easybits.apexCleared = true; })
        .catch((e) => { if (e instanceof EasyBitsDisconnected) throw e; ebErrors.push(String(e instanceof Error ? e.message : e)); });
    }
    if (pub.ebDomainCreated) {
      await ebFetch(pub.ownerEmail, redirectUri, "/domains", { method: "DELETE", body: JSON.stringify({ domainId: pub.ebDomainId }) })
        .then(() => { easybits.domainDeleted = true; })
        .catch((e) => {
          if (e instanceof EasyBitsDisconnected) throw e;
          // Ya no existe: lo que queríamos.
          if (/not found|no encontrado|404/i.test(String(e))) easybits.domainDeleted = true;
          else ebErrors.push(String(e instanceof Error ? e.message : e));
        });
    }
  } catch (e) {
    // Sin conexión no hay forma de limpiar EasyBits; el DNS ya volvió, que es lo que sirve
    // el dominio. Se reporta y se cierra la fila.
    easybits.error = e instanceof Error ? e.message : String(e);
    log("warn", "easybits", "Sitio quitado sin limpiar EasyBits (desconectado)", { domainId, error: easybits.error });
  }
  if (ebErrors.length) {
    log("warn", "easybits", "No se pudo limpiar EasyBits al quitar el sitio", { domainId, errors: ebErrors });
    throw new Error(`El DNS ya volvió a como estaba, pero EasyBits no respondió: ${ebErrors.join("; ")}. Intenta de nuevo.`);
  }
  sqlite.prepare(`DELETE FROM easybits_publications WHERE domain_id = ?`).run(domainId);
  return { ok: true, restored, skipped, easybits };
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
