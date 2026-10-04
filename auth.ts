import { getUser, getUserByApiKey, type User } from "./db.js";
import { checkRateLimit } from "./rate-limit.js";
import { verifyOAuthAccessToken } from "./oauth.js";

const encoder = new TextEncoder();
const JWT_SECRET = process.env.JWT_SECRET ?? (() => { throw new Error("JWT_SECRET required"); })();
const JWT_EXPIRY = 3600; // 1 hour

// --- Password hashing (PBKDF2 via Web Crypto) ---

const PBKDF2_ITERATIONS = 600_000;
const LEGACY_ITERATIONS = 1_000;

async function deriveKey(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
    key,
    256,
  );
  return new Uint8Array(bits);
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await deriveKey(password, salt, PBKDF2_ITERATIONS);
  return `${toHex(salt)}:${toHex(hash)}`;
}

export async function verifyPassword(password: string, stored: string): Promise<{ valid: boolean; needsRehash: boolean }> {
  const [saltHex, hashHex] = stored.split(":");
  const salt = fromHex(saltHex);
  const expected = fromHex(hashHex);

  // Try current iterations first
  const computed = await deriveKey(password, salt, PBKDF2_ITERATIONS);
  if (computed.byteLength === expected.byteLength && timingSafeEqual(computed, expected)) {
    return { valid: true, needsRehash: false };
  }

  // Fall back to legacy iterations for existing passwords
  const legacy = await deriveKey(password, salt, LEGACY_ITERATIONS);
  if (legacy.byteLength === expected.byteLength && timingSafeEqual(legacy, expected)) {
    return { valid: true, needsRehash: true };
  }

  return { valid: false, needsRehash: false };
}

// --- JWT (HMAC-SHA256 via Web Crypto) ---

export async function signJwt(payload: Record<string, unknown>, ttlSeconds: number = JWT_EXPIRY): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const body = { ...payload, iat: now, exp: now + ttlSeconds };

  const headerB64 = b64url(JSON.stringify(header));
  const bodyB64 = b64url(JSON.stringify(body));
  const data = `${headerB64}.${bodyB64}`;

  const key = await getSigningKey();
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  const sigB64 = b64url(sig);

  return `${data}.${sigB64}`;
}

export async function verifyJwt(token: string): Promise<Record<string, unknown> | null> {
  try {
    const [headerB64, bodyB64, sigB64] = token.split(".");
    if (!headerB64 || !bodyB64 || !sigB64) return null;

    const key = await getSigningKey();
    const data = `${headerB64}.${bodyB64}`;
    const sig = b64urlDecode(sigB64);

    const valid = await crypto.subtle.verify("HMAC", key, sig as BufferSource, encoder.encode(data));
    if (!valid) return null;

    const body = JSON.parse(atob(bodyB64.replace(/-/g, "+").replace(/_/g, "/")));
    if (body.exp && body.exp < Math.floor(Date.now() / 1000)) return null;

    return body;
  } catch {
    return null;
  }
}

// --- Cookie helpers ---

const IS_PROD = process.env.FLY_APP_NAME !== undefined;
const SECURE_FLAG = IS_PROD ? " Secure;" : "";

export function makeAuthCookie(token: string): string {
  return `token=${token}; HttpOnly;${SECURE_FLAG} SameSite=Strict; Path=/; Max-Age=${JWT_EXPIRY}`;
}

export function clearAuthCookie(): string {
  return `token=; HttpOnly;${SECURE_FLAG} SameSite=Strict; Path=/; Max-Age=0`;
}

export function parseCookies(header: string | null): Record<string, string> {
  if (!header) return {};
  const cookies: Record<string, string> = {};
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k) cookies[k.trim()] = v.join("=").trim();
  }
  return cookies;
}

// --- Auth middleware helper ---

// --- Turn token del asistente (`mt_`) ---
//
// Credencial de CORTA vida (5 min) que MailMask le da a Ghosty en cada turno del
// asistente; Ghosty la pone en el `Authorization` de su cliente MCP hacia `/mcp`.
// Es un JWT con `aud: "assistant"` firmado con el mismo secreto que la sesión, así que
// hay que impedir los dos cruces: un `mt_` no sirve como cookie (se rechaza su `aud`
// abajo) y una cookie de sesión no sirve como `mt_` (exige el `aud`).
export const TURN_TOKEN_TTL = 300;
const TURN_AUDIENCE = "assistant";

export async function issueTurnToken(email: string): Promise<string> {
  const jwt = await signJwt({ email, aud: TURN_AUDIENCE, jti: crypto.randomUUID() }, TURN_TOKEN_TTL);
  return `mt_${jwt}`;
}

/** Valida un `mt_…` sin gastar rate limit. Devuelve el correo del usuario o null. */
export async function verifyTurnToken(token: string): Promise<string | null> {
  if (!token.startsWith("mt_")) return null;
  const payload = await verifyJwt(token.slice(3));
  if (!payload || payload.aud !== TURN_AUDIENCE || typeof payload.email !== "string") return null;
  const user = await getUser(payload.email);
  if (!user) return null;
  if (user.passwordChangedAt && payload.iat) {
    const changedAtSec = Math.floor(new Date(user.passwordChangedAt).getTime() / 1000);
    if ((payload.iat as number) < changedAtSec) return null;
  }
  return user.email;
}

/**
 * Por dónde llegó la identidad. `turn` = el asistente actuando con un `mt_`: las rutas
 * destructivas lo detienen y piden confirmación al usuario (`agent-actions.ts`).
 */
export type AuthVia = "session" | "apikey" | "turn";
export type AuthUser = { email: string; via: AuthVia };

export async function getAuthUser(request: Request): Promise<AuthUser | null> {
  const authHeader = request.headers.get("authorization");
  if (authHeader?.startsWith("Bearer mt_")) {
    const email = await verifyTurnToken(authHeader.slice(7));
    if (!email) return null;
    // Por usuario y no por token: cada turno acuña uno nuevo.
    const rl = checkRateLimit(`turn:${email}`, 120, 60_000);
    if (!rl.allowed) return null;
    return { email, via: "turn" };
  }
  // `mo_` = access token OAuth de un cliente MCP (`oauth.ts`): mismo alcance que una `mk_`
  // (main.ts le niega fabricar llaves y el admin) y el mismo tope de 60/min, por token.
  if (authHeader?.startsWith("Bearer mo_")) {
    const t = verifyOAuthAccessToken(authHeader.slice(7));
    if (!t) return null;
    const rl = checkRateLimit(`oauth:${t.tokenId}`, 60, 60_000);
    if (!rl.allowed) return null;
    return { email: t.email, via: "apikey" };
  }
  // Try Bearer token (API key) first
  if (authHeader?.startsWith("Bearer mk_")) {
    const key = authHeader.slice(7);
    const keyPrefix = key.slice(0, 11);
    // Rate limit per API key: 60 requests per minute
    const rl = checkRateLimit(`apikey:${keyPrefix}`, 60, 60_000);
    if (!rl.allowed) return null;
    const user = await getUserByApiKey(key);
    if (!user) return null;
    // La API es para todas las cuentas, gratis incluidas (7-sep-2026): lo que se vende
    // es el dominio activado, y cada endpoint mira los derechos de SU dominio.
    return { email: user.email, via: "apikey" };
  }

  // Fall back to cookie auth
  const cookies = parseCookies(request.headers.get("cookie"));
  const token = cookies["token"];
  if (!token) return null;

  const payload = await verifyJwt(token);
  if (!payload || !payload.email) return null;
  // Un turn token puesto como cookie no es una sesión.
  if (payload.aud !== undefined) return null;

  const user = await getUser(payload.email as string);
  if (!user) return null;

  // Reject tokens issued before password change (C4: JWT revocation)
  if (user.passwordChangedAt && payload.iat) {
    const changedAtSec = Math.floor(new Date(user.passwordChangedAt).getTime() / 1000);
    if ((payload.iat as number) < changedAtSec) return null;
  }

  return { email: user.email, via: "session" };
}

// --- CSRF (double-submit cookie) ---

export function generateCsrfToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

export function makeCsrfCookie(token: string): string {
  return `csrf_token=${token};${SECURE_FLAG} SameSite=Strict; Path=/; Max-Age=${JWT_EXPIRY}`;
}

// --- Internal helpers ---

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

function toHex(buf: Uint8Array): string {
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  const bytes = hex.match(/.{2}/g)?.map((h) => parseInt(h, 16)) ?? [];
  return new Uint8Array(bytes);
}

let _signingKey: CryptoKey | null = null;
async function getSigningKey(): Promise<CryptoKey> {
  if (!_signingKey) {
    _signingKey = await crypto.subtle.importKey(
      "raw",
      encoder.encode(JWT_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"],
    );
  }
  return _signingKey;
}

function b64url(input: string | ArrayBuffer): string {
  const str = typeof input === "string"
    ? btoa(input)
    : btoa(String.fromCharCode(...new Uint8Array(input)));
  return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}
