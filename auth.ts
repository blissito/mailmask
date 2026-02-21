import { getUser, type User } from "./db.js";

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

export async function signJwt(payload: Record<string, unknown>): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const body = { ...payload, iat: now, exp: now + JWT_EXPIRY };

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

export async function getAuthUser(request: Request): Promise<{ email: string } | null> {
  const cookies = parseCookies(request.headers.get("cookie"));
  const token = cookies["token"];
  if (!token) return null;

  const payload = await verifyJwt(token);
  if (!payload || !payload.email) return null;

  const user = await getUser(payload.email as string);
  if (!user) return null;

  // Reject tokens issued before password change (C4: JWT revocation)
  if (user.passwordChangedAt && payload.iat) {
    const changedAtSec = Math.floor(new Date(user.passwordChangedAt).getTime() / 1000);
    if ((payload.iat as number) < changedAtSec) return null;
  }

  return { email: user.email };
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
