import { getUser } from "./db.ts";

const encoder = new TextEncoder();
const JWT_SECRET = Deno.env.get("JWT_SECRET") ?? "dev-secret-change-in-prod";
const JWT_EXPIRY = 3600; // 1 hour

// --- Password hashing (PBKDF2 via Web Crypto) ---

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations: 100_000 },
    key,
    256,
  );
  const hash = new Uint8Array(bits);
  return `${toHex(salt)}:${toHex(hash)}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [saltHex, hashHex] = stored.split(":");
  const salt = fromHex(saltHex);
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations: 100_000 },
    key,
    256,
  );
  return toHex(new Uint8Array(bits)) === hashHex;
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

const IS_PROD = Deno.env.get("DENO_DEPLOYMENT_ID") !== undefined;
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

  return { email: user.email };
}

// --- Internal helpers ---

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
