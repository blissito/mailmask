import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { _setKv } from "./db.ts";

// Use in-memory KV for test isolation (must be set before importing main.ts)
const testKv = await Deno.openKv(":memory:");
_setKv(testKv);

import { app } from "./main.ts";

const testOpts = { sanitizeResources: false, sanitizeOps: false };

// Unique fake IP per test run to avoid rate limiter collisions across runs
let ipCounter = 0;
const testIpBase = `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
function nextIp(): string { return `${testIpBase}.${ipCounter++ % 255}`; }

// Helper to make requests to the app
async function req(path: string, opts?: RequestInit): Promise<Response> {
  return app.fetch(new Request(`http://localhost${path}`, opts));
}

function jsonPost(path: string, body: unknown, cookie?: string): Promise<Response> {
  const headers: Record<string, string> = { "content-type": "application/json", "x-forwarded-for": nextIp() };
  if (cookie) headers["cookie"] = cookie;
  return req(path, { method: "POST", headers, body: JSON.stringify(body) });
}

function jsonPut(path: string, body: unknown, cookie?: string): Promise<Response> {
  const headers: Record<string, string> = { "content-type": "application/json", "x-forwarded-for": nextIp() };
  if (cookie) headers["cookie"] = cookie;
  return req(path, { method: "PUT", headers, body: JSON.stringify(body) });
}

function jsonGet(path: string, cookie?: string): Promise<Response> {
  const headers: Record<string, string> = {};
  if (cookie) headers["cookie"] = cookie;
  return req(path, { headers });
}

function extractCookie(res: Response): string | undefined {
  const setCookie = res.headers.get("set-cookie");
  if (!setCookie) return undefined;
  const match = setCookie.match(/token=([^;]+)/);
  return match ? `token=${match[1]}` : undefined;
}

// Unique email per test run to avoid collisions
const suffix = Date.now();

// --- Auth flow ---

Deno.test({ name: "POST /api/auth/register — 201 + sets cookie", ...testOpts, fn: async () => {
  const res = await jsonPost("/api/auth/register", {
    email: `test-reg-${suffix}@example.com`,
    password: "password123",
  });
  assertEquals(res.status, 201);
  const cookie = extractCookie(res);
  assertEquals(typeof cookie, "string");
  await res.body?.cancel();
}});

Deno.test({ name: "POST /api/auth/register — duplicate 409", ...testOpts, fn: async () => {
  const res = await jsonPost("/api/auth/register", {
    email: `test-reg-${suffix}@example.com`,
    password: "password123",
  });
  assertEquals(res.status, 409);
  await res.body?.cancel();
}});

Deno.test({ name: "POST /api/auth/register — missing fields 400", ...testOpts, fn: async () => {
  const res = await jsonPost("/api/auth/register", { email: "", password: "" });
  assertEquals(res.status, 400);
  await res.body?.cancel();
}});

Deno.test({ name: "POST /api/auth/register — short password 400", ...testOpts, fn: async () => {
  const res = await jsonPost("/api/auth/register", {
    email: `short-pw-${suffix}@example.com`,
    password: "123",
  });
  assertEquals(res.status, 400);
  await res.body?.cancel();
}});

Deno.test({ name: "POST /api/auth/login — 200 + sets cookie", ...testOpts, fn: async () => {
  const res = await jsonPost("/api/auth/login", {
    email: `test-reg-${suffix}@example.com`,
    password: "password123",
  });
  assertEquals(res.status, 200);
  const cookie = extractCookie(res);
  assertEquals(typeof cookie, "string");
  await res.body?.cancel();
}});

Deno.test({ name: "POST /api/auth/login — wrong password 401", ...testOpts, fn: async () => {
  const res = await jsonPost("/api/auth/login", {
    email: `test-reg-${suffix}@example.com`,
    password: "wrongpassword",
  });
  assertEquals(res.status, 401);
  await res.body?.cancel();
}});

Deno.test({ name: "POST /api/auth/login — nonexistent user 401", ...testOpts, fn: async () => {
  const res = await jsonPost("/api/auth/login", {
    email: "nobody@nowhere.com",
    password: "password123",
  });
  assertEquals(res.status, 401);
  await res.body?.cancel();
}});

Deno.test({ name: "GET /api/auth/me — no cookie 401", ...testOpts, fn: async () => {
  const res = await jsonGet("/api/auth/me");
  assertEquals(res.status, 401);
  await res.body?.cancel();
}});

Deno.test({ name: "GET /api/auth/me — valid cookie returns user", ...testOpts, fn: async () => {
  const loginRes = await jsonPost("/api/auth/login", {
    email: `test-reg-${suffix}@example.com`,
    password: "password123",
  });
  const cookie = extractCookie(loginRes)!;
  await loginRes.body?.cancel();

  const res = await jsonGet("/api/auth/me", cookie);
  assertEquals(res.status, 200);
  const data = await res.json();
  assertEquals(data.email, `test-reg-${suffix}@example.com`);
}});

Deno.test({ name: "POST /api/auth/set-password — invalidates old JWT", ...testOpts, fn: async () => {
  // Create user directly via DB to avoid rate limits
  const { createUser, setPasswordToken } = await import("./db.ts");
  const { hashPassword, signJwt } = await import("./auth.ts");

  const email = `pwchange-${suffix}@example.com`;
  const hash = await hashPassword("oldpassword1");
  await createUser(email, hash);

  const jwt = await signJwt({ email });
  const oldCookie = `token=${jwt}`;

  // Verify old cookie works
  const checkRes = await jsonGet("/api/auth/me", oldCookie);
  assertEquals(checkRes.status, 200);
  await checkRes.body?.cancel();

  // Create password token
  const token = crypto.randomUUID();
  await setPasswordToken(email, token);

  // Wait so iat differs from passwordChangedAt
  await new Promise((r) => setTimeout(r, 1100));

  // Set new password
  const setRes = await jsonPost("/api/auth/set-password", { token, password: "newpassword1" });
  assertEquals(setRes.status, 200);
  await setRes.body?.cancel();

  // Old cookie should be rejected
  const meRes = await jsonGet("/api/auth/me", oldCookie);
  assertEquals(meRes.status, 401);
  await meRes.body?.cancel();
}});

// --- Domains (no plan = 402) ---

Deno.test({ name: "POST /api/domains — no plan 402", ...testOpts, fn: async () => {
  const loginRes = await jsonPost("/api/auth/login", {
    email: `test-reg-${suffix}@example.com`,
    password: "password123",
  });
  const cookie = extractCookie(loginRes)!;
  await loginRes.body?.cancel();

  const res = await jsonPost("/api/domains", { domain: "test.com" }, cookie);
  assertEquals(res.status, 402);
  await res.body?.cancel();
}});

// --- Health check ---

Deno.test({ name: "GET /health — returns expected shape", ...testOpts, fn: async () => {
  const res = await req("/health");
  const data = await res.json();
  assertEquals(typeof data.status, "string");
  assertEquals(data.service, "mailmask");
  assertEquals(typeof data.timestamp, "string");
  assertEquals(typeof data.queueDepth, "number");
  assertEquals(typeof data.deadLetterCount, "number");
  assertEquals(typeof data.ses, "string");
}});

// --- Rule validation ---

Deno.test({ name: "Rule validation — SSRF, regex length, invalid regex", ...testOpts, fn: async () => {
  const { createUser, updateUserSubscription, createDomain } = await import("./db.ts");
  const { hashPassword, signJwt } = await import("./auth.ts");

  const email = `ruletest-${suffix}@example.com`;
  const hash = await hashPassword("testpassword1");
  await createUser(email, hash);
  await updateUserSubscription(email, {
    plan: "developer",
    status: "active",
    currentPeriodEnd: new Date(Date.now() + 365 * 86400000).toISOString(),
  });
  const domain = await createDomain(email, `rule-${suffix}.test`, ["dkim1"], "verify1");
  const jwt = await signJwt({ email });
  const cookie = `token=${jwt}`;

  // SSRF: private IP webhook
  const ssrfRes = await jsonPost(`/api/domains/${domain.id}/rules`, {
    field: "from", match: "contains", value: "test",
    action: "webhook", target: "http://169.254.169.254/latest/meta-data",
  }, cookie);
  assertEquals(ssrfRes.status, 400);
  const ssrfData = await ssrfRes.json();
  assertEquals(ssrfData.error.includes("privada"), true);

  // Regex too long
  const longRes = await jsonPost(`/api/domains/${domain.id}/rules`, {
    field: "from", match: "regex", value: "a".repeat(201), action: "discard",
  }, cookie);
  assertEquals(longRes.status, 400);
  const longData = await longRes.json();
  assertEquals(longData.error.includes("largo"), true);

  // Invalid regex
  const badRes = await jsonPost(`/api/domains/${domain.id}/rules`, {
    field: "from", match: "regex", value: "[invalid", action: "discard",
  }, cookie);
  assertEquals(badRes.status, 400);
  const badData = await badRes.json();
  assertEquals(badData.error.includes("inválido"), true);

  // Valid rule succeeds
  const okRes = await jsonPost(`/api/domains/${domain.id}/rules`, {
    field: "from", match: "contains", value: "spam", action: "discard",
  }, cookie);
  assertEquals(okRes.status, 201);
  await okRes.body?.cancel();
}});

// --- Alias update validation ---

Deno.test({ name: "Alias update — invalid email 400, whitelist ignores unknown fields", ...testOpts, fn: async () => {
  const { createUser, updateUserSubscription, createDomain, createAlias } = await import("./db.ts");
  const { hashPassword, signJwt } = await import("./auth.ts");

  const email = `aliastest-${suffix}@example.com`;
  const hash = await hashPassword("testpassword1");
  await createUser(email, hash);
  await updateUserSubscription(email, {
    plan: "developer",
    status: "active",
    currentPeriodEnd: new Date(Date.now() + 365 * 86400000).toISOString(),
  });
  const domain = await createDomain(email, `alias-${suffix}.test`, ["dkim1"], "verify1");
  await createAlias(domain.id, "info", ["dest@example.com"]);
  const jwt = await signJwt({ email });
  const cookie = `token=${jwt}`;

  // Invalid destination email
  const badRes = await jsonPut(`/api/domains/${domain.id}/aliases/info`, {
    destinations: ["not-an-email"],
  }, cookie);
  assertEquals(badRes.status, 400);
  await badRes.body?.cancel();

  // Empty destinations
  const emptyRes = await jsonPut(`/api/domains/${domain.id}/aliases/info`, {
    destinations: [],
  }, cookie);
  assertEquals(emptyRes.status, 400);
  await emptyRes.body?.cancel();

  // Unknown fields ignored, valid update succeeds
  const okRes = await jsonPut(`/api/domains/${domain.id}/aliases/info`, {
    enabled: false, hackField: "ignored",
  }, cookie);
  assertEquals(okRes.status, 200);
  const data = await okRes.json();
  assertEquals(data.enabled, false);
  assertEquals(data.hackField, undefined);
}});
