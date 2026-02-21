import { assertEquals, assertExists } from "https://deno.land/std@0.224.0/assert/mod.ts";

// Tests require DATABASE_URL pointing to a test Postgres database

import { app } from "./main.ts";
import {
  createUser, getUser, createDomain, createAlias, createRule,
  listUserDomains, listAliases, listRules, updateUserSubscription,
  createPendingCheckout, _getSql,
} from "./db.ts";
import { hashPassword, signJwt } from "./auth.ts";

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
  const { setPasswordToken } = await import("./db.ts");

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
  const badRes = await jsonPut(`/api/domains/${domain.id}/alias/info`, {
    destinations: ["not-an-email"],
  }, cookie);
  assertEquals(badRes.status, 400);
  await badRes.body?.cancel();

  // Empty destinations
  const emptyRes = await jsonPut(`/api/domains/${domain.id}/alias/info`, {
    destinations: [],
  }, cookie);
  assertEquals(emptyRes.status, 400);
  await emptyRes.body?.cancel();

  // Unknown fields ignored, valid update succeeds
  const okRes = await jsonPut(`/api/domains/${domain.id}/alias/info`, {
    enabled: false, hackField: "ignored",
  }, cookie);
  assertEquals(okRes.status, 200);
  const data = await okRes.json();
  assertEquals(data.enabled, false);
  assertEquals(data.hackField, undefined);
}});

// --- Backup/Restore verification ---

Deno.test({ name: "Backup create → parse → restore → verify data integrity", ...testOpts, fn: async () => {
  // Setup: create users with domains, aliases, and rules
  const backupEmail1 = `backup-user1-${suffix}@example.com`;
  const backupEmail2 = `backup-user2-${suffix}@example.com`;
  const hash = await hashPassword("testpass123");

  await createUser(backupEmail1, hash);
  await updateUserSubscription(backupEmail1, {
    plan: "developer",
    status: "active",
    currentPeriodEnd: new Date(Date.now() + 365 * 86400000).toISOString(),
  });
  const domain1 = await createDomain(backupEmail1, `backup1-${suffix}.test`, ["dkim1"], "v1");
  await createAlias(domain1.id, "contact", ["real1@gmail.com"]);
  await createAlias(domain1.id, "support", ["real2@gmail.com", "real3@gmail.com"]);
  await createRule(domain1.id, {
    field: "from", match: "contains", value: "spam",
    action: "discard", target: "", priority: 0, enabled: true,
  });

  await createUser(backupEmail2, hash);
  await updateUserSubscription(backupEmail2, {
    plan: "basico",
    status: "active",
    currentPeriodEnd: new Date(Date.now() + 30 * 86400000).toISOString(),
  });
  const domain2 = await createDomain(backupEmail2, `backup2-${suffix}.test`, ["dkim2"], "v2");
  await createAlias(domain2.id, "*", ["catchall@gmail.com"]);

  // Step 1: Simulate runBackup() — iterate KV and build backup JSON
  // (replicates main.ts:184-211 without S3)
  const kv = _getSql();
  const backupData: Record<string, unknown>[] = [];

  for await (const entry of kv.list<any>({ prefix: ["users"] })) {
    const user = entry.value;
    // Only include our backup test users
    if (!user.email.startsWith("backup-user") || !user.email.includes(`${suffix}`)) continue;

    const domains = await listUserDomains(user.email);
    const domainsData = [];
    for (const d of domains) {
      const aliases = await listAliases(d.id);
      const rules = await listRules(d.id);
      domainsData.push({ domain: d.domain, domainId: d.id, verified: d.verified, aliases, rules });
    }
    backupData.push({
      email: user.email,
      subscription: user.subscription,
      emailVerified: user.emailVerified,
      createdAt: user.createdAt,
      domains: domainsData,
    });
  }

  const backupJson = JSON.stringify(backupData, null, 2);

  // Step 2: Parse and verify backup contents
  const parsed = JSON.parse(backupJson) as any[];
  assertEquals(parsed.length, 2);

  const bu1 = parsed.find((u: any) => u.email === backupEmail1);
  const bu2 = parsed.find((u: any) => u.email === backupEmail2);
  assertExists(bu1, "User 1 should be in backup");
  assertExists(bu2, "User 2 should be in backup");

  assertEquals(bu1.subscription.plan, "developer");
  assertEquals(bu1.domains.length, 1);
  assertEquals(bu1.domains[0].aliases.length, 2);
  assertEquals(bu1.domains[0].rules.length, 1);
  assertEquals(bu1.domains[0].rules[0].value, "spam");

  assertEquals(bu2.subscription.plan, "basico");
  assertEquals(bu2.domains.length, 1);
  assertEquals(bu2.domains[0].aliases.length, 1);
  assertEquals(bu2.domains[0].aliases[0].alias, "*");

  // Step 3: Simulate restore — delete original data then recreate from backup
  // Delete aliases and rules from KV
  for (const u of [bu1, bu2]) {
    for (const d of u.domains) {
      for (const a of d.aliases) {
        await kv.delete(["aliases", d.domainId, a.alias]);
      }
      for (const r of d.rules) {
        await kv.delete(["rules", d.domainId, r.id]);
      }
    }
  }

  // Verify data is gone
  const aliasesGone = await listAliases(domain1.id);
  assertEquals(aliasesGone.length, 0, "Aliases should be deleted before restore");

  // Restore from backup
  for (const u of parsed) {
    for (const d of u.domains) {
      for (const a of d.aliases) {
        await kv.set(["aliases", d.domainId, a.alias], a);
      }
      for (const r of d.rules) {
        await kv.set(["rules", d.domainId, r.id], r);
      }
    }
  }

  // Step 4: Verify restored data matches original
  const restoredAliases1 = await listAliases(domain1.id);
  assertEquals(restoredAliases1.length, 2);
  const contactAlias = restoredAliases1.find((a) => a.alias === "contact");
  assertExists(contactAlias);
  assertEquals(contactAlias!.destinations, ["real1@gmail.com"]);

  const supportAlias = restoredAliases1.find((a) => a.alias === "support");
  assertExists(supportAlias);
  assertEquals(supportAlias!.destinations, ["real2@gmail.com", "real3@gmail.com"]);

  const restoredRules1 = await listRules(domain1.id);
  assertEquals(restoredRules1.length, 1);
  assertEquals(restoredRules1[0].action, "discard");
  assertEquals(restoredRules1[0].value, "spam");

  const restoredAliases2 = await listAliases(domain2.id);
  assertEquals(restoredAliases2.length, 1);
  assertEquals(restoredAliases2[0].alias, "*");
  assertEquals(restoredAliases2[0].destinations, ["catchall@gmail.com"]);
}});

// --- Webhook HTTP handler tests ---

const MP_SECRET = Deno.env.get("MP_WEBHOOK_SECRET") ?? "test-webhook-secret";
Deno.env.set("MP_WEBHOOK_SECRET", MP_SECRET);
Deno.env.set("MP_ACCESS_TOKEN", "test-mp-token");

async function computeHmac(secret: string, dataId: string, requestId: string, ts: string): Promise<string> {
  const manifest = `id:${dataId};request-id:${requestId};ts:${ts};`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(manifest));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function postWebhook(body: unknown, dataId: string): Promise<Response> {
  const requestId = `req-${crypto.randomUUID()}`;
  const ts = Math.floor(Date.now() / 1000).toString();
  const v1 = await computeHmac(MP_SECRET, dataId, requestId, ts);

  return app.fetch(new Request(
    `http://localhost/api/webhooks/mercadopago?data.id=${dataId}`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-signature": `ts=${ts},v1=${v1}`,
        "x-request-id": requestId,
      },
      body: JSON.stringify(body),
    },
  ));
}

Deno.test({ name: "Webhook - invalid HMAC returns 401", ...testOpts, fn: async () => {
  const res = await app.fetch(new Request(
    `http://localhost/api/webhooks/mercadopago?data.id=12345`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-signature": "ts=1700000000,v1=invalid_signature",
        "x-request-id": "req-1",
      },
      body: JSON.stringify({ type: "payment", data: { id: "12345" } }),
    },
  ));
  assertEquals(res.status, 401);
  await res.body?.cancel();
}});

Deno.test({ name: "Webhook - subscription authorized activates plan", ...testOpts, fn: async () => {
  const email = `webhook-activate-${suffix}@example.com`;
  const hash = await hashPassword("testpass123");
  await createUser(email, hash);

  const subId = `sub-${crypto.randomUUID()}`;

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url.includes("api.mercadopago.com/preapproval/")) {
      return new Response(JSON.stringify({
        payer_email: email,
        external_reference: email,
        status: "authorized",
        auto_recurring: { transaction_amount: 449, frequency: 1 },
      }));
    }
    return originalFetch(input, init);
  };

  try {
    const res = await postWebhook(
      { type: "subscription_preapproval", data: { id: subId } },
      subId,
    );
    assertEquals(res.status, 200);
    await res.body?.cancel();

    const user = await getUser(email);
    assertEquals(user?.subscription?.status, "active");
    assertEquals(user?.subscription?.plan, "freelancer");
    assertEquals(user?.subscription?.mpSubscriptionId, subId);
  } finally {
    globalThis.fetch = originalFetch;
  }
}});

Deno.test({ name: "Webhook - subscription cancelled updates status", ...testOpts, fn: async () => {
  const email = `webhook-cancel-${suffix}@example.com`;
  const hash = await hashPassword("testpass123");
  await createUser(email, hash);

  const subId = `sub-cancel-${crypto.randomUUID()}`;
  await updateUserSubscription(email, {
    plan: "freelancer",
    status: "active",
    mpSubscriptionId: subId,
    currentPeriodEnd: new Date(Date.now() + 30 * 86400000).toISOString(),
  });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input: string | URL | Request, _init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url.includes("api.mercadopago.com/preapproval/")) {
      return new Response(JSON.stringify({
        payer_email: email,
        external_reference: email,
        status: "cancelled",
        auto_recurring: { transaction_amount: 449, frequency: 1 },
      }));
    }
    return originalFetch(input, _init);
  };

  try {
    const res = await postWebhook(
      { type: "subscription_preapproval", data: { id: subId } },
      subId,
    );
    assertEquals(res.status, 200);
    await res.body?.cancel();

    const user = await getUser(email);
    assertEquals(user?.subscription?.status, "cancelled");
  } finally {
    globalThis.fetch = originalFetch;
  }
}});

Deno.test({ name: "Webhook - idempotency: second call is no-op", ...testOpts, fn: async () => {
  const email = `webhook-idemp-${suffix}@example.com`;
  const hash = await hashPassword("testpass123");
  await createUser(email, hash);

  const subId = `sub-idemp-${crypto.randomUUID()}`;
  let fetchCount = 0;

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input: string | URL | Request, _init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url.includes("api.mercadopago.com/preapproval/")) {
      fetchCount++;
      return new Response(JSON.stringify({
        payer_email: email,
        external_reference: email,
        status: "authorized",
        auto_recurring: { transaction_amount: 49, frequency: 1 },
      }));
    }
    return originalFetch(input, _init);
  };

  try {
    const res1 = await postWebhook(
      { type: "subscription_preapproval", data: { id: subId } },
      subId,
    );
    assertEquals(res1.status, 200);
    await res1.body?.cancel();
    assertEquals(fetchCount, 1);

    const res2 = await postWebhook(
      { type: "subscription_preapproval", data: { id: subId } },
      subId,
    );
    assertEquals(res2.status, 200);
    await res2.body?.cancel();
    assertEquals(fetchCount, 1, "Should not fetch MP API again for already-processed webhook");
  } finally {
    globalThis.fetch = originalFetch;
  }
}});

Deno.test({ name: "Webhook - guest checkout creates user and activates plan", ...testOpts, fn: async () => {
  const guestToken = crypto.randomUUID();
  const guestEmail = `guest-${suffix}@example.com`;

  await createPendingCheckout(guestToken, "developer");

  const subId = `sub-guest-${crypto.randomUUID()}`;

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input: string | URL | Request, _init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url.includes("api.mercadopago.com/preapproval/")) {
      return new Response(JSON.stringify({
        payer_email: guestEmail,
        external_reference: guestToken,
        status: "authorized",
        auto_recurring: { transaction_amount: 999, frequency: 1 },
      }));
    }
    return originalFetch(input, _init);
  };

  try {
    const res = await postWebhook(
      { type: "subscription_preapproval", data: { id: subId } },
      subId,
    );
    assertEquals(res.status, 200);
    await res.body?.cancel();

    const user = await getUser(guestEmail);
    assertExists(user, "Guest user should be created");
    assertEquals(user?.subscription?.status, "active");
    assertEquals(user?.subscription?.plan, "developer");
  } finally {
    globalThis.fetch = originalFetch;
  }
}});
