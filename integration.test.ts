import { describe, it, before } from "node:test";
import assert from "node:assert/strict";

import { app } from "./main.ts";
import {
  createUser, getUser, createDomain, createAlias, createRule,
  listUserDomains, listAliases, listRules, updateUserSubscription,
  createPendingCheckout,
} from "./db.ts";
import { hashPassword, signJwt } from "./auth.ts";

// Unique fake IP per test run to avoid rate limiter collisions
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

const suffix = Date.now();

// --- Auth flow ---

describe("Auth", () => {
  it("POST /api/auth/register — 201 + sets cookie", async () => {
    const res = await jsonPost("/api/auth/register", {
      email: `test-reg-${suffix}@example.com`,
      password: "password123",
    });
    assert.equal(res.status, 201);
    assert.ok(extractCookie(res));
    await res.body?.cancel();
  });

  it("POST /api/auth/register — duplicate 409", async () => {
    const res = await jsonPost("/api/auth/register", {
      email: `test-reg-${suffix}@example.com`,
      password: "password123",
    });
    assert.equal(res.status, 409);
    await res.body?.cancel();
  });

  it("POST /api/auth/register — missing fields 400", async () => {
    const res = await jsonPost("/api/auth/register", { email: "", password: "" });
    assert.equal(res.status, 400);
    await res.body?.cancel();
  });

  it("POST /api/auth/register — short password 400", async () => {
    const res = await jsonPost("/api/auth/register", {
      email: `short-pw-${suffix}@example.com`,
      password: "123",
    });
    assert.equal(res.status, 400);
    await res.body?.cancel();
  });

  it("POST /api/auth/login — 200 + sets cookie", async () => {
    const res = await jsonPost("/api/auth/login", {
      email: `test-reg-${suffix}@example.com`,
      password: "password123",
    });
    assert.equal(res.status, 200);
    assert.ok(extractCookie(res));
    await res.body?.cancel();
  });

  it("POST /api/auth/login — wrong password 401", async () => {
    const res = await jsonPost("/api/auth/login", {
      email: `test-reg-${suffix}@example.com`,
      password: "wrongpassword",
    });
    assert.equal(res.status, 401);
    await res.body?.cancel();
  });

  it("POST /api/auth/login — nonexistent user 401", async () => {
    const res = await jsonPost("/api/auth/login", {
      email: "nobody@nowhere.com",
      password: "password123",
    });
    assert.equal(res.status, 401);
    await res.body?.cancel();
  });

  it("GET /api/auth/me — no cookie 401", async () => {
    const res = await jsonGet("/api/auth/me");
    assert.equal(res.status, 401);
    await res.body?.cancel();
  });

  it("GET /api/auth/me — valid cookie returns user", async () => {
    const loginRes = await jsonPost("/api/auth/login", {
      email: `test-reg-${suffix}@example.com`,
      password: "password123",
    });
    const cookie = extractCookie(loginRes)!;
    await loginRes.body?.cancel();

    const res = await jsonGet("/api/auth/me", cookie);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.email, `test-reg-${suffix}@example.com`);
  });

  it("POST /api/auth/set-password — invalidates old JWT", async () => {
    const { setPasswordToken } = await import("./db.ts");

    const email = `pwchange-${suffix}@example.com`;
    const hash = await hashPassword("oldpassword1");
    createUser(email, hash);

    const jwt = await signJwt({ email });
    const oldCookie = `token=${jwt}`;

    const checkRes = await jsonGet("/api/auth/me", oldCookie);
    assert.equal(checkRes.status, 200);
    await checkRes.body?.cancel();

    const token = crypto.randomUUID();
    setPasswordToken(email, token);

    await new Promise((r) => setTimeout(r, 1100));

    const setRes = await jsonPost("/api/auth/set-password", { token, password: "newpassword1" });
    assert.equal(setRes.status, 200);
    await setRes.body?.cancel();

    const meRes = await jsonGet("/api/auth/me", oldCookie);
    assert.equal(meRes.status, 401);
    await meRes.body?.cancel();
  });
});

// --- Domains ---

describe("Domains", () => {
  it("POST /api/domains — no plan 402", async () => {
    const loginRes = await jsonPost("/api/auth/login", {
      email: `test-reg-${suffix}@example.com`,
      password: "password123",
    });
    const cookie = extractCookie(loginRes)!;
    await loginRes.body?.cancel();

    const res = await jsonPost("/api/domains", { domain: "test.com" }, cookie);
    assert.equal(res.status, 402);
    await res.body?.cancel();
  });
});

// --- Health check ---

describe("Health", () => {
  it("GET /health — returns expected shape", async () => {
    const res = await req("/health");
    const data = await res.json();
    assert.equal(typeof data.status, "string");
    assert.equal(data.service, "mailmask");
    assert.equal(typeof data.timestamp, "string");
    assert.equal(typeof data.queueDepth, "number");
    assert.equal(typeof data.deadLetterCount, "number");
    assert.equal(typeof data.ses, "string");
  });
});

// --- Rule validation ---

describe("Rules", () => {
  it("SSRF, regex length, invalid regex", async () => {
    const email = `ruletest-${suffix}@example.com`;
    const hash = await hashPassword("testpassword1");
    createUser(email, hash);
    updateUserSubscription(email, {
      plan: "developer",
      status: "active",
      currentPeriodEnd: new Date(Date.now() + 365 * 86400000).toISOString(),
    });
    const domain = createDomain(email, `rule-${suffix}.test`, ["dkim1"], "verify1");
    const jwt = await signJwt({ email });
    const cookie = `token=${jwt}`;

    // SSRF: private IP webhook
    const ssrfRes = await jsonPost(`/api/domains/${domain.id}/rules`, {
      field: "from", match: "contains", value: "test",
      action: "webhook", target: "http://169.254.169.254/latest/meta-data",
    }, cookie);
    assert.equal(ssrfRes.status, 400);
    const ssrfData = await ssrfRes.json();
    assert.ok(ssrfData.error.includes("privada"));

    // Regex too long
    const longRes = await jsonPost(`/api/domains/${domain.id}/rules`, {
      field: "from", match: "regex", value: "a".repeat(201), action: "discard",
    }, cookie);
    assert.equal(longRes.status, 400);
    const longData = await longRes.json();
    assert.ok(longData.error.includes("largo"));

    // Invalid regex
    const badRes = await jsonPost(`/api/domains/${domain.id}/rules`, {
      field: "from", match: "regex", value: "[invalid", action: "discard",
    }, cookie);
    assert.equal(badRes.status, 400);
    const badData = await badRes.json();
    assert.ok(badData.error.includes("inválido"));

    // Valid rule succeeds
    const okRes = await jsonPost(`/api/domains/${domain.id}/rules`, {
      field: "from", match: "contains", value: "spam", action: "discard",
    }, cookie);
    assert.equal(okRes.status, 201);
    await okRes.body?.cancel();
  });
});

// --- Alias validation ---

describe("Alias update", () => {
  it("invalid email 400, whitelist ignores unknown fields", async () => {
    const email = `aliastest-${suffix}@example.com`;
    const hash = await hashPassword("testpassword1");
    createUser(email, hash);
    updateUserSubscription(email, {
      plan: "developer",
      status: "active",
      currentPeriodEnd: new Date(Date.now() + 365 * 86400000).toISOString(),
    });
    const domain = createDomain(email, `alias-${suffix}.test`, ["dkim1"], "verify1");
    createAlias(domain.id, "info", ["dest@example.com"]);
    const jwt = await signJwt({ email });
    const cookie = `token=${jwt}`;

    const badRes = await jsonPut(`/api/domains/${domain.id}/alias/info`, {
      destinations: ["not-an-email"],
    }, cookie);
    assert.equal(badRes.status, 400);
    await badRes.body?.cancel();

    const emptyRes = await jsonPut(`/api/domains/${domain.id}/alias/info`, {
      destinations: [],
    }, cookie);
    assert.equal(emptyRes.status, 400);
    await emptyRes.body?.cancel();

    const okRes = await jsonPut(`/api/domains/${domain.id}/alias/info`, {
      enabled: false, hackField: "ignored",
    }, cookie);
    assert.equal(okRes.status, 200);
    const data = await okRes.json();
    assert.equal(data.enabled, false);
    assert.equal(data.hackField, undefined);
  });
});

// --- Webhook HTTP handler tests ---

const MP_SECRET = process.env.MP_WEBHOOK_SECRET ?? "test-webhook-secret";

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

describe("Webhook", () => {
  it("invalid HMAC returns 401", async () => {
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
    assert.equal(res.status, 401);
    await res.body?.cancel();
  });

  it("subscription authorized activates plan", async () => {
    const email = `webhook-activate-${suffix}@example.com`;
    const hash = await hashPassword("testpass123");
    createUser(email, hash);

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
      assert.equal(res.status, 200);
      await res.body?.cancel();

      const user = getUser(email);
      assert.equal(user?.subscription?.status, "active");
      assert.equal(user?.subscription?.plan, "freelancer");
      assert.equal(user?.subscription?.mpSubscriptionId, subId);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("subscription cancelled updates status", async () => {
    const email = `webhook-cancel-${suffix}@example.com`;
    const hash = await hashPassword("testpass123");
    createUser(email, hash);

    const subId = `sub-cancel-${crypto.randomUUID()}`;
    updateUserSubscription(email, {
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
      assert.equal(res.status, 200);
      await res.body?.cancel();

      const user = getUser(email);
      assert.equal(user?.subscription?.status, "cancelled");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("idempotency: second call is no-op", async () => {
    const email = `webhook-idemp-${suffix}@example.com`;
    const hash = await hashPassword("testpass123");
    createUser(email, hash);

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
      assert.equal(res1.status, 200);
      await res1.body?.cancel();
      assert.equal(fetchCount, 1);

      const res2 = await postWebhook(
        { type: "subscription_preapproval", data: { id: subId } },
        subId,
      );
      assert.equal(res2.status, 200);
      await res2.body?.cancel();
      assert.equal(fetchCount, 1, "Should not fetch MP API again for already-processed webhook");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("guest checkout creates user and activates plan", async () => {
    const guestToken = crypto.randomUUID();
    const guestEmail = `guest-${suffix}@example.com`;

    createPendingCheckout(guestToken, "developer");

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
      assert.equal(res.status, 200);
      await res.body?.cancel();

      const user = getUser(guestEmail);
      assert.ok(user, "Guest user should be created");
      assert.equal(user?.subscription?.status, "active");
      assert.equal(user?.subscription?.plan, "developer");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  // --- New webhook tests ---

  it("paused status → sub past_due", async () => {
    const email = `webhook-paused-${suffix}@example.com`;
    const hash = await hashPassword("testpass123");
    createUser(email, hash);

    const subId = `sub-paused-${crypto.randomUUID()}`;
    updateUserSubscription(email, {
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
          status: "paused",
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
      assert.equal(res.status, 200);
      await res.body?.cancel();

      const user = getUser(email);
      assert.equal(user?.subscription?.status, "past_due");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("plan detection: amount fallback — 449 = freelancer", async () => {
    const email = `webhook-plan-amt-${suffix}@example.com`;
    const hash = await hashPassword("testpass123");
    createUser(email, hash);

    const subId = `sub-plan-amt-${crypto.randomUUID()}`;

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: string | URL | Request, _init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("api.mercadopago.com/preapproval/")) {
        return new Response(JSON.stringify({
          payer_email: email,
          external_reference: email,
          status: "authorized",
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
      assert.equal(res.status, 200);
      await res.body?.cancel();

      const user = getUser(email);
      assert.equal(user?.subscription?.plan, "freelancer");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("plan detection: amount 999 = developer", async () => {
    const email = `webhook-plan-dev-${suffix}@example.com`;
    const hash = await hashPassword("testpass123");
    createUser(email, hash);

    const subId = `sub-plan-dev-${crypto.randomUUID()}`;

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: string | URL | Request, _init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("api.mercadopago.com/preapproval/")) {
        return new Response(JSON.stringify({
          payer_email: email,
          external_reference: email,
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
      assert.equal(res.status, 200);
      await res.body?.cancel();

      const user = getUser(email);
      assert.equal(user?.subscription?.plan, "developer");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
