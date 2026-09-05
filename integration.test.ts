import { describe, it, before } from "node:test";
import assert from "node:assert/strict";

import { app } from "./main.ts";
import {
  createUser, getUser, createDomain, createAlias, createRule,
  listUserDomains, listAliases, listRules, updateUserSubscription,
  createPendingCheckout, createAddon, getAddonById, updateAddon,
  addSuppression, getConversation, listMessages, getSendCount,
} from "./db.ts";
import { hashPassword, signJwt, generateCsrfToken } from "./auth.ts";
import { sqlite } from "./pg.ts";

// Unique fake IP per test run to avoid rate limiter collisions
let ipCounter = 0;
const testIpBase = `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
function nextIp(): string { return `${testIpBase}.${ipCounter++ % 255}`; }

// Helper to make requests to the app
async function req(path: string, opts?: RequestInit): Promise<Response> {
  return app.fetch(new Request(`http://localhost${path}`, opts));
}

function jsonPost(path: string, body: unknown, cookie?: string, csrf?: string): Promise<Response> {
  const headers: Record<string, string> = { "content-type": "application/json", "x-forwarded-for": nextIp() };
  if (cookie) headers["cookie"] = csrf ? `${cookie}; csrf_token=${csrf}` : cookie;
  if (csrf) headers["x-csrf-token"] = csrf;
  return req(path, { method: "POST", headers, body: JSON.stringify(body) });
}

function jsonPut(path: string, body: unknown, cookie?: string, csrf?: string): Promise<Response> {
  const headers: Record<string, string> = { "content-type": "application/json", "x-forwarded-for": nextIp() };
  if (cookie) headers["cookie"] = csrf ? `${cookie}; csrf_token=${csrf}` : cookie;
  if (csrf) headers["x-csrf-token"] = csrf;
  return req(path, { method: "PUT", headers, body: JSON.stringify(body) });
}

function jsonGet(path: string, cookie?: string): Promise<Response> {
  const headers: Record<string, string> = {};
  if (cookie) headers["cookie"] = cookie;
  return req(path, { headers });
}

function extractCookies(res: Response): { cookie?: string; csrfToken?: string } {
  // Try getSetCookie first, then fall back to parsing combined header
  const all = res.headers.getSetCookie?.() ?? [];
  const parts = all.length > 0 ? all : (res.headers.get("set-cookie") ?? "").split(/,(?=\s*\w+=)/);
  let cookie: string | undefined;
  let csrfToken: string | undefined;
  for (const sc of parts) {
    const tokenMatch = sc.match(/(?:^|[\s,])token=([^;,]+)/);
    if (tokenMatch && !cookie) cookie = `token=${tokenMatch[1]}`;
    const csrfMatch = sc.match(/csrf_token=([^;,]+)/);
    if (csrfMatch && !csrfToken) csrfToken = csrfMatch[1];
  }
  return { cookie, csrfToken };
}

function extractCookie(res: Response): string | undefined {
  return extractCookies(res).cookie;
}

const suffix = Date.now();

// --- Auth flow ---

describe("Auth", () => {
  // Los rate limits viven en la DB y sobreviven entre corridas. Se limpian aquí para que
  // la suite no dependa del historial acumulado en data/test.db, que hacía fallar estos
  // tests de forma intermitente con corridas seguidas.
  before(() => {
    sqlite.prepare("DELETE FROM rate_limits").run();
  });

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

  it("POST /api/auth/register — missing fields 422", async () => {
    const res = await jsonPost("/api/auth/register", { email: "", password: "" });
    assert.equal(res.status, 422);
    await res.body?.cancel();
  });

  it("POST /api/auth/register — short password 422", async () => {
    const res = await jsonPost("/api/auth/register", {
      email: `short-pw-${suffix}@example.com`,
      password: "123",
    });
    assert.equal(res.status, 422);
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
    const { cookie, csrfToken } = extractCookies(loginRes);
    await loginRes.body?.cancel();

    const res = await jsonPost("/api/domains", { domain: "test.com" }, cookie!, csrfToken);
    assert.equal(res.status, 402);
    await res.body?.cancel();
  });
});

// --- Add-ons: gate de envío y endpoints ---

describe("Add-ons API", () => {
  const email = `addon-api-${suffix}@example.com`;
  let cookie: string | undefined;
  let csrfToken: string | undefined;
  let domainId = "";

  before(async () => {
    sqlite.prepare("DELETE FROM rate_limits").run();
    createUser(email, await hashPassword("password123"));
    await updateUserSubscription(email, {
      plan: "basico",
      status: "active",
      mpSubscriptionId: `sub-addon-api-${suffix}`,
      currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString(),
    });
    const loginRes = await jsonPost("/api/auth/login", { email, password: "password123" });
    ({ cookie, csrfToken } = extractCookies(loginRes));
    await loginRes.body?.cancel();

    const dom = createDomain(email, `addon-api-${suffix}.com`, ["dkim1"], "verify1");
    domainId = dom.id;
    sqlite.prepare("UPDATE domains SET verified = 1 WHERE id = ?").run(domainId);
  });

  it("básico sin add-on no puede enviar", async () => {
    const res = await jsonPost(`/api/domains/${domainId}/send`,
      { to: "alguien@example.com", subject: "hola", body: "texto" }, cookie!, csrfToken);
    assert.equal(res.status, 403);
    const data = await res.json();
    assert.match(data.error, /add-on de envíos/i);
  });

  it("GET /api/addons devuelve catálogo", async () => {
    const res = await req("/api/addons", { headers: { cookie: cookie! } });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.deepEqual(Object.keys(data.catalog).sort(), ["domain", "sends100", "sends25"]);
    assert.ok(Array.isArray(data.mine));
  });

  it("rechaza un kind inválido", async () => {
    const res = await jsonPost("/api/addons/checkout", { kind: "gratis" }, cookie!, csrfToken);
    assert.equal(res.status, 400);
    await res.body?.cancel();
  });

  it("no permite un segundo add-on de envíos", async () => {
    const a = createAddon(email, "sends100");
    const { updateAddon } = await import("./db.ts");
    updateAddon(a.id, { status: "active", currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString() });

    const res = await jsonPost("/api/addons/checkout", { kind: "sends25" }, cookie!, csrfToken);
    assert.equal(res.status, 409);
    await res.body?.cancel();

    // …y con el add-on activo el gate de envío ya deja pasar
    const me = await req("/api/auth/me", { headers: { cookie: cookie! } });
    const data = await me.json();
    assert.equal(data.limits.sendsUnlocked, true);
    assert.equal(data.limits.sends, 100);
    assert.equal(data.addons.length, 1);
  });

  it("redactar sin add-on da 403", async () => {
    // Este usuario ya tiene sends100 activo del test anterior, así que se usa uno limpio.
    const e2 = `compose-nolimit-${suffix}@example.com`;
    sqlite.prepare("DELETE FROM rate_limits").run();
    createUser(e2, await hashPassword("password123"));
    await updateUserSubscription(e2, {
      plan: "basico", status: "active", mpSubscriptionId: `sub-cnl-${suffix}`,
      currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString(),
    });
    const lr = await jsonPost("/api/auth/login", { email: e2, password: "password123" });
    const { cookie: c2, csrfToken: t2 } = extractCookies(lr);
    await lr.body?.cancel();

    const d2 = createDomain(e2, `compose-nl-${suffix}.com`, ["dk"], "vf");
    sqlite.prepare("UPDATE domains SET verified = 1 WHERE id = ?").run(d2.id);
    createAlias(d2.id, "hola", ["dest@example.com"]);

    const res = await jsonPost("/api/bandeja/conversations", {
      domainId: d2.id, to: "cliente@example.com", subject: "Hola", body: "texto", fromAlias: "hola",
    }, c2!, t2);
    assert.equal(res.status, 403);
    assert.match((await res.json()).error, /add-on de envíos/i);
  });

  it("cancelar un add-on inexistente da 404", async () => {
    const res = await jsonPost(`/api/addons/${crypto.randomUUID()}/cancel`, {}, cookie!, csrfToken);
    assert.equal(res.status, 404);
    await res.body?.cancel();
  });

  it("no deja cancelar una cortesía", async () => {
    // La compuerta tiene que estar en el endpoint, no solo en la UI: esconder el botón
    // no impide el POST, y una clienta con una cortesía llegó a tener ese botón enfrente.
    const { createCourtesyAddon } = await import("./db.ts");
    const { addon } = createCourtesyAddon({
      userEmail: email, kind: "domain",
      currentPeriodEnd: new Date(Date.now() + 400 * 864e5).toISOString(),
      note: "regalo de prueba", grantedBy: "test",
    });

    const res = await jsonPost(`/api/addons/${addon.id}/cancel`, {}, cookie!, csrfToken);
    assert.equal(res.status, 400);
    assert.match((await res.json()).error, /cortesía/i);

    // Y sigue viva: el intento fallido no la marcó cancelada.
    assert.equal(getAddonById(addon.id)?.status, "active");
  });

  it("la cortesía viaja al dashboard sin precio", async () => {
    const res = await req("/api/addons", { headers: { cookie: cookie! } });
    const data = await res.json();
    const cortesia = data.mine.find((a: { isCourtesy: boolean }) => a.isCourtesy);
    assert.ok(cortesia, "aparece en la lista");
    // De aquí sale el "+$99 MXN/mes" que la pantalla vieja le mostraba a un regalo.
    assert.equal(cortesia.priceCents, 0);
    assert.equal(cortesia.source, "courtesy");
  });
});

describe("Historial de pagos", () => {
  const email = `orders-api-${suffix}@example.com`;
  let cookie: string | undefined;

  before(async () => {
    sqlite.prepare("DELETE FROM rate_limits").run();
    createUser(email, await hashPassword("password123"));
    await updateUserSubscription(email, {
      plan: "basico", status: "active", mpSubscriptionId: `sub-orders-${suffix}`,
      currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString(),
    });
    const loginRes = await jsonPost("/api/auth/login", { email, password: "password123" });
    ({ cookie } = extractCookies(loginRes));
    await loginRes.body?.cancel();
  });

  it("sin sesión da 401", async () => {
    const res = await req("/api/billing/orders");
    assert.equal(res.status, 401);
    await res.body?.cancel();
  });

  it("una cuenta sin movimientos devuelve lista vacía y la nota de factura", async () => {
    const res = await req("/api/billing/orders", { headers: { cookie: cookie! } });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.deepEqual(data.orders, []);
    assert.equal(data.nextCursor, null);
    // Es la única vía para pedir CFDI, así que tiene que venir siempre.
    assert.match(data.invoiceNote, /CFDI/);
  });

  it("devuelve los cargos con folio y referencia, sin filtrar lo interno", async () => {
    const { recordOrder } = await import("./db.ts");
    recordOrder({
      userEmail: email, kind: "charge", subject: "plan", subjectKey: "basico",
      description: "Plan Básico (mensual)", amountCents: 4900, listPriceCents: 4900,
      mpPaymentId: "999888777", eventKey: `orders-api-${suffix}-1`,
      raw: { payer_id: "no-debe-salir" },
    });

    const res = await req("/api/billing/orders", { headers: { cookie: cookie! } });
    const [orden] = (await res.json()).orders;

    assert.match(orden.number, /^MM-\d{4}-[0-9A-F]{4}$/);
    assert.equal(orden.amountCents, 4900);
    assert.equal(orden.reference, "999888777");
    // `raw` trae datos del pagador que MercadoPago nos manda; no salen al cliente.
    assert.equal(orden.raw, undefined);
    assert.equal(orden.eventKey, undefined);
  });

  it("respeta el límite", async () => {
    const { recordOrder } = await import("./db.ts");
    for (let i = 0; i < 3; i++) {
      recordOrder({
        userEmail: email, kind: "charge", subject: "plan", description: `Cargo ${i}`,
        amountCents: 100, eventKey: `orders-api-${suffix}-lim-${i}`,
      });
    }
    const res = await req("/api/billing/orders?limit=2", { headers: { cookie: cookie! } });
    const data = await res.json();
    assert.equal(data.orders.length, 2);
    assert.ok(data.nextCursor, "hay cursor cuando se llenó la página");
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
    const csrf = generateCsrfToken();
    const cookie = `token=${jwt}`;

    // SSRF: private IP webhook
    const ssrfRes = await jsonPost(`/api/domains/${domain.id}/rules`, {
      field: "from", match: "contains", value: "test",
      action: "webhook", target: "http://169.254.169.254/latest/meta-data",
    }, cookie, csrf);
    assert.equal(ssrfRes.status, 400);
    const ssrfData = await ssrfRes.json();
    assert.ok(ssrfData.error.includes("privada"));

    // Regex too long
    const longRes = await jsonPost(`/api/domains/${domain.id}/rules`, {
      field: "from", match: "regex", value: "a".repeat(201), action: "discard",
    }, cookie, csrf);
    assert.equal(longRes.status, 400);
    const longData = await longRes.json();
    assert.ok(longData.error.includes("largo"));

    // Invalid regex
    const badRes = await jsonPost(`/api/domains/${domain.id}/rules`, {
      field: "from", match: "regex", value: "[invalid", action: "discard",
    }, cookie, csrf);
    assert.equal(badRes.status, 400);
    const badData = await badRes.json();
    assert.ok(badData.error.includes("inválido"));

    // ReDoS: cuantificador anidado. Es corto y compila, así que las dos validaciones
    // anteriores lo dejaban pasar — y una regla así congela el proceso entero cuando
    // llega un correo que casi coincide.
    const redosRes = await jsonPost(`/api/domains/${domain.id}/rules`, {
      field: "subject", match: "regex", value: "^(a+)+$", action: "discard",
    }, cookie, csrf);
    assert.equal(redosRes.status, 400);
    const redosData = await redosRes.json();
    assert.ok(redosData.error.includes("cuantificador"));

    // Una regex normal sigue guardándose
    const regexOkRes = await jsonPost(`/api/domains/${domain.id}/rules`, {
      field: "subject", match: "regex", value: "^factura-\\d+$", action: "discard",
    }, cookie, csrf);
    assert.equal(regexOkRes.status, 201);
    await regexOkRes.body?.cancel();

    // Valid rule succeeds
    const okRes = await jsonPost(`/api/domains/${domain.id}/rules`, {
      field: "from", match: "contains", value: "spam", action: "discard",
    }, cookie, csrf);
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
    const csrf = generateCsrfToken();
    const cookie = `token=${jwt}`;

    const badRes = await jsonPut(`/api/domains/${domain.id}/alias/info`, {
      destinations: ["not-an-email"],
    }, cookie, csrf);
    assert.equal(badRes.status, 400);
    await badRes.body?.cancel();

    const emptyRes = await jsonPut(`/api/domains/${domain.id}/alias/info`, {
      destinations: [],
    }, cookie, csrf);
    assert.equal(emptyRes.status, 400);
    await emptyRes.body?.cancel();

    const okRes = await jsonPut(`/api/domains/${domain.id}/alias/info`, {
      enabled: false, hackField: "ignored",
    }, cookie, csrf);
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

async function postWebhook(body: unknown, dataId: string, fixedRequestId?: string): Promise<Response> {
  const requestId = fixedRequestId ?? `req-${crypto.randomUUID()}`;
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

describe("Google sign-in", () => {
  const CLIENT_ID = "test-client.apps.googleusercontent.com";
  function idToken(payload: Record<string, unknown>): string {
    const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
    return `${b64({ alg: "RS256" })}.${b64(payload)}.sig`;
  }
  function seedState(state: string, value: Record<string, unknown> = {}, ttlMs = 60_000): void {
    sqlite.prepare("INSERT INTO tokens (token, kind, value, expires_at) VALUES (?, 'oauth-state', ?, ?)")
      .run(state, JSON.stringify(value), new Date(Date.now() + ttlMs).toISOString());
  }
  function mockGoogle(email: string, extra: Record<string, unknown> = {}) {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url === "https://oauth2.googleapis.com/token") {
        return new Response(JSON.stringify({ id_token: idToken({ aud: CLIENT_ID, email, email_verified: true, sub: "g-1", ...extra }) }));
      }
      return originalFetch(input, init);
    };
    return () => { globalThis.fetch = originalFetch; };
  }
  const suffix = crypto.randomUUID().slice(0, 8);
  let envBackup: { id?: string; secret?: string };
  before(() => {
    envBackup = { id: process.env.GOOGLE_CLIENT_ID, secret: process.env.GOOGLE_CLIENT_SECRET };
    process.env.GOOGLE_CLIENT_ID = CLIENT_ID;
    process.env.GOOGLE_CLIENT_SECRET = "test-secret";
  });

  it("start redirects to Google with a stored state", async () => {
    const res = await app.fetch(new Request("http://localhost/api/auth/google?ref=abc&coupon=XY"));
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.get("location")!);
    assert.equal(loc.origin, "https://accounts.google.com");
    assert.equal(loc.searchParams.get("client_id"), CLIENT_ID);
    assert.equal(loc.searchParams.get("redirect_uri"), "http://localhost/api/auth/google/callback");
    const state = loc.searchParams.get("state")!;
    const row = sqlite.prepare("SELECT value FROM tokens WHERE token = ? AND kind = 'oauth-state'").get(state) as { value: string };
    assert.deepEqual(JSON.parse(row.value), { ref: "abc", coupon: "XY" });
  });

  it("callback creates a verified account and logs in", async () => {
    const email = `google-new-${suffix}@example.com`;
    const state = `st-${crypto.randomUUID()}`;
    seedState(state, { coupon: "PROMO" });
    const restore = mockGoogle(email);
    try {
      const res = await app.fetch(new Request(`http://localhost/api/auth/google/callback?code=c0de&state=${state}`));
      assert.equal(res.status, 302);
      assert.ok(res.headers.get("location")!.endsWith("/app?coupon=PROMO"));
      const cookies = res.headers.getSetCookie();
      assert.ok(cookies.some((c) => c.startsWith("token=")));
      assert.ok(cookies.some((c) => c.startsWith("csrf_token=")));
      const user = getUser(email);
      assert.ok(user);
      assert.equal(user!.emailVerified, true);
      // state is single-use
      const again = await app.fetch(new Request(`http://localhost/api/auth/google/callback?code=c0de&state=${state}`));
      assert.ok(again.headers.get("location")!.includes("error=google-state"));
    } finally {
      restore();
    }
  });

  it("callback on an existing password account is the same account; password still works", async () => {
    const email = `google-existing-${suffix}@example.com`;
    createUser(email, await hashPassword("password123"));
    const state = `st-${crypto.randomUUID()}`;
    seedState(state);
    const restore = mockGoogle(email);
    try {
      const res = await app.fetch(new Request(`http://localhost/api/auth/google/callback?code=c0de&state=${state}`));
      assert.equal(res.status, 302);
      assert.ok(res.headers.get("location")!.endsWith("/app"));
      assert.equal(getUser(email)!.emailVerified, true);
    } finally {
      restore();
    }
    const login = await app.fetch(new Request("http://localhost/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: "password123" }),
    }));
    assert.equal(login.status, 200);
    await login.body?.cancel();
    assert.equal(sqlite.prepare("SELECT count(*) AS c FROM users WHERE email = ?").get(email)!.c, 1);
  });

  it("callback rejects an unverified Google email and a wrong audience", async () => {
    const email = `google-unverified-${suffix}@example.com`;
    let state = `st-${crypto.randomUUID()}`;
    seedState(state);
    let restore = mockGoogle(email, { email_verified: false });
    try {
      const res = await app.fetch(new Request(`http://localhost/api/auth/google/callback?code=c0de&state=${state}`));
      assert.ok(res.headers.get("location")!.includes("error=google-no-verificado"));
    } finally { restore(); }
    state = `st-${crypto.randomUUID()}`;
    seedState(state);
    restore = mockGoogle(email, { aud: "otro" });
    try {
      const res = await app.fetch(new Request(`http://localhost/api/auth/google/callback?code=c0de&state=${state}`));
      assert.ok(res.headers.get("location")!.includes("error=google-aud"));
    } finally { restore(); }
    assert.equal(getUser(email), null);
    process.env.GOOGLE_CLIENT_ID = envBackup.id;
    process.env.GOOGLE_CLIENT_SECRET = envBackup.secret;
  });
});

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

    // La idempotencia se llavea por EVENTO (x-request-id), no por suscripción: el mismo
    // preapproval debe poder procesarse varias veces (pending -> authorized), pero el
    // mismo evento reenviado por MP no.
    const sameEvent = `req-idemp-${crypto.randomUUID()}`;
    try {
      const res1 = await postWebhook(
        { type: "subscription_preapproval", data: { id: subId } }, subId, sameEvent,
      );
      assert.equal(res1.status, 200);
      await res1.body?.cancel();
      assert.equal(fetchCount, 1);

      const res2 = await postWebhook(
        { type: "subscription_preapproval", data: { id: subId } }, subId, sameEvent,
      );
      assert.equal(res2.status, 200);
      await res2.body?.cancel();
      assert.equal(fetchCount, 1, "el mismo evento reenviado no debe reprocesarse");

      // Y la regresión que costó un pago: un evento DISTINTO del mismo preapproval
      // (pending -> authorized) sí debe procesarse.
      const res3 = await postWebhook(
        { type: "subscription_preapproval", data: { id: subId } }, subId,
      );
      assert.equal(res3.status, 200);
      await res3.body?.cancel();
      assert.equal(fetchCount, 2, "un evento nuevo del mismo preapproval SÍ debe procesarse");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  // Espacio de fallo que costó el pago de una clienta: el webhook tenía seis formas de
  // perder un cobro y tres devolvían 200 sin log.
  it("acepta data.id con mayúsculas (MP firma en minúsculas)", async () => {
    const email = `webhook-upper-${suffix}@example.com`;
    createUser(email, await hashPassword("testpass123"));
    const subId = `SUB-UPPER-${crypto.randomUUID().toUpperCase()}`;

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: string | URL | Request, _init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("api.mercadopago.com/preapproval/")) {
        return new Response(JSON.stringify({
          payer_email: email, external_reference: email, status: "authorized",
          auto_recurring: { transaction_amount: 49, frequency: 1 },
        }));
      }
      return originalFetch(input, _init);
    };
    try {
      // El manifest se firma con el id en minúsculas, pero la query lo trae en mayúsculas.
      const requestId = `req-${crypto.randomUUID()}`;
      const ts = Math.floor(Date.now() / 1000).toString();
      const v1 = await computeHmac(MP_SECRET, subId.toLowerCase(), requestId, ts);
      const res = await app.fetch(new Request(
        `http://localhost/api/webhooks/mercadopago?data.id=${subId}`,
        {
          method: "POST",
          headers: { "content-type": "application/json", "x-signature": `ts=${ts},v1=${v1}`, "x-request-id": requestId },
          body: JSON.stringify({ type: "subscription_preapproval", data: { id: subId } }),
        },
      ));
      assert.equal(res.status, 200, "no debe rechazarse por mayúsculas");
      await res.body?.cancel();
      assert.equal(getUser(email)?.subscription?.status, "active");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("acepta data.id solo en el body, sin query", async () => {
    const email = `webhook-bodyid-${suffix}@example.com`;
    createUser(email, await hashPassword("testpass123"));
    const subId = `sub-bodyid-${crypto.randomUUID()}`;

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: string | URL | Request, _init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("api.mercadopago.com/preapproval/")) {
        return new Response(JSON.stringify({
          payer_email: email, external_reference: email, status: "authorized",
          auto_recurring: { transaction_amount: 49, frequency: 1 },
        }));
      }
      return originalFetch(input, _init);
    };
    try {
      const requestId = `req-${crypto.randomUUID()}`;
      const ts = Math.floor(Date.now() / 1000).toString();
      const v1 = await computeHmac(MP_SECRET, subId, requestId, ts);
      const res = await app.fetch(new Request(
        `http://localhost/api/webhooks/mercadopago`, // sin ?data.id
        {
          method: "POST",
          headers: { "content-type": "application/json", "x-signature": `ts=${ts},v1=${v1}`, "x-request-id": requestId },
          body: JSON.stringify({ type: "subscription_preapproval", data: { id: subId } }),
        },
      ));
      assert.equal(res.status, 200);
      await res.body?.cancel();
      assert.equal(getUser(email)?.subscription?.status, "active");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("un tipo desconocido responde 200 pero no se traga el evento en silencio", async () => {
    const dataId = `unknown-${crypto.randomUUID()}`;
    const res = await postWebhook({ type: "preapproval", data: { id: dataId } }, dataId);
    // 200 para que MP no reintente algo que no nos toca, pero queda registrado en el log.
    assert.equal(res.status, 200);
    await res.body?.cancel();
  });

  it("si MP devuelve error al consultar el preapproval, responde 500 para forzar reintento", async () => {
    const dataId = `sub-fetchfail-${crypto.randomUUID()}`;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: string | URL | Request, _init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("api.mercadopago.com/preapproval/")) {
        return new Response(JSON.stringify({ message: "not found" }), { status: 404 });
      }
      return originalFetch(input, _init);
    };
    try {
      const res = await postWebhook({ type: "subscription_preapproval", data: { id: dataId } }, dataId);
      assert.equal(res.status, 500, "debe pedir reintento, no devolver 200 y perder el pago");
      await res.body?.cancel();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("un email sin fila en users no se reporta como activado", async () => {
    const ghost = `fantasma-${suffix}@example.com`;
    const dataId = `sub-ghost-${crypto.randomUUID()}`;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: string | URL | Request, _init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("api.mercadopago.com/preapproval/")) {
        return new Response(JSON.stringify({
          payer_email: ghost, external_reference: ghost, status: "authorized",
          auto_recurring: { transaction_amount: 49, frequency: 1 },
        }));
      }
      return originalFetch(input, _init);
    };
    try {
      const res = await postWebhook({ type: "subscription_preapproval", data: { id: dataId } }, dataId);
      assert.equal(res.status, 500, "antes devolvía 200 y logueaba 'Subscription activated' sin escribir nada");
      await res.body?.cancel();
      assert.equal(getUser(ghost), null);
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

  // Regresión crítica: el add-on de envíos cuesta $49, exactamente lo mismo que el plan
  // básico. Si el webhook no sale por la rama de add-on, el fallback por monto lo activaría
  // como plan y le sobrescribiría subPlan/subMpId al usuario.
  it("add-on de $49 no toca la suscripción base", async () => {
    const email = `webhook-addon-${suffix}@example.com`;
    const hash = await hashPassword("testpass123");
    createUser(email, hash);
    await updateUserSubscription(email, {
      plan: "developer",
      status: "active",
      mpSubscriptionId: "sub-base-original",
      currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString(),
    });

    const addon = createAddon(email, "sends25");
    const subId = `sub-addon-${crypto.randomUUID()}`;

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: string | URL | Request, _init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("api.mercadopago.com/preapproval/")) {
        return new Response(JSON.stringify({
          payer_email: email,
          external_reference: `addon:${addon.id}`,
          status: "authorized",
          auto_recurring: { transaction_amount: 49, frequency: 1 },
        }));
      }
      return originalFetch(input, _init);
    };

    try {
      const res = await postWebhook({ type: "subscription_preapproval", data: { id: subId } }, subId);
      assert.equal(res.status, 200);
      await res.body?.cancel();

      const user = getUser(email);
      assert.equal(user?.subscription?.plan, "developer", "el plan base no debe cambiar");
      assert.equal(user?.subscription?.mpSubscriptionId, "sub-base-original", "el preapproval base no debe cambiar");

      const stored = getAddonById(addon.id);
      assert.equal(stored?.status, "active");
      assert.equal(stored?.mpPreapprovalId, subId);
      assert.ok(stored?.currentPeriodEnd, "debe quedar con periodo vigente");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("cancelación de add-on en MP lo desactiva sin tocar el plan", async () => {
    const email = `webhook-addon-cancel-${suffix}@example.com`;
    const hash = await hashPassword("testpass123");
    createUser(email, hash);
    await updateUserSubscription(email, {
      plan: "basico",
      status: "active",
      mpSubscriptionId: "sub-base-basico",
      currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString(),
    });

    const addon = createAddon(email, "domain");
    const subId = `sub-addon-cancel-${crypto.randomUUID()}`;

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: string | URL | Request, _init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("api.mercadopago.com/preapproval/")) {
        return new Response(JSON.stringify({
          payer_email: email,
          external_reference: `addon:${addon.id}`,
          status: "cancelled",
          auto_recurring: { transaction_amount: 99, frequency: 1 },
        }));
      }
      return originalFetch(input, _init);
    };

    try {
      const res = await postWebhook({ type: "subscription_preapproval", data: { id: subId } }, subId);
      assert.equal(res.status, 200);
      await res.body?.cancel();

      assert.equal(getAddonById(addon.id)?.status, "cancelled");
      assert.equal(getUser(email)?.subscription?.status, "active", "el plan base sigue vivo");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("el pago recurrente de un add-on extiende su periodo, no el del plan", async () => {
    const email = `webhook-addon-renew-${suffix}@example.com`;
    const hash = await hashPassword("testpass123");
    createUser(email, hash);
    const basePeriodEnd = new Date(Date.now() + 30 * 864e5).toISOString();
    await updateUserSubscription(email, {
      plan: "basico",
      status: "active",
      mpSubscriptionId: "sub-base-renew",
      currentPeriodEnd: basePeriodEnd,
    });

    const addon = createAddon(email, "sends100");
    const mpId = `mp-addon-renew-${crypto.randomUUID()}`;
    const { updateAddon } = await import("./db.ts");
    updateAddon(addon.id, { status: "active", mpPreapprovalId: mpId, currentPeriodEnd: new Date(Date.now() + 2 * 864e5).toISOString() });

    const payId = `pay-addon-${crypto.randomUUID()}`;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: string | URL | Request, _init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("authorized_payments/")) {
        return new Response(JSON.stringify({
          preapproval_id: mpId,
          status: "processed",
          payment: { status: "approved" },
        }));
      }
      return originalFetch(input, _init);
    };

    try {
      const res = await postWebhook({ type: "subscription_authorized_payment", data: { id: payId } }, payId);
      assert.equal(res.status, 200);
      await res.body?.cancel();

      const stored = getAddonById(addon.id);
      assert.ok(
        new Date(stored!.currentPeriodEnd!) > new Date(Date.now() + 30 * 864e5),
        "el periodo del add-on debe haberse extendido ~35 días",
      );
      assert.equal(getUser(email)?.subscription?.currentPeriodEnd, basePeriodEnd, "el periodo del plan no se toca");
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

  it("renewal extends subscription period (not resets)", async () => {
    const email = `webhook-renew-${suffix}@example.com`;
    const hash = await hashPassword("testpass123");
    createUser(email, hash);

    const subId = `sub-renew-${crypto.randomUUID()}`;
    const originalEnd = new Date(Date.now() + 15 * 86400000); // 15 days from now
    updateUserSubscription(email, {
      plan: "freelancer",
      status: "active",
      mpSubscriptionId: subId,
      currentPeriodEnd: originalEnd.toISOString(),
    });

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
      assert.equal(user?.subscription?.status, "active");
      assert.equal(user?.subscription?.plan, "freelancer");
      // Period should be extended from the original end, not from now
      const newEnd = new Date(user!.subscription!.currentPeriodEnd!);
      assert.ok(newEnd > originalEnd, `Expected ${newEnd.toISOString()} > ${originalEnd.toISOString()}`);
      // Should be ~35 days from original end (monthly buffer)
      const diffDays = (newEnd.getTime() - originalEnd.getTime()) / 86400000;
      assert.ok(diffDays >= 34 && diffDays <= 36, `Expected ~35 days extension, got ${diffDays}`);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("migrate: relinks subscription, keeps period, cancels old preapproval, records no order", async () => {
    const email = `webhook-migrate-${suffix}@example.com`;
    createUser(email, await hashPassword("testpass123"));
    const oldId = `sub-old-${crypto.randomUUID()}`;
    const newId = `sub-new-${crypto.randomUUID()}`;
    const periodEnd = new Date(Date.now() + 20 * 86400000).toISOString();
    updateUserSubscription(email, { plan: "basico", status: "active", mpSubscriptionId: oldId, currentPeriodEnd: periodEnd });
    const ordersBefore = sqlite.prepare("SELECT count(*) AS c FROM orders WHERE user_email = ?").get(email) as { c: number };

    const cancelled: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("api.mercadopago.com/preapproval/") && init?.method === "PUT") {
        cancelled.push(url.split("/").pop()!);
        return new Response(JSON.stringify({ status: "cancelled" }));
      }
      if (url.includes(`api.mercadopago.com/preapproval/${newId}`)) {
        return new Response(JSON.stringify({
          status: "authorized",
          payer_email: "otra-cuenta@example.com",
          external_reference: `migrate:${email}`,
          next_payment_date: "2026-09-28T18:38:13.000-04:00",
          auto_recurring: { transaction_amount: 49, frequency: 1, start_date: "2026-09-28T18:38:13.000-04:00" },
        }));
      }
      return originalFetch(input, init);
    };
    try {
      const res = await postWebhook({ type: "subscription_preapproval", data: { id: newId } }, newId);
      assert.equal(res.status, 200);
      await res.body?.cancel();

      const user = getUser(email);
      assert.equal(user?.subscription?.mpSubscriptionId, newId);
      assert.equal(user?.subscription?.plan, "basico");
      assert.equal(user?.subscription?.status, "active");
      assert.equal(user?.subscription?.currentPeriodEnd, periodEnd);
      assert.deepEqual(cancelled, [oldId]);
      const ordersAfter = sqlite.prepare("SELECT count(*) AS c FROM orders WHERE user_email = ?").get(email) as { c: number };
      assert.equal(ordersAfter.c, ordersBefore.c);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("migrate: non-authorized status changes nothing", async () => {
    const email = `webhook-migrate-pending-${suffix}@example.com`;
    createUser(email, await hashPassword("testpass123"));
    const oldId = `sub-old-${crypto.randomUUID()}`;
    const newId = `sub-new-${crypto.randomUUID()}`;
    updateUserSubscription(email, { plan: "basico", status: "active", mpSubscriptionId: oldId, currentPeriodEnd: new Date(Date.now() + 86400000).toISOString() });

    let puts = 0;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (init?.method === "PUT") { puts++; return new Response("{}"); }
      if (url.includes(`api.mercadopago.com/preapproval/${newId}`)) {
        return new Response(JSON.stringify({ status: "pending", external_reference: `migrate:${email}` }));
      }
      return originalFetch(input, init);
    };
    try {
      const res = await postWebhook({ type: "subscription_preapproval", data: { id: newId } }, newId);
      assert.equal(res.status, 200);
      await res.body?.cancel();
      assert.equal(getUser(email)?.subscription?.mpSubscriptionId, oldId);
      assert.equal(puts, 0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("addon with future start_date activates until start+35 without recording a charge", async () => {
    const email = `webhook-addon-deferred-${suffix}@example.com`;
    createUser(email, await hashPassword("testpass123"));
    updateUserSubscription(email, { plan: "basico", status: "active", currentPeriodEnd: new Date(Date.now() + 30 * 86400000).toISOString() });
    const addon = createAddon(email, "sends25");
    const mpId = `addon-deferred-${crypto.randomUUID()}`;
    updateAddon(addon.id, { mpPreapprovalId: mpId });
    const start = new Date(Date.now() + 14 * 86400000);

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes(`api.mercadopago.com/preapproval/${mpId}`)) {
        return new Response(JSON.stringify({
          status: "authorized",
          external_reference: `addon:${addon.id}`,
          auto_recurring: { transaction_amount: 49, currency_id: "MXN", start_date: start.toISOString() },
        }));
      }
      return originalFetch(input, init);
    };
    try {
      const res = await postWebhook({ type: "subscription_preapproval", data: { id: mpId } }, mpId);
      assert.equal(res.status, 200);
      await res.body?.cancel();
      const after = getAddonById(addon.id)!;
      assert.equal(after.status, "active");
      const diffDays = (new Date(after.currentPeriodEnd!).getTime() - start.getTime()) / 86400000;
      assert.ok(diffDays >= 34 && diffDays <= 36, `expected start+35, got ${diffDays}`);
      const charges = sqlite.prepare("SELECT count(*) AS c FROM orders WHERE subject_id = ? AND kind = 'charge'").get(addon.id) as { c: number };
      assert.equal(charges.c, 0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("plan determined from sub.reason fallback (coupon with non-standard amount)", async () => {
    const email = `webhook-reason-${suffix}@example.com`;
    const hash = await hashPassword("testpass123");
    createUser(email, hash);

    const subId = `sub-reason-${crypto.randomUUID()}`;

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: string | URL | Request, _init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("api.mercadopago.com/preapproval/")) {
        return new Response(JSON.stringify({
          payer_email: email,
          external_reference: email,
          status: "authorized",
          reason: "MailMask — Plan Developer (Mensual) — 50% OFF",
          auto_recurring: { transaction_amount: 1, frequency: 1 }, // non-standard coupon amount
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
      assert.equal(user?.subscription?.status, "active");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

// --- Redactar correo nuevo desde la Bandeja ---

describe("Bandeja: redactar", () => {
  const email = `compose-${suffix}@example.com`;
  let cookie: string | undefined;
  let csrfToken: string | undefined;
  let domainId = "";

  before(async () => {
    sqlite.prepare("DELETE FROM rate_limits").run();
    createUser(email, await hashPassword("password123"));
    await updateUserSubscription(email, {
      plan: "basico",
      status: "active",
      mpSubscriptionId: `sub-compose-${suffix}`,
      currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString(),
    });
    // Add-on de 25/día para poder probar el tope sin mandar 100 correos.
    const a = createAddon(email, "sends25");
    updateAddon(a.id, { status: "active", currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString() });

    const loginRes = await jsonPost("/api/auth/login", { email, password: "password123" });
    ({ cookie, csrfToken } = extractCookies(loginRes));
    await loginRes.body?.cancel();

    const dom = createDomain(email, `compose-${suffix}.com`, ["dkim1"], "verify1");
    domainId = dom.id;
    sqlite.prepare("UPDATE domains SET verified = 1 WHERE id = ?").run(domainId);
    createAlias(domainId, "hola", ["destino@example.com"]);
    createAlias(domainId, "off", ["destino@example.com"]);
    sqlite.prepare("UPDATE alias SET enabled = 0 WHERE domain_id = ? AND alias = ?").run(domainId, "off");
  });

  const compose = (over: Record<string, unknown> = {}) =>
    jsonPost("/api/bandeja/conversations", {
      domainId, to: "cliente@example.com", subject: "Cotización", body: "Hola, va la propuesta.", fromAlias: "hola",
      ...over,
    }, cookie!, csrfToken);

  it("rechaza un remitente que no es alias del dominio", async () => {
    const res = await compose({ fromAlias: "inventado" });
    assert.equal(res.status, 400);
    assert.match((await res.json()).error, /alias activo/i);
  });

  it("rechaza un alias deshabilitado", async () => {
    const res = await compose({ fromAlias: "off" });
    assert.equal(res.status, 400);
  });

  it("rechaza un destinatario inválido", async () => {
    const res = await compose({ to: "no-es-un-email" });
    assert.equal(res.status, 400);
  });

  it("rechaza un destinatario en la lista de supresión", async () => {
    addSuppression(domainId, "rebotado@example.com", "bounce:Permanent");
    const res = await compose({ to: "rebotado@example.com" });
    assert.equal(res.status, 422);
  });

  it("respeta el tope diario del add-on", async () => {
    // El add-on de este usuario es de 25/día. Se llena el contador a mano: ningún test
    // de esta suite llega a enviar, así que la fila del día no existe todavía.
    const day = new Date().toISOString().slice(0, 10);
    const expires = new Date(Date.now() + 3 * 864e5).toISOString();
    sqlite.prepare(
      "INSERT OR REPLACE INTO send_counts (domain_id, month, count, expires_at) VALUES (?,?,?,?)",
    ).run(domainId, day, 25, expires);

    const res = await compose({ subject: "Uno de más" });
    assert.equal(res.status, 429);
    assert.match((await res.json()).error, /Límite diario/i);

    // La cuota rechazada se devuelve: no queda consumida de más.
    assert.equal(getSendCount(domainId), 25);
  });

  it("un dominio sin verificar no puede redactar", async () => {
    sqlite.prepare("UPDATE domains SET verified = 0 WHERE id = ?").run(domainId);
    const res = await compose();
    assert.equal(res.status, 400);
    await res.body?.cancel();
    sqlite.prepare("UPDATE domains SET verified = 1 WHERE id = ?").run(domainId);
  });
});
