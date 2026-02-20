import { Elysia } from "elysia";
import {
  getUser,
  createUser,
  createDomain,
  getDomain,
  listUserDomains,
  updateDomain,
  deleteDomain,
  countUserDomains,
  createAlias,
  getAlias,
  listAliases,
  updateAlias,
  deleteAlias,
  countAliases,
  createRule,
  listRules,
  deleteRule,
  listLogs,
  PLANS,
  updateUserSubscription,
  getUserBySubscriptionId,
  extendSubscriptionPeriod,
  getUserPlanLimits,
  setVerifyToken,
  getUserByVerifyToken,
  verifyUserEmail,
  createPendingCheckout,
  getPendingCheckout,
  deletePendingCheckout,
  setPasswordToken,
  getEmailByPasswordToken,
  deletePasswordToken,
  updateUserPassword,
  isWebhookProcessed,
  markWebhookProcessed,
  createUserIfNotExists,
  getQueueDepth,
  getDeadLetterCount,
  // Mesa + outbound
  listConversations,
  getConversation,
  updateConversation,
  listMessages,
  addMessage,
  addNote,
  listNotes,
  createAgent,
  getAgentByEmail,
  listAgents,
  deleteAgent,
  countAgents,
  createAgentInvite,
  getAgentInvite,
  deleteAgentInvite,
  addSuppression,
  isSuppressed,
  incrementSendCount,
  getSendCount,
  createBulkJob,
  getBulkJob,
  updateBulkJob,
  listPendingBulkJobs,
  getDomainMesaSettings,
  setDomainMesaEnabled,
  PLAN_MESA_LIMITS,
  listAllUsers,
  deleteUser,
} from "./db.ts";
import {
  hashPassword,
  verifyPassword,
  signJwt,
  makeAuthCookie,
  clearAuthCookie,
  getAuthUser,
} from "./auth.ts";
import { checkRateLimit } from "./rate-limit.ts";
import {
  verifyDomain,
  checkDomainStatus,
  createReceiptRule,
  deleteReceiptRule,
  sendFromDomain,
  sendAlert,
  checkSesHealth,
  putBackupToS3,
  deleteOldBackups,
  getConfigSetName,
  listBackups,
  getBackupFromS3,
  deleteBackupFromS3,
  deleteConfigurationSet,
  deleteDomainIdentity,
} from "./ses.ts";
import { processInbound } from "./forwarding.ts";
import { log } from "./logger.ts";
import "./cron.ts";

// --- Fail-fast env validation (deferred for Deno Deploy compatibility) ---
let envChecked = false;
function ensureEnv() {
  if (envChecked) return;
  const REQUIRED_ENV = [
    "JWT_SECRET",
    "MP_ACCESS_TOKEN",
    "MP_WEBHOOK_SECRET",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
  ];
  for (const key of REQUIRED_ENV) {
    if (!Deno.env.get(key)) throw new Error(`Missing required env var: ${key}`);
  }
  envChecked = true;
}

// --- Helpers ---

function getMainDomainUrl(): string {
  const raw = Deno.env.get("MAIN_DOMAIN") ?? "localhost:8000";
  const bare = raw.replace(/^https?:\/\//, "").replace(/\/+$/, "");
  return `https://${bare}`;
}

const PUBLIC_DIR = new URL("./public", import.meta.url).pathname;

async function serveStatic(path: string): Promise<Response> {
  try {
    const file = await Deno.readFile(`${PUBLIC_DIR}${path}`);
    const ext = path.split(".").pop() ?? "";
    const types: Record<string, string> = {
      html: "text/html; charset=utf-8",
      js: "application/javascript; charset=utf-8",
      css: "text/css; charset=utf-8",
      png: "image/png",
      svg: "image/svg+xml",
      ico: "image/x-icon",
      xml: "application/xml; charset=utf-8",
      txt: "text/plain; charset=utf-8",
    };
    return new Response(file, {
      headers: { "content-type": types[ext] ?? "application/octet-stream" },
    });
  } catch {
    return new Response("Not found", { status: 404 });
  }
}

function getIp(request: Request): string {
  return (
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    request.headers.get("cf-connecting-ip") ??
    "unknown"
  );
}

async function rateLimitGuard(
  ip: string,
  limit: number,
  windowMs: number,
): Promise<Response | null> {
  const result = await checkRateLimit(ip, limit, windowMs);
  if (!result.allowed) {
    const retryAfter = Math.ceil((result.resetAt - Date.now()) / 1000);
    return new Response(JSON.stringify({ error: "Demasiadas solicitudes" }), {
      status: 429,
      headers: {
        "content-type": "application/json",
        "retry-after": String(retryAfter),
      },
    });
  }
  return null;
}

// --- Admin check ---

function isAdmin(email: string): boolean {
  const admins = (Deno.env.get("ADMIN_EMAILS") ?? "").split(",").map(e => e.trim().toLowerCase());
  return admins.includes(email.toLowerCase());
}

// --- Backup logic (shared by cron + admin endpoint) ---

async function runBackup(): Promise<{ key: string; users: number }> {
  const backupData: Record<string, unknown>[] = [];
  const { _getKv } = await import("./db.ts");
  const kv = _getKv();

  for await (const entry of kv.list<any>({ prefix: ["users"] })) {
    const user = entry.value;
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

  const dateStr = new Date().toISOString().split("T")[0];
  const key = `mailmask-backup-${dateStr}.json`;
  await putBackupToS3(key, JSON.stringify(backupData, null, 2));
  await deleteOldBackups();
  return { key, users: backupData.length };
}

// --- SNS signature verification ---

const snscertCache = new Map<string, string>();

async function fetchSnsCert(url: string): Promise<string> {
  const cached = snscertCache.get(url);
  if (cached) return cached;

  const parsed = new URL(url);
  if (
    !parsed.hostname.endsWith(".amazonaws.com") ||
    parsed.protocol !== "https:"
  ) {
    throw new Error("Invalid SNS certificate URL");
  }

  const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`Failed to fetch SNS cert: ${res.status}`);
  const pem = await res.text();
  snscertCache.set(url, pem);
  return pem;
}

function buildSnsStringToSign(body: Record<string, string>): string {
  const type = body.Type;
  let fields: string[];
  if (type === "Notification") {
    fields = ["Message", "MessageId"];
    if (body.Subject) fields.push("Subject");
    fields.push("Timestamp", "TopicArn", "Type");
  } else {
    // SubscriptionConfirmation / UnsubscribeConfirmation
    fields = [
      "Message",
      "MessageId",
      "SubscribeURL",
      "Timestamp",
      "TopicArn",
      "Type",
    ];
  }
  return fields.map((f) => `${f}\n${body[f]}`).join("\n") + "\n";
}

async function verifySnsSignature(
  body: Record<string, string>,
): Promise<boolean> {
  const expectedTopicArn = Deno.env.get("SNS_TOPIC_ARN");
  if (expectedTopicArn && body.TopicArn !== expectedTopicArn) return false;

  const certUrl = body.SigningCertURL;
  if (!certUrl) return false;

  try {
    const pem = await fetchSnsCert(certUrl);
    const stringToSign = buildSnsStringToSign(body);

    const { createVerify } = await import("node:crypto");
    const verifier = createVerify("SHA1");
    verifier.update(stringToSign);
    return verifier.verify(pem, body.Signature, "base64");
  } catch (err) {
    log("error", "server", "SNS signature verification failed", { error: String(err) });
    return false;
  }
}

const GRACE_PERIOD_MS = 15 * 24 * 60 * 60 * 1000; // 15 days

async function checkEmailVerified(email: string): Promise<Response | null> {
  const user = await getUser(email);
  if (!user) return null;
  if (user.emailVerified) return null;
  const createdAt = new Date(user.createdAt).getTime();
  if (Date.now() - createdAt < GRACE_PERIOD_MS) return null;
  return new Response(
    JSON.stringify({ error: "Verifica tu email para continuar" }),
    {
      status: 403,
      headers: { "content-type": "application/json" },
    },
  );
}

// --- SSRF protection ---

function isPrivateUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return true;
    const hostname = parsed.hostname.toLowerCase();
    if (hostname === "localhost" || hostname === "[::1]") return true;
    // IPv6 private ranges
    if (hostname.startsWith("[fc") || hostname.startsWith("[fd") || hostname.startsWith("[fe80")) return true;
    // IPv4 checks
    const ipv4Match = hostname.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (ipv4Match) {
      const [, a, b] = ipv4Match.map(Number);
      if (a === 127) return true; // loopback
      if (a === 10) return true; // 10.x.x.x
      if (a === 172 && b >= 16 && b <= 31) return true; // 172.16-31.x.x
      if (a === 192 && b === 168) return true; // 192.168.x.x
      if (a === 169 && b === 254) return true; // link-local
      if (a === 0) return true; // 0.x.x.x
    }
    return false;
  } catch {
    return true; // invalid URL = reject
  }
}

// --- App ---

const app = new Elysia()

  // --- CORS ---
  .onRequest(({ request }) => {
    ensureEnv();
    const isDeploy = !!Deno.env.get("DENO_DEPLOYMENT_ID");
    const corsOrigin = isDeploy
      ? getMainDomainUrl()
      : request.headers.get("origin") || "http://localhost:8000";
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "access-control-allow-origin": corsOrigin,
          "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS",
          "access-control-allow-headers": "content-type",
          "access-control-allow-credentials": "true",
          "access-control-max-age": "86400",
        },
      });
    }
  })
  .onAfterHandle(({ request, response }) => {
    const isDeploy = !!Deno.env.get("DENO_DEPLOYMENT_ID");
    const corsOrigin = isDeploy
      ? getMainDomainUrl()
      : request.headers.get("origin") || "http://localhost:8000";
    if (response instanceof Response) {
      response.headers.set("access-control-allow-origin", corsOrigin);
      response.headers.set("access-control-allow-credentials", "true");
      response.headers.set("x-frame-options", "DENY");
      response.headers.set("x-content-type-options", "nosniff");
      response.headers.set(
        "referrer-policy",
        "strict-origin-when-cross-origin",
      );
      response.headers.set(
        "content-security-policy",
        "default-src 'self'; style-src 'self'; img-src 'self' data:; script-src 'self'",
      );
    }
    return response;
  })

  // --- Health ---
  .get("/health", async () => {
    const [queueDepth, deadLetterCount, sesOk] = await Promise.all([
      getQueueDepth(),
      getDeadLetterCount(),
      checkSesHealth(),
    ]);
    const healthy = queueDepth <= 50 && deadLetterCount === 0 && sesOk;
    return new Response(JSON.stringify({
      status: healthy ? "ok" : "degraded",
      service: "mailmask",
      timestamp: new Date().toISOString(),
      queueDepth,
      deadLetterCount,
      ses: sesOk ? "ok" : "unreachable",
    }), {
      status: healthy ? 200 : 503,
      headers: { "content-type": "application/json" },
    });
  })

  // --- Static pages ---
  .get("/", () => serveStatic("/landing.html"))
  .get("/login", () => serveStatic("/login.html"))
  .get("/register", () => serveStatic("/register.html"))
  .get("/app", () => serveStatic("/app.html"))
  .get("/css/*", ({ params }) => serveStatic(`/css/${params["*"]}`))
  .get("/js/*", ({ params }) => serveStatic(`/js/${params["*"]}`))
  .get("/favicon.svg", () => serveStatic("/favicon.svg"))
  .get("/landing", () => serveStatic("/landing.html"))
  .get("/mesa", () => serveStatic("/mesa.html"))
  .get("/admin", async ({ request }) => {
    const user = await getAuthUser(request);
    if (!user || !isAdmin(user.email)) return new Response("Not found", { status: 404 });
    return serveStatic("/admin.html");
  })
  .get("/set-password", () => serveStatic("/set-password.html"))
  .get("/forgot-password", () => serveStatic("/forgot-password.html"))
  .get("/terms", () => serveStatic("/terms.html"))
  .get("/privacy", () => serveStatic("/privacy.html"))
  .get("/robots.txt", () => serveStatic("/robots.txt"))
  .get("/sitemap.xml", () => serveStatic("/sitemap.xml"))

  // --- Auth ---

  .post("/api/auth/register", async ({ request }) => {
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 5, 60_000);
    if (limited) return limited;

    const body = await request.json();
    const email = (body.email ?? "").toLowerCase().trim();
    const password = body.password;
    if (!email || !password)
      return new Response(
        JSON.stringify({ error: "Email y contraseña requeridos" }),
        { status: 400 },
      );
    if (password.length < 8)
      return new Response(
        JSON.stringify({ error: "Contraseña mínimo 8 caracteres" }),
        { status: 400 },
      );

    const existing = await getUser(email);
    if (existing)
      return new Response(
        JSON.stringify({ error: "Este email ya está registrado" }),
        { status: 409 },
      );

    const hash = await hashPassword(password);
    await createUser(email, hash);

    // Send verification email
    const verifyToken = crypto.randomUUID();
    await setVerifyToken(email, verifyToken);
    const verifyUrl = `${getMainDomainUrl()}/api/auth/verify-email?token=${verifyToken}`;
    const alertFrom =
      Deno.env.get("ALERT_FROM_EMAIL") ?? "noreply@mailmask.app";
    try {
      await sendFromDomain(
        alertFrom,
        email,
        "Verifica tu email — MailMask",
        `Hola,\n\nVerifica tu email haciendo clic en este enlace:\n${verifyUrl}\n\nTienes 15 días para verificar tu cuenta.\n\n— MailMask`,
      );
    } catch (err) {
      log("error", "auth", "Failed to send verification email", { error: String(err) });
    }

    const token = await signJwt({ email });
    return new Response(JSON.stringify({ ok: true }), {
      status: 201,
      headers: {
        "content-type": "application/json",
        "set-cookie": makeAuthCookie(token),
      },
    });
  })

  .post("/api/auth/login", async ({ request }) => {
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 10, 60_000);
    if (limited) return limited;

    const loginBody = await request.json();
    const email = (loginBody.email ?? "").toLowerCase().trim();
    const password = loginBody.password;
    if (!email || !password)
      return new Response(
        JSON.stringify({ error: "Email y contraseña requeridos" }),
        { status: 400 },
      );

    // Per-email rate limit: 5 attempts per 15 minutes (prevents credential stuffing across IPs)
    const emailRl = await checkRateLimit(`login:${email}`, 5, 15 * 60_000);
    if (!emailRl.allowed) {
      const waitMin = Math.max(1, Math.ceil((emailRl.resetAt - Date.now()) / 60_000));
      return new Response(
        JSON.stringify({ error: `Demasiados intentos. Esperá ${waitMin} minuto${waitMin > 1 ? "s" : ""}.` }),
        { status: 429, headers: { "content-type": "application/json", "retry-after": String(Math.ceil((emailRl.resetAt - Date.now()) / 1000)) } },
      );
    }

    const user = await getUser(email);
    if (!user)
      return new Response(JSON.stringify({ error: "Credenciales inválidas" }), {
        status: 401,
      });

    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid)
      return new Response(JSON.stringify({ error: "Credenciales inválidas" }), {
        status: 401,
      });

    const token = await signJwt({ email });
    return new Response(JSON.stringify({ ok: true, email }), {
      headers: {
        "content-type": "application/json",
        "set-cookie": makeAuthCookie(token),
      },
    });
  })

  .post("/api/auth/logout", () => {
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        "content-type": "application/json",
        "set-cookie": clearAuthCookie(),
      },
    });
  })

  .get("/api/auth/me", async ({ request }) => {
    const auth = await getAuthUser(request);
    if (!auth)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });
    const user = await getUser(auth.email);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });
    const domains = await listUserDomains(user.email);
    const limits = getUserPlanLimits(user);

    // Build usage data
    const aliasesPerDomain = await Promise.all(
      domains.map(async (d) => ({
        domain: d.domain,
        domainId: d.id,
        current: await countAliases(d.id),
        limit: limits.aliases,
      })),
    );

    return new Response(
      JSON.stringify({
        email: user.email,
        domainsCount: domains.length,
        subscription: {
          ...(user.subscription ?? { plan: "basico", status: "none" }),
          currentPeriodEnd: user.subscription?.currentPeriodEnd ?? null,
        },
        limits,
        emailVerified: user.emailVerified ?? false,
        usage: {
          domains: { current: domains.length, limit: limits.domains },
          aliasesPerDomain,
        },
      }),
      {
        headers: { "content-type": "application/json" },
      },
    );
  })

  .get("/api/auth/verify-email", async ({ request }) => {
    const url = new URL(request.url);
    const token = url.searchParams.get("token");
    if (!token) return new Response("Token inválido", { status: 400 });

    const user = await getUserByVerifyToken(token);
    if (!user)
      return new Response("Token inválido o expirado", { status: 400 });

    await verifyUserEmail(user.email);
    // Redirect to app with success message
    return new Response(null, {
      status: 302,
      headers: { location: "/app?verified=true" },
    });
  })

  .post("/api/auth/forgot-password", async ({ request }) => {
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 3, 60_000);
    if (limited) return limited;

    const forgotBody = await request.json();
    const email = (forgotBody.email ?? "").toLowerCase().trim();
    if (!email)
      return new Response(JSON.stringify({ error: "Email requerido" }), {
        status: 400,
      });

    const emailLimited = await checkRateLimit(`forgot:${email}`, 1, 300_000);
    if (!emailLimited.allowed) {
      const waitMs = emailLimited.resetAt - Date.now();
      const waitMin = Math.max(1, Math.ceil(waitMs / 60_000));
      return new Response(
        JSON.stringify({
          error: `Ya enviamos un enlace. Esperá ${waitMin} minuto${waitMin > 1 ? "s" : ""} antes de intentar de nuevo.`,
        }),
        { status: 429, headers: { "content-type": "application/json" } },
      );
    }

    const user = await getUser(email);
    if (user) {
      const token = crypto.randomUUID();
      await setPasswordToken(email, token);
      const resetUrl = `${getMainDomainUrl()}/set-password?token=${token}`;
      const alertFrom =
        Deno.env.get("ALERT_FROM_EMAIL") ?? "noreply@mailmask.app";
      try {
        await sendFromDomain(
          alertFrom,
          email,
          "Restablecer contraseña — MailMask",
          `Hola,\n\nRecibimos una solicitud para restablecer tu contraseña.\n\nHaz clic en este enlace para crear una nueva contraseña:\n${resetUrl}\n\nEste enlace es válido por 7 días.\n\nSi no solicitaste esto, puedes ignorar este email.\n\n— https://MailMask.deno.dev`,
        );
      } catch (err) {
        log("error", "auth", "Failed to send password reset email", { error: String(err) });
      }
    }

    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  })

  .post("/api/auth/set-password", async ({ request }) => {
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 5, 60_000);
    if (limited) return limited;

    const { token, password } = await request.json();
    if (!token || !password)
      return new Response(
        JSON.stringify({ error: "Token y contraseña requeridos" }),
        { status: 400 },
      );
    if (password.length < 8)
      return new Response(
        JSON.stringify({ error: "Contraseña mínimo 8 caracteres" }),
        { status: 400 },
      );

    const email = await getEmailByPasswordToken(token);
    if (!email)
      return new Response(
        JSON.stringify({ error: "Token inválido o expirado" }),
        { status: 400 },
      );

    const hash = await hashPassword(password);
    await updateUserPassword(email, hash);
    await verifyUserEmail(email);
    await deletePasswordToken(token);

    const jwt = await signJwt({ email });
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        "content-type": "application/json",
        "set-cookie": makeAuthCookie(jwt),
      },
    });
  })

  // --- Domains ---

  .get("/api/domains", async ({ request }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const domains = await listUserDomains(user.email);
    return new Response(JSON.stringify(domains), {
      headers: { "content-type": "application/json" },
    });
  })

  .post("/api/domains", async ({ request }) => {
    const auth = await getAuthUser(request);
    if (!auth)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });
    const user = (await getUser(auth.email))!;

    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 10, 60_000);
    if (limited) return limited;

    // Check email verification grace period
    const verifyBlock = await checkEmailVerified(auth.email);
    if (verifyBlock) return verifyBlock;

    // Check plan limits
    const limits = getUserPlanLimits(user);
    if (limits.domains === 0) {
      return new Response(
        JSON.stringify({
          error: "Necesitas un plan activo para agregar dominios",
        }),
        { status: 402 },
      );
    }
    const currentCount = await countUserDomains(user.email);
    if (currentCount >= limits.domains) {
      return new Response(
        JSON.stringify({
          error: `Tu plan permite máximo ${limits.domains} dominio(s)`,
        }),
        { status: 400 },
      );
    }

    const { domain } = await request.json();
    if (!domain || typeof domain !== "string") {
      return new Response(JSON.stringify({ error: "Dominio requerido" }), {
        status: 400,
      });
    }

    // Validate domain format
    const domainRegex =
      /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
      return new Response(
        JSON.stringify({ error: "Formato de dominio inválido" }),
        { status: 400 },
      );
    }

    // Check if domain already registered
    const existing = await (await import("./db.ts")).getDomainByName(domain);
    if (existing) {
      return new Response(
        JSON.stringify({ error: "Este dominio ya está registrado" }),
        { status: 409 },
      );
    }

    // Verify with SES
    let dnsRecords;
    try {
      dnsRecords = await verifyDomain(domain);
    } catch (err) {
      return new Response(
        JSON.stringify({
          error: "Error verificando dominio con SES",
          details: String(err),
        }),
        { status: 500 },
      );
    }

    // Create receipt rule for inbound (clean up residual rule first)
    try { await deleteReceiptRule(domain); } catch { /* ignore */ }
    try {
      await createReceiptRule(domain);
    } catch (err) {
      const errStr = String(err);
      if (!errStr.includes("AlreadyExists")) {
        log("error", "ses", "Failed to create receipt rule", { domain, error: errStr });
        return new Response(
          JSON.stringify({ error: "No se pudo configurar la recepción de emails. Intenta de nuevo." }),
          { status: 500 },
        );
      }
    }

    const newDomain = await createDomain(
      user.email,
      domain,
      dnsRecords.dkimTokens,
      dnsRecords.verificationToken,
    );

    // Return DNS records the customer needs to configure
    return new Response(
      JSON.stringify({
        domain: newDomain,
        dnsRecords: {
          mx: {
            type: "MX",
            name: domain,
            value: "10 inbound-smtp.us-east-1.amazonaws.com",
            priority: 10,
          },
          verification: {
            type: "TXT",
            name: `_amazonses.${domain}`,
            value: dnsRecords.verificationToken,
          },
          dkim: dnsRecords.dkimTokens.map((token: string) => ({
            type: "CNAME",
            name: `${token}._domainkey.${domain}`,
            value: `${token}.dkim.amazonses.com`,
          })),
        },
      }),
      {
        status: 201,
        headers: { "content-type": "application/json" },
      },
    );
  })

  .get("/api/domains/:id", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }

    return new Response(JSON.stringify(domain), {
      headers: { "content-type": "application/json" },
    });
  })

  .post("/api/domains/:id/verify", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }

    const status = await checkDomainStatus(domain.domain);
    await updateDomain(domain.id, { verified: status.verified });

    return new Response(
      JSON.stringify({
        domain: domain.domain,
        verified: status.verified,
        dkimVerified: status.dkimVerified,
      }),
      {
        headers: { "content-type": "application/json" },
      },
    );
  })

  .delete("/api/domains/:id", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }

    // Clean up all SES resources (best effort)
    try { await deleteReceiptRule(domain.domain); } catch { /* best effort */ }
    try { await deleteConfigurationSet(domain.domain); } catch { /* best effort */ }
    try { await deleteDomainIdentity(domain.domain); } catch { /* best effort */ }

    await deleteDomain(params.id);
    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  })

  // --- Aliases ---

  .get("/api/domains/:id/aliases", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }

    const aliases = await listAliases(domain.id);
    return new Response(JSON.stringify(aliases), {
      headers: { "content-type": "application/json" },
    });
  })

  .post("/api/domains/:id/aliases", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });
    const fullUser = (await getUser(auth.email))!;

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== auth.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }

    const verifyBlock = await checkEmailVerified(auth.email);
    if (verifyBlock) return verifyBlock;

    const aliasLimits = getUserPlanLimits(fullUser);
    const count = await countAliases(domain.id);
    if (count >= aliasLimits.aliases) {
      return new Response(
        JSON.stringify({
          error: `Tu plan permite máximo ${aliasLimits.aliases} máscaras por dominio`,
        }),
        { status: 400 },
      );
    }

    const { alias, destinations } = await request.json();
    if (!alias || !destinations?.length) {
      return new Response(
        JSON.stringify({ error: "Alias y destinos requeridos" }),
        { status: 400 },
      );
    }

    // Validate alias format (alphanumeric, dots, hyphens, or * for catch-all)
    if (alias !== "*" && !/^[a-zA-Z0-9._-]+$/.test(alias)) {
      return new Response(
        JSON.stringify({ error: "Formato de alias inválido" }),
        { status: 400 },
      );
    }

    // Validate destination emails
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    const invalid = destinations.filter((d: string) => !emailRegex.test(d));
    if (invalid.length) {
      return new Response(
        JSON.stringify({
          error: `Email(s) de destino inválido(s): ${invalid.join(", ")}`,
        }),
        { status: 400 },
      );
    }

    const existing = await getAlias(domain.id, alias);
    if (existing) {
      return new Response(JSON.stringify({ error: "Este alias ya existe" }), {
        status: 409,
      });
    }

    const newAlias = await createAlias(domain.id, alias, destinations);
    return new Response(JSON.stringify(newAlias), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  })

  .put("/api/domains/:id/aliases/:alias", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }

    const body = await request.json();

    // Whitelist allowed fields
    const updates: Record<string, unknown> = {};
    if (typeof body.enabled === "boolean") updates.enabled = body.enabled;
    if (Array.isArray(body.destinations)) {
      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      const invalid = body.destinations.filter((d: string) => typeof d !== "string" || !emailRegex.test(d));
      if (invalid.length) {
        return new Response(
          JSON.stringify({ error: `Email(s) de destino inválido(s): ${invalid.join(", ")}` }),
          { status: 400 },
        );
      }
      if (body.destinations.length === 0) {
        return new Response(
          JSON.stringify({ error: "Se requiere al menos un destino" }),
          { status: 400 },
        );
      }
      updates.destinations = body.destinations;
    }

    const updated = await updateAlias(domain.id, params.alias, updates);
    if (!updated)
      return new Response(JSON.stringify({ error: "Alias no encontrado" }), {
        status: 404,
      });

    return new Response(JSON.stringify(updated), {
      headers: { "content-type": "application/json" },
    });
  })

  .delete("/api/domains/:id/aliases/:alias", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }

    const deleted = await deleteAlias(domain.id, params.alias);
    if (!deleted)
      return new Response(JSON.stringify({ error: "Alias no encontrado" }), {
        status: 404,
      });

    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  })

  // --- Rules ---

  .get("/api/domains/:id/rules", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }

    const rules = await listRules(domain.id);
    return new Response(JSON.stringify(rules), {
      headers: { "content-type": "application/json" },
    });
  })

  .post("/api/domains/:id/rules", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });
    const fullUser = (await getUser(auth.email))!;

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== auth.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }

    const ruleLimits = getUserPlanLimits(fullUser);
    const existingRules = await listRules(domain.id);
    if (existingRules.length >= ruleLimits.rules) {
      return new Response(
        JSON.stringify({
          error: `Tu plan permite máximo ${ruleLimits.rules} reglas por dominio`,
        }),
        { status: 400 },
      );
    }

    const {
      field,
      match,
      value,
      action,
      target,
      priority = 0,
      enabled = true,
    } = await request.json();
    if (!field || !match || !value || !action) {
      return new Response(
        JSON.stringify({
          error: "Campos requeridos: field, match, value, action",
        }),
        { status: 400 },
      );
    }

    const validFields = ["to", "from", "subject"];
    const validMatches = ["contains", "equals", "regex"];
    const validActions = ["forward", "webhook", "discard"];

    if (
      !validFields.includes(field) ||
      !validMatches.includes(match) ||
      !validActions.includes(action)
    ) {
      return new Response(
        JSON.stringify({
          error: "Valores inválidos para field, match o action",
        }),
        { status: 400 },
      );
    }

    if (action !== "discard" && !target) {
      return new Response(
        JSON.stringify({
          error: "Target requerido para acciones forward y webhook",
        }),
        { status: 400 },
      );
    }

    // SSRF: validate webhook targets aren't private IPs
    if (action === "webhook" && target && isPrivateUrl(target)) {
      return new Response(
        JSON.stringify({ error: "URL de webhook no permitida (dirección privada)" }),
        { status: 400 },
      );
    }

    // ReDoS: limit regex pattern length
    if (match === "regex") {
      if (value.length > 200) {
        return new Response(
          JSON.stringify({ error: "Patrón regex demasiado largo (máx 200 caracteres)" }),
          { status: 400 },
        );
      }
      try {
        new RegExp(value);
      } catch {
        return new Response(
          JSON.stringify({ error: "Patrón regex inválido" }),
          { status: 400 },
        );
      }
    }

    const rule = await createRule(domain.id, {
      field,
      match,
      value,
      action,
      target: target ?? "",
      priority,
      enabled,
    });
    return new Response(JSON.stringify(rule), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  })

  .delete("/api/domains/:id/rules/:ruleId", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }

    const deleted = await deleteRule(domain.id, params.ruleId);
    if (!deleted)
      return new Response(JSON.stringify({ error: "Regla no encontrada" }), {
        status: 404,
      });

    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  })

  // --- Logs ---

  .get("/api/domains/:id/logs", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }

    const url = new URL(request.url);
    const limit = Math.min(
      parseInt(url.searchParams.get("limit") ?? "50"),
      100,
    );

    const logs = await listLogs(domain.id, limit);
    return new Response(JSON.stringify(logs), {
      headers: { "content-type": "application/json" },
    });
  })

  // --- Billing ---

  .post("/api/billing/guest-checkout", async ({ request }) => {
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 5, 60_000);
    if (limited) return limited;

    const { plan = "basico", billing = "monthly" } = await request
      .json()
      .catch(() => ({ plan: "basico", billing: "monthly" }));
    const planKey = plan as keyof typeof PLANS;
    if (!PLANS[planKey]) {
      return new Response(JSON.stringify({ error: "Plan inválido" }), {
        status: 400,
      });
    }
    const isYearly = billing === "yearly";

    const token = crypto.randomUUID();
    await createPendingCheckout(token, isYearly ? `${planKey}:yearly` : planKey);

    const { PreApproval } = await import("mercadopago");
    const mpAccessToken = Deno.env.get("MP_ACCESS_TOKEN");
    if (!mpAccessToken) {
      return new Response(
        JSON.stringify({ error: "MercadoPago no configurado" }),
        { status: 500 },
      );
    }

    const preApproval = new PreApproval({ accessToken: mpAccessToken });
    const backUrl = getMainDomainUrl() + "/landing?success=1";

    try {
      const billingLabel = isYearly ? "Anual" : "Mensual";
      // deno-lint-ignore no-explicit-any
      const body: any = {
        reason: `MailMask — Plan ${planKey.charAt(0).toUpperCase() + planKey.slice(1)} (${billingLabel})`,
        auto_recurring: {
          frequency: isYearly ? 12 : 1,
          frequency_type: "months",
          transaction_amount: isYearly ? PLANS[planKey].yearlyPrice / 100 : PLANS[planKey].price / 100,
          currency_id: "MXN",
          ...(isYearly ? {} : {
            free_trial: {
              frequency: 1,
              frequency_type: "months",
            },
          }),
        },
        payer_email: "guest@mailmask.app",
        back_url: backUrl,
        external_reference: token,
      };
      const result = await preApproval.create({ body });

      return new Response(JSON.stringify({ init_point: result.init_point }), {
        headers: { "content-type": "application/json" },
      });
    } catch (err) {
      log("error", "billing", "MP guest-checkout error", { error: String(err) });
      return new Response(
        JSON.stringify({ error: "Error al crear suscripción en MercadoPago" }),
        {
          status: 500,
          headers: { "content-type": "application/json" },
        },
      );
    }
  })

  .post("/api/billing/checkout", async ({ request }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const { plan = "basico", billing = "monthly" } = await request
      .json()
      .catch(() => ({ plan: "basico", billing: "monthly" }));
    const planKey = plan as keyof typeof PLANS;
    if (!PLANS[planKey]) {
      return new Response(JSON.stringify({ error: "Plan inválido" }), {
        status: 400,
      });
    }
    const isYearly = billing === "yearly";

    const { PreApproval } = await import("mercadopago");
    const mpAccessToken = Deno.env.get("MP_ACCESS_TOKEN");
    if (!mpAccessToken) {
      return new Response(
        JSON.stringify({ error: "MercadoPago no configurado" }),
        { status: 500 },
      );
    }

    const preApproval = new PreApproval({ accessToken: mpAccessToken });
    const backUrl = getMainDomainUrl() + "/app?billing=success";

    try {
      const billingLabel = isYearly ? "Anual" : "Mensual";
      // deno-lint-ignore no-explicit-any
      const body: any = {
        reason: `MailMask — Plan ${planKey.charAt(0).toUpperCase() + planKey.slice(1)} (${billingLabel})`,
        auto_recurring: {
          frequency: isYearly ? 12 : 1,
          frequency_type: "months",
          transaction_amount: isYearly ? PLANS[planKey].yearlyPrice / 100 : PLANS[planKey].price / 100,
          currency_id: "MXN",
          ...(isYearly ? {} : {
            free_trial: {
              frequency: 1,
              frequency_type: "months",
            },
          }),
        },
        payer_email: "guest@mailmask.app",
        back_url: backUrl,
        external_reference: user.email,
      };
      const result = await preApproval.create({ body });

      return new Response(JSON.stringify({ init_point: result.init_point }), {
        headers: { "content-type": "application/json" },
      });
    } catch (err: any) {
      const detail = String(err?.message ?? err?.cause ?? err);
      log("error", "billing", "MP checkout error", { error: detail });
      const msg = detail.includes("same user")
        ? "No puedes suscribirte con la misma cuenta del proveedor de pagos. Usa otra cuenta de MercadoPago."
        : "Error al crear suscripción en MercadoPago";
      return new Response(
        JSON.stringify({ error: msg }),
        { status: 500, headers: { "content-type": "application/json" } },
      );
    }
  })

  .post("/api/webhooks/mercadopago", async ({ request }) => {
    // Validate HMAC signature
    const secret = Deno.env.get("MP_WEBHOOK_SECRET");
    if (!secret) {
      log("error", "webhook", "MP_WEBHOOK_SECRET not configured");
      return new Response("Server misconfigured", { status: 500 });
    }
    const xSignature = request.headers.get("x-signature") ?? "";
    const xRequestId = request.headers.get("x-request-id") ?? "";
    const url = new URL(request.url);
    const dataId = url.searchParams.get("data.id") ?? "";

    // Parse ts and v1 from x-signature
    const parts = Object.fromEntries(
      xSignature.split(",").map((p) => {
        const [k, ...v] = p.trim().split("=");
        return [k, v.join("=")];
      }),
    );
    const ts = parts["ts"] ?? "";
    const v1 = parts["v1"] ?? "";

    const manifest = `id:${dataId};request-id:${xRequestId};ts:${ts};`;
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(manifest),
    );
    const computed = Array.from(new Uint8Array(sig))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    if (computed !== v1) {
      log("warn", "webhook", "MP webhook: invalid signature");
      return new Response("Unauthorized", { status: 401 });
    }

    const body = await request.json();
    log("info", "webhook", "MP webhook received", { type: body.type, dataId: body.data?.id });

    // Handle subscription_preapproval events
    if (body.type === "subscription_preapproval" && body.data?.id) {
      try {
        // Idempotency: skip if already successfully processed
        if (await isWebhookProcessed(body.data.id)) {
          return new Response("OK", { status: 200 });
        }

        const mpAccessToken = Deno.env.get("MP_ACCESS_TOKEN");
        if (!mpAccessToken) {
          log("error", "webhook", "MP_ACCESS_TOKEN not configured");
          return new Response("Server misconfigured", { status: 500 });
        }

        const subRes = await fetch(
          `https://api.mercadopago.com/preapproval/${body.data.id}`,
          {
            headers: { Authorization: `Bearer ${mpAccessToken}` },
            signal: AbortSignal.timeout(10_000),
          },
        );
        const sub = await subRes.json();

        log("info", "webhook", "MP subscription fetched", { payer_email: sub.payer_email, external_reference: sub.external_reference, status: sub.status });

        const externalRef = sub.external_reference ?? "";
        const UUID_RE =
          /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        const isGuestCheckout = UUID_RE.test(externalRef);

        // Resolve email: for guest checkout use payer_email from MP, otherwise external_reference is the email
        let email = isGuestCheckout ? sub.payer_email : externalRef;
        if (!email) email = sub.payer_email;
        if (email) email = email.toLowerCase().trim();

        if (email) {
          if (sub.status === "authorized") {
            // Check if this is a renewal for an existing active user
            const existingUser = await getUser(email);
            const existingSub = existingUser?.subscription;
            const isYearlyBilling = sub.auto_recurring?.frequency === 12;
            const bufferDays = isYearlyBilling ? 370 : 35;

            if (existingSub && existingSub.mpSubscriptionId === body.data.id && existingSub.status === "active") {
              // Recurring charge — just extend the period
              await extendSubscriptionPeriod(email, bufferDays);
              log("info", "webhook", "Subscription renewed", { email, bufferDays });
            } else {
              // First activation — determine plan
              type PlanKey = "basico" | "freelancer" | "developer" | "pro" | "agencia";
              let plan: PlanKey | undefined;

              if (isGuestCheckout) {
                const pendingPlan = await getPendingCheckout(externalRef);
                if (pendingPlan) {
                  const basePlan = pendingPlan.split(":")[0];
                  if (basePlan in PLANS) {
                    plan = basePlan as PlanKey;
                  }
                }
                await deletePendingCheckout(externalRef);
              }

              if (!plan) {
                const amount = sub.auto_recurring?.transaction_amount ?? 0;
                const amountToPlan: Record<number, PlanKey> = {
                  49: "basico", 449: "freelancer", 999: "developer", 299: "pro",
                  490: "basico", 4490: "freelancer", 9990: "developer",
                };
                plan = amountToPlan[amount];
              }

              if (!plan) {
                log("warn", "webhook", "Could not determine plan, not activating", { email, amount: sub.auto_recurring?.transaction_amount });
                return new Response("OK", { status: 200 });
              }

              // Guest checkout: create user if not exists
              if (isGuestCheckout) {
                const created = await createUserIfNotExists(email, await hashPassword(crypto.randomUUID()));
                if (created) log("info", "webhook", "Guest user created", { email });
              }

              const periodEnd = new Date();
              periodEnd.setDate(periodEnd.getDate() + bufferDays);

              await updateUserSubscription(email, {
                plan,
                status: "active",
                mpSubscriptionId: body.data.id,
                currentPeriodEnd: periodEnd.toISOString(),
              });
              log("info", "webhook", "Subscription activated", { email, plan });

              const alertFrom = Deno.env.get("ALERT_FROM_EMAIL") ?? "noreply@mailmask.app";

              if (isGuestCheckout) {
                // Guest checkout: send welcome email with password-setup link
                const pwToken = crypto.randomUUID();
                await setPasswordToken(email, pwToken);
                const setPasswordUrl = `${getMainDomainUrl()}/set-password?token=${pwToken}`;
                try {
                  await sendFromDomain(
                    alertFrom,
                    email,
                    "¡Bienvenido a MailMask! Configura tu contraseña",
                    `¡Hola!\n\nTu suscripción al plan ${plan.charAt(0).toUpperCase() + plan.slice(1)} está activa.\n\nConfigura tu contraseña para acceder a tu cuenta:\n${setPasswordUrl}\n\nEste enlace es válido por 7 días.\n\n— MailMask`,
                  );
                  log("info", "webhook", "Welcome email sent", { email });
                } catch (err) {
                  log("error", "webhook", "Failed to send welcome email", { email, error: String(err) });
                }
              } else {
                // Authenticated checkout: send payment confirmation
                try {
                  await sendFromDomain(
                    alertFrom,
                    email,
                    "Confirmación de pago — MailMask",
                    `¡Hola!\n\nTu pago fue procesado exitosamente. Tu plan ${plan.charAt(0).toUpperCase() + plan.slice(1)} está activo.\n\nPuedes administrar tu cuenta en:\n${getMainDomainUrl()}/app\n\nGracias por usar MailMask.\n\n— MailMask`,
                  );
                  log("info", "webhook", "Payment confirmation sent", { email });
                } catch (err) {
                  log("error", "webhook", "Failed to send payment confirmation", { email, error: String(err) });
                }
              }
            }
          } else if (sub.status === "cancelled") {
            const existingUser = await getUser(email);
            const currentSub = existingUser?.subscription;
            if (currentSub && currentSub.mpSubscriptionId === body.data.id) {
              await updateUserSubscription(email, {
                ...currentSub,
                status: "cancelled",
              });
              log("info", "webhook", "Subscription cancelled", { email });
            }
          } else if (sub.status === "paused") {
            const existingUser = await getUser(email);
            const currentSub = existingUser?.subscription;
            if (currentSub && currentSub.mpSubscriptionId === body.data.id) {
              await updateUserSubscription(email, {
                ...currentSub,
                status: "past_due",
              });
              log("info", "webhook", "Subscription paused (past_due)", { email });
            }
          }

          // Mark as processed only after successful handling
          await markWebhookProcessed(body.data.id);
        }
      } catch (err) {
        log("error", "webhook", "MP webhook processing error", { error: String(err) });
        return new Response("Internal error", { status: 500 });
      }
    }

    return new Response("OK", { status: 200 });
  })

  .post("/api/billing/cancel", async ({ request }) => {
    const auth = await getAuthUser(request);
    if (!auth)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });
    const user = await getUser(auth.email);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const subId = user.subscription?.mpSubscriptionId;
    if (!subId) {
      return new Response(
        JSON.stringify({ error: "No hay suscripción activa" }),
        { status: 400 },
      );
    }

    const mpAccessToken = Deno.env.get("MP_ACCESS_TOKEN");
    if (!mpAccessToken) {
      return new Response(
        JSON.stringify({ error: "MercadoPago no configurado" }),
        { status: 500 },
      );
    }

    const res = await fetch(
      `https://api.mercadopago.com/preapproval/${subId}`,
      {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${mpAccessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ status: "cancelled" }),
        signal: AbortSignal.timeout(10_000),
      },
    );

    if (!res.ok) {
      const err = await res.text();
      log("error", "billing", "MP cancel error", { error: err });
      return new Response(
        JSON.stringify({ error: "Error al cancelar en MercadoPago" }),
        { status: 500 },
      );
    }

    await updateUserSubscription(auth.email, {
      ...user.subscription!,
      status: "cancelled",
    });
    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  })

  .get("/api/billing/status", async ({ request }) => {
    const auth = await getAuthUser(request);
    if (!auth)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });
    const user = await getUser(auth.email);
    return new Response(
      JSON.stringify({
        subscription: user?.subscription ?? { plan: "basico", status: "none" },
      }),
      {
        headers: { "content-type": "application/json" },
      },
    );
  })

  // --- Export ---

  .get("/api/export", async ({ request }) => {
    const auth = await getAuthUser(request);
    if (!auth)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      });

    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 5, 3600_000);
    if (limited) return limited;

    const domains = await listUserDomains(auth.email);
    const exportData: Record<string, unknown>[] = [];

    for (const domain of domains) {
      const aliases = await listAliases(domain.id);
      const rules = await listRules(domain.id);
      const logs = await listLogs(domain.id, 100);
      exportData.push({
        domain: domain.domain,
        domainId: domain.id,
        verified: domain.verified,
        aliases,
        rules,
        logs,
      });
    }

    const payload = {
      email: auth.email,
      exportedAt: new Date().toISOString(),
      domains: exportData,
    };

    return new Response(JSON.stringify(payload, null, 2), {
      headers: {
        "content-type": "application/json",
        "content-disposition": `attachment; filename="mailmask-export-${Date.now()}.json"`,
      },
    });
  })

  // --- Outbound send ---

  .post("/api/domains/:id/send", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    const user = (await getUser(auth.email))!;
    const limits = getUserPlanLimits(user);

    if (limits.sends === 0) {
      return new Response(JSON.stringify({ error: "Tu plan no incluye envío de emails" }), { status: 403 });
    }

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== auth.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }
    if (!domain.verified) {
      return new Response(JSON.stringify({ error: "Dominio no verificado" }), { status: 400 });
    }

    const { to, subject, html, body, replyTo, from: fromLocal } = await request.json();
    if (!to || !subject || (!html && !body)) {
      return new Response(JSON.stringify({ error: "to, subject y body/html requeridos" }), { status: 400 });
    }

    if (await isSuppressed(domain.id, to)) {
      return new Response(JSON.stringify({ error: "Destinatario en lista de supresión (bounce/complaint previo)" }), { status: 422 });
    }

    const currentSends = await getSendCount(domain.id);
    if (currentSends >= limits.sends) {
      return new Response(JSON.stringify({ error: `Límite mensual de envíos alcanzado (${limits.sends})` }), { status: 429 });
    }

    const fromAddress = `${fromLocal ?? "noreply"}@${domain.domain}`;
    try {
      const messageId = await sendFromDomain(fromAddress, to, subject, body ?? html, {
        html,
        replyTo,
        configSet: getConfigSetName(domain.domain),
      });
      await incrementSendCount(domain.id);
      return new Response(JSON.stringify({ ok: true, messageId }), {
        headers: { "content-type": "application/json" },
      });
    } catch (err) {
      log("error", "ses", "Outbound send failed", { error: String(err), domainId: domain.id });
      return new Response(JSON.stringify({ error: "Error enviando email" }), { status: 500 });
    }
  })

  // --- Bulk send ---

  .post("/api/domains/:id/send-bulk", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    const user = (await getUser(auth.email))!;
    const limits = getUserPlanLimits(user);

    if (limits.sends === 0) {
      return new Response(JSON.stringify({ error: "Tu plan no incluye envío de emails" }), { status: 403 });
    }

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== auth.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }
    if (!domain.verified) {
      return new Response(JSON.stringify({ error: "Dominio no verificado" }), { status: 400 });
    }

    const { recipients, subject, html, from: fromLocal } = await request.json();
    if (!recipients?.length || !subject || !html) {
      return new Response(JSON.stringify({ error: "recipients[], subject y html requeridos" }), { status: 400 });
    }
    if (!Array.isArray(recipients) || recipients.length > 10000) {
      return new Response(JSON.stringify({ error: "Máximo 10,000 destinatarios por lote" }), { status: 400 });
    }

    const fromAddress = `${fromLocal ?? "noreply"}@${domain.domain}`;
    const job = await createBulkJob({
      domainId: domain.id,
      recipients,
      subject,
      html,
      from: fromAddress,
      totalRecipients: recipients.length,
    });

    return new Response(JSON.stringify({ ok: true, jobId: job.id }), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  })

  .get("/api/domains/:id/bulk/:jobId", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== auth.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }

    const job = await getBulkJob(domain.id, params.jobId);
    if (!job) return new Response(JSON.stringify({ error: "Job no encontrado" }), { status: 404 });

    return new Response(JSON.stringify(job), {
      headers: { "content-type": "application/json" },
    });
  })

  // --- Mesa: conversations ---

  .get("/api/mesa/conversations", async ({ request }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const url = new URL(request.url);
    const domainId = url.searchParams.get("domainId");
    const status = url.searchParams.get("status") ?? undefined;
    const assignedTo = url.searchParams.get("assignedTo") ?? undefined;

    if (!domainId) {
      return new Response(JSON.stringify({ error: "domainId requerido" }), { status: 400 });
    }

    const domain = await getDomain(domainId);
    if (!domain) return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });

    const isOwner = domain.ownerEmail === auth.email;
    const agent = !isOwner ? await getAgentByEmail(domainId, auth.email) : null;
    if (!isOwner && !agent) {
      return new Response(JSON.stringify({ error: "Sin acceso a este dominio" }), { status: 403 });
    }

    const convs = await listConversations(domainId, { status, assignedTo });
    return new Response(JSON.stringify(convs), {
      headers: { "content-type": "application/json" },
    });
  })

  .get("/api/mesa/conversations/:id", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const url = new URL(request.url);
    const domainId = url.searchParams.get("domainId");
    if (!domainId) return new Response(JSON.stringify({ error: "domainId requerido" }), { status: 400 });

    const domain = await getDomain(domainId);
    if (!domain) return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });

    const isOwner = domain.ownerEmail === auth.email;
    const agent = !isOwner ? await getAgentByEmail(domainId, auth.email) : null;
    if (!isOwner && !agent) {
      return new Response(JSON.stringify({ error: "Sin acceso" }), { status: 403 });
    }

    const conv = await getConversation(domainId, params.id);
    if (!conv) return new Response(JSON.stringify({ error: "Conversación no encontrada" }), { status: 404 });

    const [messages, notes] = await Promise.all([
      listMessages(conv.id),
      listNotes(conv.id),
    ]);

    return new Response(JSON.stringify({ ...conv, messages, notes }), {
      headers: { "content-type": "application/json" },
    });
  })

  .post("/api/mesa/conversations/:id/reply", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const { domainId, body: replyBody, html } = await request.json();
    if (!domainId || (!replyBody && !html)) {
      return new Response(JSON.stringify({ error: "domainId y body/html requeridos" }), { status: 400 });
    }

    const domain = await getDomain(domainId);
    if (!domain) return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });

    const user = (await getUser(auth.email))!;
    const plan = user.subscription?.plan ?? "basico";
    const mesaLimits = PLAN_MESA_LIMITS[plan as keyof typeof PLAN_MESA_LIMITS] ?? PLAN_MESA_LIMITS.basico;
    if (!mesaLimits.mesaActions) {
      return new Response(JSON.stringify({ error: "Tu plan no permite responder desde Mesa. Actualiza a Freelancer o superior." }), { status: 403 });
    }

    const isOwner = domain.ownerEmail === auth.email;
    const agent = !isOwner ? await getAgentByEmail(domainId, auth.email) : null;
    if (!isOwner && !agent) {
      return new Response(JSON.stringify({ error: "Sin acceso" }), { status: 403 });
    }

    const conv = await getConversation(domainId, params.id);
    if (!conv) return new Response(JSON.stringify({ error: "Conversación no encontrada" }), { status: 404 });

    const fromAddress = `${conv.to.split("@")[0]}@${domain.domain}`;
    const lastRef = conv.threadReferences[conv.threadReferences.length - 1];

    try {
      const messageId = await sendFromDomain(fromAddress, conv.from, `Re: ${conv.subject}`, replyBody ?? html, {
        html,
        configSet: getConfigSetName(domain.domain),
        inReplyTo: lastRef,
        references: conv.threadReferences.join(" "),
      });
      await incrementSendCount(domain.id);

      await addMessage({
        conversationId: conv.id,
        from: fromAddress,
        body: replyBody ?? "",
        html: html ?? "",
        direction: "outbound",
        createdAt: new Date().toISOString(),
        messageId,
      });

      await updateConversation(domainId, conv.id, {
        threadReferences: [...conv.threadReferences, messageId],
        lastMessageAt: new Date().toISOString(),
        messageCount: conv.messageCount + 1,
      });

      return new Response(JSON.stringify({ ok: true, messageId }), {
        headers: { "content-type": "application/json" },
      });
    } catch (err) {
      log("error", "ses", "Mesa reply failed", { error: String(err) });
      return new Response(JSON.stringify({ error: "Error enviando respuesta" }), { status: 500 });
    }
  })

  .post("/api/mesa/conversations/:id/assign", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const { domainId, assignedTo } = await request.json();
    if (!domainId) return new Response(JSON.stringify({ error: "domainId requerido" }), { status: 400 });

    const domain = await getDomain(domainId);
    if (!domain) return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });

    const user = (await getUser(auth.email))!;
    const plan = user.subscription?.plan ?? "basico";
    const mesaLimits = PLAN_MESA_LIMITS[plan as keyof typeof PLAN_MESA_LIMITS] ?? PLAN_MESA_LIMITS.basico;
    if (!mesaLimits.mesaActions) {
      return new Response(JSON.stringify({ error: "Tu plan no permite asignar conversaciones" }), { status: 403 });
    }

    const isOwner = domain.ownerEmail === auth.email;
    if (!isOwner) {
      return new Response(JSON.stringify({ error: "Solo el dueño puede asignar conversaciones" }), { status: 403 });
    }

    const updated = await updateConversation(domainId, params.id, { assignedTo: assignedTo ?? undefined });
    if (!updated) return new Response(JSON.stringify({ error: "Conversación no encontrada" }), { status: 404 });

    return new Response(JSON.stringify(updated), {
      headers: { "content-type": "application/json" },
    });
  })

  .post("/api/mesa/conversations/:id/note", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const { domainId, body: noteBody } = await request.json();
    if (!domainId || !noteBody) return new Response(JSON.stringify({ error: "domainId y body requeridos" }), { status: 400 });

    const domain = await getDomain(domainId);
    if (!domain) return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });

    const user = (await getUser(auth.email))!;
    const plan = user.subscription?.plan ?? "basico";
    const mesaLimits = PLAN_MESA_LIMITS[plan as keyof typeof PLAN_MESA_LIMITS] ?? PLAN_MESA_LIMITS.basico;
    if (!mesaLimits.mesaActions) {
      return new Response(JSON.stringify({ error: "Tu plan no permite agregar notas" }), { status: 403 });
    }

    const isOwner = domain.ownerEmail === auth.email;
    const agent = !isOwner ? await getAgentByEmail(domainId, auth.email) : null;
    if (!isOwner && !agent) {
      return new Response(JSON.stringify({ error: "Sin acceso" }), { status: 403 });
    }

    const conv = await getConversation(domainId, params.id);
    if (!conv) return new Response(JSON.stringify({ error: "Conversación no encontrada" }), { status: 404 });

    const note = await addNote({
      conversationId: conv.id,
      author: auth.email,
      body: noteBody,
      createdAt: new Date().toISOString(),
    });

    return new Response(JSON.stringify(note), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  })

  .patch("/api/mesa/conversations/:id", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const patchBody = await request.json();
    const { domainId, status: newStatus, tags, priority } = patchBody;
    if (!domainId) return new Response(JSON.stringify({ error: "domainId requerido" }), { status: 400 });

    const domain = await getDomain(domainId);
    if (!domain) return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });

    const user = (await getUser(auth.email))!;
    const plan = user.subscription?.plan ?? "basico";
    const mesaLimits = PLAN_MESA_LIMITS[plan as keyof typeof PLAN_MESA_LIMITS] ?? PLAN_MESA_LIMITS.basico;
    if (!mesaLimits.mesaActions) {
      return new Response(JSON.stringify({ error: "Tu plan no permite modificar conversaciones" }), { status: 403 });
    }

    const isOwner = domain.ownerEmail === auth.email;
    const agent = !isOwner ? await getAgentByEmail(domainId, auth.email) : null;
    if (!isOwner && !agent) {
      return new Response(JSON.stringify({ error: "Sin acceso" }), { status: 403 });
    }

    const updates: Record<string, unknown> = {};
    if (newStatus && ["open", "snoozed", "closed"].includes(newStatus)) updates.status = newStatus;
    if (tags && Array.isArray(tags)) updates.tags = tags;
    if (priority && ["normal", "urgent"].includes(priority)) updates.priority = priority;

    const updated = await updateConversation(domainId, params.id, updates);
    if (!updated) return new Response(JSON.stringify({ error: "Conversación no encontrada" }), { status: 404 });

    return new Response(JSON.stringify(updated), {
      headers: { "content-type": "application/json" },
    });
  })

  // --- Mesa settings ---

  .post("/api/domains/:id/mesa", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== auth.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }

    const { enabled, forwardAlso } = await request.json();
    await setDomainMesaEnabled(domain.id, enabled ?? false, forwardAlso ?? true);

    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  })

  .get("/api/domains/:id/mesa", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== auth.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }

    const settings = await getDomainMesaSettings(domain.id);
    return new Response(JSON.stringify(settings), {
      headers: { "content-type": "application/json" },
    });
  })

  // --- Agents ---

  .post("/api/domains/:id/agents/invite", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== auth.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }

    const user = (await getUser(auth.email))!;
    const plan = user.subscription?.plan ?? "basico";
    const mesaLimits = PLAN_MESA_LIMITS[plan as keyof typeof PLAN_MESA_LIMITS] ?? PLAN_MESA_LIMITS.basico;
    if (mesaLimits.agents === 0) {
      return new Response(JSON.stringify({ error: "Tu plan no incluye agentes" }), { status: 403 });
    }

    const currentAgents = await countAgents(domain.id);
    if (currentAgents >= mesaLimits.agents) {
      return new Response(JSON.stringify({ error: `Límite de agentes alcanzado (${mesaLimits.agents})` }), { status: 400 });
    }

    const { email, name, role = "agent" } = await request.json();
    if (!email || !name) return new Response(JSON.stringify({ error: "email y name requeridos" }), { status: 400 });
    if (!["admin", "agent"].includes(role)) return new Response(JSON.stringify({ error: "role inválido" }), { status: 400 });

    const existing = await getAgentByEmail(domain.id, email);
    if (existing) return new Response(JSON.stringify({ error: "Este email ya es agente de este dominio" }), { status: 409 });

    const token = await createAgentInvite(domain.id, email, name, role);
    const inviteUrl = `${getMainDomainUrl()}/api/agents/accept?token=${token}`;

    const alertFrom = Deno.env.get("ALERT_FROM_EMAIL") ?? "noreply@mailmask.app";
    try {
      await sendFromDomain(alertFrom, email, `Invitación a Mesa — ${domain.domain}`,
        `Hola ${name},\n\n${auth.email} te invita como ${role} en Mesa para el dominio ${domain.domain}.\n\nAcepta la invitación aquí:\n${inviteUrl}\n\nEste enlace es válido por 7 días.\n\n— MailMask`);
    } catch (err) {
      log("error", "ses", "Failed to send agent invite", { error: String(err) });
    }

    return new Response(JSON.stringify({ ok: true, inviteUrl }), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  })

  .get("/api/agents/accept", async ({ request }) => {
    const url = new URL(request.url);
    const token = url.searchParams.get("token");
    if (!token) return new Response("Token inválido", { status: 400 });

    const invite = await getAgentInvite(token);
    if (!invite) return new Response("Token inválido o expirado", { status: 400 });

    const existingUser = await getUser(invite.email);
    if (!existingUser) {
      const { hashPassword: hp } = await import("./auth.ts");
      await createUserIfNotExists(invite.email, await hp(crypto.randomUUID()));
    }

    await createAgent({
      domainId: invite.domainId,
      email: invite.email,
      name: invite.name,
      role: invite.role,
    });
    await deleteAgentInvite(token);

    return new Response(null, {
      status: 302,
      headers: { location: "/mesa?welcome=1" },
    });
  })

  .get("/api/domains/:id/agents", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== auth.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }

    const agents = await listAgents(domain.id);
    return new Response(JSON.stringify(agents), {
      headers: { "content-type": "application/json" },
    });
  })

  .delete("/api/domains/:id/agents/:agentId", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== auth.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }

    const deleted = await deleteAgent(domain.id, params.agentId);
    if (!deleted) return new Response(JSON.stringify({ error: "Agente no encontrado" }), { status: 404 });

    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  })

  // --- SES bounce/complaint events ---

  .post("/api/webhooks/ses-events", async ({ request }) => {
    const body = await request.json();

    if (body.Type === "SubscriptionConfirmation" && body.SubscribeURL) {
      const parsed = new URL(body.SubscribeURL);
      if (parsed.hostname.endsWith(".amazonaws.com") && parsed.protocol === "https:") {
        await fetch(body.SubscribeURL);
      }
      return new Response("OK", { status: 200 });
    }

    if (body.Type !== "Notification") return new Response("OK", { status: 200 });

    try {
      const message = JSON.parse(body.Message);
      const eventType = message.eventType ?? message.notificationType;

      if (eventType === "Bounce" || eventType === "bounce") {
        const bounce = message.bounce ?? message;
        const recipients = bounce.bouncedRecipients ?? [];
        for (const r of recipients) {
          const email = r.emailAddress;
          const configSet = message.mail?.tags?.["ses:configuration-set"]?.[0] ?? "";
          const domainName = configSet.replace("mailmask-", "").replace(/-/g, ".");
          if (domainName) {
            const { getDomainByName } = await import("./db.ts");
            const domainRecord = await getDomainByName(domainName);
            if (domainRecord) {
              await addSuppression(domainRecord.id, email, `bounce:${bounce.bounceType}`);
              log("info", "ses", "Added to suppression (bounce)", { email, domain: domainName });
            }
          }
        }
      } else if (eventType === "Complaint" || eventType === "complaint") {
        const complaint = message.complaint ?? message;
        const recipients = complaint.complainedRecipients ?? [];
        for (const r of recipients) {
          const email = r.emailAddress;
          const configSet = message.mail?.tags?.["ses:configuration-set"]?.[0] ?? "";
          const domainName = configSet.replace("mailmask-", "").replace(/-/g, ".");
          if (domainName) {
            const { getDomainByName } = await import("./db.ts");
            const domainRecord = await getDomainByName(domainName);
            if (domainRecord) {
              await addSuppression(domainRecord.id, email, "complaint");
              log("info", "ses", "Added to suppression (complaint)", { email, domain: domainName });
            }
          }
        }
      }
    } catch (err) {
      log("error", "ses", "SES event processing error", { error: String(err) });
    }

    return new Response("OK", { status: 200 });
  })

  // --- Webhook: SES inbound via SNS ---

  .post("/api/webhooks/ses-inbound", async ({ request }) => {
    const body = await request.json();

    // Validate SNS signature
    if (!body.Type || !body.Signature || !body.SigningCertURL) {
      return new Response(JSON.stringify({ error: "Invalid SNS message" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    }
    const valid = await verifySnsSignature(body);
    if (!valid) {
      log("warn", "server", "SES inbound: invalid SNS signature");
      return new Response(JSON.stringify({ error: "Invalid signature" }), {
        status: 403,
        headers: { "content-type": "application/json" },
      });
    }

    try {
      const result = await processInbound(body);
      return new Response(JSON.stringify(result), {
        headers: { "content-type": "application/json" },
      });
    } catch (err) {
      log("error", "server", "SES inbound processing error", { error: String(err) });
      return new Response(JSON.stringify({ error: "Processing failed" }), {
        status: 500,
        headers: { "content-type": "application/json" },
      });
    }
  })

  // --- Admin: backups ---

  .get("/api/admin/backups", async ({ request }) => {
    const user = await getAuthUser(request);
    if (!user || !isAdmin(user.email))
      return new Response(JSON.stringify({ error: "Acceso denegado" }), { status: 403, headers: { "content-type": "application/json" } });

    const backups = await listBackups();
    return new Response(JSON.stringify(backups), { headers: { "content-type": "application/json" } });
  })

  .get("/api/admin/backups/:key", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user || !isAdmin(user.email))
      return new Response(JSON.stringify({ error: "Acceso denegado" }), { status: 403, headers: { "content-type": "application/json" } });

    try {
      const content = await getBackupFromS3(params.key);
      return new Response(content, {
        headers: {
          "content-type": "application/json",
          "content-disposition": `attachment; filename="${params.key}"`,
        },
      });
    } catch {
      return new Response(JSON.stringify({ error: "Backup no encontrado" }), { status: 404, headers: { "content-type": "application/json" } });
    }
  })

  .delete("/api/admin/backups/:key", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user || !isAdmin(user.email))
      return new Response(JSON.stringify({ error: "Acceso denegado" }), { status: 403, headers: { "content-type": "application/json" } });

    try {
      await deleteBackupFromS3(params.key);
      log("info", "backup", "Backup deleted by admin", { email: user.email, key: params.key });
      return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
    } catch {
      return new Response(JSON.stringify({ error: "No se pudo eliminar el backup" }), { status: 500, headers: { "content-type": "application/json" } });
    }
  })

  .post("/api/admin/backups/trigger", async ({ request }) => {
    const user = await getAuthUser(request);
    if (!user || !isAdmin(user.email))
      return new Response(JSON.stringify({ error: "Acceso denegado" }), { status: 403, headers: { "content-type": "application/json" } });

    try {
      const result = await runBackup();
      log("info", "backup", "Manual backup triggered by admin", { email: user.email, key: result.key });
      return new Response(JSON.stringify({ ok: true, key: result.key, users: result.users }), { headers: { "content-type": "application/json" } });
    } catch (err) {
      log("error", "backup", "Manual backup failed", { error: String(err) });
      return new Response(JSON.stringify({ error: "Backup falló" }), { status: 500, headers: { "content-type": "application/json" } });
    }
  })

  // --- Admin: Users CRUD ---

  .get("/api/admin/users", async ({ request }) => {
    const user = await getAuthUser(request);
    if (!user || !isAdmin(user.email))
      return new Response(JSON.stringify({ error: "Acceso denegado" }), { status: 403, headers: { "content-type": "application/json" } });

    const users = await listAllUsers();
    const result = [];
    for (const u of users) {
      const domainsCount = await countUserDomains(u.email);
      result.push({
        email: u.email,
        plan: u.subscription?.plan ?? null,
        status: u.subscription?.status ?? "none",
        currentPeriodEnd: u.subscription?.currentPeriodEnd ?? null,
        emailVerified: u.emailVerified ?? false,
        createdAt: u.createdAt,
        domainsCount,
      });
    }
    return new Response(JSON.stringify(result), { headers: { "content-type": "application/json" } });
  })

  .get("/api/admin/users/:email", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth || !isAdmin(auth.email))
      return new Response(JSON.stringify({ error: "Acceso denegado" }), { status: 403, headers: { "content-type": "application/json" } });

    const target = await getUser(decodeURIComponent(params.email));
    if (!target)
      return new Response(JSON.stringify({ error: "Usuario no encontrado" }), { status: 404, headers: { "content-type": "application/json" } });

    const domains = await listUserDomains(target.email);
    const domainsWithAliases = [];
    for (const d of domains) {
      const aliasCount = await countAliases(d.id);
      domainsWithAliases.push({ id: d.id, domain: d.domain, verified: d.verified, aliasCount });
    }

    const { passwordHash: _, ...safe } = target;
    return new Response(JSON.stringify({ ...safe, domains: domainsWithAliases }), { headers: { "content-type": "application/json" } });
  })

  .patch("/api/admin/users/:email", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth || !isAdmin(auth.email))
      return new Response(JSON.stringify({ error: "Acceso denegado" }), { status: 403, headers: { "content-type": "application/json" } });

    const email = decodeURIComponent(params.email);
    const target = await getUser(email);
    if (!target)
      return new Response(JSON.stringify({ error: "Usuario no encontrado" }), { status: 404, headers: { "content-type": "application/json" } });

    const body = await request.json();
    const validPlans = ["basico", "freelancer", "developer", "pro", "agencia"];
    const validStatuses = ["active", "past_due", "cancelled", "none"];

    // Update subscription fields
    if (body.plan !== undefined || body.status !== undefined || body.currentPeriodEnd !== undefined) {
      const sub = target.subscription ?? { plan: "basico", status: "none" as const };
      if (body.plan !== undefined && validPlans.includes(body.plan)) sub.plan = body.plan;
      if (body.status !== undefined && validStatuses.includes(body.status)) sub.status = body.status;
      if (body.currentPeriodEnd !== undefined) sub.currentPeriodEnd = body.currentPeriodEnd || undefined;
      await updateUserSubscription(email, sub);
    }

    // Update emailVerified
    if (body.emailVerified !== undefined) {
      const fresh = await getUser(email);
      if (fresh) {
        const { _getKv } = await import("./db.ts");
        const kv = _getKv();
        await kv.set(["users", email], { ...fresh, emailVerified: !!body.emailVerified });
      }
    }

    log("info", "admin", "User updated by admin", { admin: auth.email, target: email, changes: body });
    const updated = await getUser(email);
    const { passwordHash: _, ...safe } = updated!;
    return new Response(JSON.stringify(safe), { headers: { "content-type": "application/json" } });
  })

  .delete("/api/admin/users/:email", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth || !isAdmin(auth.email))
      return new Response(JSON.stringify({ error: "Acceso denegado" }), { status: 403, headers: { "content-type": "application/json" } });

    const email = decodeURIComponent(params.email);
    if (email === auth.email)
      return new Response(JSON.stringify({ error: "No puedes eliminarte a ti mismo" }), { status: 400, headers: { "content-type": "application/json" } });

    const deleted = await deleteUser(email);
    if (!deleted)
      return new Response(JSON.stringify({ error: "Usuario no encontrado" }), { status: 404, headers: { "content-type": "application/json" } });

    log("info", "admin", "User deleted by admin", { admin: auth.email, target: email });
    return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
  });

// --- Bulk send cron (every minute, processes 14 emails/sec) ---

Deno.cron("bulk-send", "* * * * *", async () => {
  const jobs = await listPendingBulkJobs();
  if (jobs.length === 0) return;

  for (const job of jobs) {
    if (job.status === "queued") {
      job.status = "processing";
      await updateBulkJob(job);
    }

    const configSet = getConfigSetName(job.from.split("@")[1] ?? "");
    const batchSize = 14; // SES rate limit ~14/sec
    const startIdx = job.sent + job.failed + job.skippedSuppressed;
    const batch = job.recipients.slice(startIdx, startIdx + batchSize);

    if (batch.length === 0) {
      job.status = "completed";
      job.completedAt = new Date().toISOString();
      await updateBulkJob(job);
      continue;
    }

    for (const recipient of batch) {
      // Check suppression
      if (await isSuppressed(job.domainId, recipient)) {
        job.skippedSuppressed++;
        continue;
      }

      try {
        await sendFromDomain(job.from, recipient, job.subject, job.html, {
          html: job.html,
          configSet,
        });
        job.sent++;
        await incrementSendCount(job.domainId);
      } catch (err) {
        job.failed++;
        job.lastError = String(err);
        log("warn", "ses", "Bulk send failed for recipient", { recipient, error: String(err) });
      }
    }

    // Check if done
    if (job.sent + job.failed + job.skippedSuppressed >= job.totalRecipients) {
      job.status = job.failed > 0 && job.sent === 0 ? "failed" : "completed";
      job.completedAt = new Date().toISOString();
    }

    await updateBulkJob(job);
  }
});

// --- Monitoring cron (every 5 minutes) ---

Deno.cron("queue-monitor", "*/5 * * * *", async () => {
  const queueDepth = await getQueueDepth();
  const deadLetterCount = await getDeadLetterCount();

  if (deadLetterCount > 0) {
    await sendAlert("dead-letter-queue", `Dead-letter queue has ${deadLetterCount} item(s). Emails failed permanently after max retries.\nQueue depth: ${queueDepth}`);
  } else if (queueDepth > 10) {
    await sendAlert("queue-backlog", `Forward queue backlog: ${queueDepth} items pending retry.`);
  }
});

// --- Daily backup cron (4:00 UTC) ---

Deno.cron("daily-backup", "0 4 * * *", async () => {
  try {
    const result = await runBackup();
    log("info", "backup", "Daily backup completed", { users: result.users, key: result.key });
  } catch (err) {
    log("error", "backup", "Daily backup failed", { error: String(err) });
    await sendAlert("backup-failure", `Daily backup failed: ${String(err)}`);
  }
});

const port = parseInt(Deno.env.get("PORT") ?? "8000");
Deno.serve({ port }, (req) => app.fetch(req));
export { app };
