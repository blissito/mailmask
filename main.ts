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
    const queueDepth = await getQueueDepth();
    const deadLetterCount = await getDeadLetterCount();
    const healthy = queueDepth <= 50 && deadLetterCount === 0;
    return new Response(JSON.stringify({
      status: healthy ? "ok" : "degraded",
      service: "mailmask",
      timestamp: new Date().toISOString(),
      queueDepth,
      deadLetterCount,
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

    // Create receipt rule for inbound
    try {
      await createReceiptRule(domain);
    } catch (err) {
      log("warn", "ses", "Could not create receipt rule (may already exist)", { error: String(err) });
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

    // Clean up SES receipt rule
    try {
      await deleteReceiptRule(domain.domain);
    } catch {
      /* best effort */
    }

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
    const updated = await updateAlias(domain.id, params.alias, body);
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
            if (currentSub) {
              await updateUserSubscription(email, {
                ...currentSub,
                status: "cancelled",
              });
              log("info", "webhook", "Subscription cancelled", { email });
            }
          } else if (sub.status === "paused") {
            const existingUser = await getUser(email);
            const currentSub = existingUser?.subscription;
            if (currentSub) {
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

const port = parseInt(Deno.env.get("PORT") ?? "8000");
Deno.serve({ port }, (req) => app.fetch(req));
export { app };
