import { Elysia, t } from "elysia";
import { node } from "@elysiajs/node";
import { openapi } from "@elysiajs/openapi";
import * as fs from "node:fs";
import * as path from "node:path";
import * as dns from "node:dns/promises";
import { programar, esServidor } from "./scheduler.js";
import { revisarPatron } from "./regex-guard.js";
import { addSseClient } from "./sse-hub.js";
import { db } from "./pg.js";
import { users as usersTable } from "./schema.js";
import { eq } from "drizzle-orm";
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
  updateRule,
  deleteRule,
  countRules,
  listLogs,
  getForwardCounts,
  PLANS,
  ADDONS,
  listAddons,
  listEffectiveAddons,
  getAddonById,
  getAddonByMpId,
  createAddon,
  updateAddon,
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
  isChargeFailureWarned,
  markChargeFailureWarned,
  recordOrder,
  chargeEventKey,
  listOrders,
  getLastOrder,
  planLabel,
  planPriceCents,
  addonLabel,
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
  normalizeSuppressionKeys,
  incrementSendCount,
  decrementSendCount,
  getSendCount,
  createConversation,
  createBulkJob,
  getBulkJob,
  updateBulkJob,
  listPendingBulkJobs,
  PLAN_MESA_LIMITS,
  softDeleteConversation,
  restoreConversation,
  listAllUsers,
  deleteUser,
  getCoupon,
  createCoupon,
  listCoupons,
  deleteCoupon,
  markCouponUsed,
  createSmtpCredential,
  listSmtpCredentials,
  revokeSmtpCredential,
  // Referrals
  generateReferralSlug,
  setReferralSlug,
  getUserByReferralSlug,
  createReferral,
  getReferralByReferred,
  listReferrals,
  markReferralConverted,
  createReferralCredit,
  getUnusedCredits,
  markCreditsUsed,
  getReferralStats,
  incrementPaymentCount,
  getUserReferredBy,
  setUserReferredBy,
  recordReferralClick,
  // API Keys
  createApiKey,
  listApiKeys,
  revokeApiKey,
  // Domain registrations
  TLD_PRICES,
  createDomainRegistration,
  getDomainRegistration,
  getDomainRegistrationsByUser,
  updateDomainRegistration,
  getDomainRegistrationByPaymentId,
  listCannedResponses,
  createCannedResponse,
  deleteCannedResponse,
} from "./db.js";
import type { AddonKind } from "./db.js";
import {
  hashPassword,
  verifyPassword,
  signJwt,
  makeAuthCookie,
  clearAuthCookie,
  getAuthUser,
  parseCookies,
  generateCsrfToken,
  makeCsrfCookie,
} from "./auth.js";
import { checkRateLimit } from "./rate-limit.js";
import {
  verifyDomain,
  checkDomainStatus,
  createReceiptRule,
  deleteReceiptRule,
  sendFromDomain,
  normalizeAddress,
  encodeHeader,
  sendAlert,
  checkSesHealth,
  deleteOldBackups,
  getConfigSetName,
  listBackups,
  getBackupFromS3,
  deleteBackupFromS3,
  deleteConfigurationSet,
  deleteDomainIdentity,
} from "./ses.js";
import { processInbound, extractPlainBody, extractHtmlBody, extractAttachments, extractAttachmentByIndex, rebuildConversationsFromS3 } from "./forwarding.js";
import { fetchEmailFromS3, repairReceiptRules, ensureDomainInbound, ensureSnsSubscription, AWS_REGION, getBackupBytesFromS3 } from "./ses.js";
import { runDbBackup, DB_BACKUP_SUFFIX } from "./backup.js";
import { resolveEmailBody, extractInlineImages, appendSignature, quotePrevious, MAX_EMAIL_HTML_BYTES } from "./email-html.js";
import { putEmailImageToS3, getEmailImageFromS3, deleteEmailImageFromS3, sweepOrphanEmailImages, putEmailFileToS3, getEmailFileFromS3, deleteEmailFileFromS3, ALLOWED_IMAGE_TYPES } from "./ses.js";
import type { InlineImage, Attachment } from "./ses.js";
import { sqlite } from "./pg.js";
import { log } from "./logger.js";
import { createSmtpIamCredential, revokeSmtpIamCredential } from "./ses.js";
import {
  sendTemplate,
  verifyEmail as verifyEmailTemplate,
  passwordReset,
  mesaInvite,
  paymentConfirmation,
  addonPurchase,
  renewalReceipt,
  chargeFailed,
  guestWelcome,
  SUPPORT_EMAIL,
} from "./emails.js";
import "./cron.js";

// --- Coupons (dynamic, from DB) ---
type PlanKeyTop = "basico" | "freelancer" | "developer" | "pro" | "agencia";

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
    if (!process.env[key]) throw new Error(`Missing required env var: ${key}`);
  }
  envChecked = true;
}

// --- Helpers ---

function getMainDomainUrl(): string {
  const raw = process.env.MAIN_DOMAIN ?? "www.mailmask.studio";
  const bare = raw.replace(/^https?:\/\//, "").replace(/\/+$/, "");
  return `https://${bare}`;
}

const PUBLIC_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "public");

async function serveStatic(filePath: string): Promise<Response> {
  try {
    const resolved = path.resolve(PUBLIC_DIR, filePath.replace(/^\//, ""));
    if (!resolved.startsWith(PUBLIC_DIR)) {
      return new Response("Not found", { status: 404 });
    }
    const file = fs.readFileSync(resolved);
    const ext = filePath.split(".").pop() ?? "";
    const types: Record<string, string> = {
      html: "text/html; charset=utf-8",
      js: "application/javascript; charset=utf-8",
      css: "text/css; charset=utf-8",
      png: "image/png",
      // Sin jpg/jpeg aquí, los JPG salían como application/octet-stream y WhatsApp
      // descartaba el og:image sin decir nada — los navegadores no lo notan porque
      // adivinan el tipo por el contenido, los scrapers no.
      jpg: "image/jpeg",
      jpeg: "image/jpeg",
      webp: "image/webp",
      avif: "image/avif",
      gif: "image/gif",
      svg: "image/svg+xml",
      ico: "image/x-icon",
      woff: "font/woff",
      woff2: "font/woff2",
      json: "application/json; charset=utf-8",
      xml: "application/xml; charset=utf-8",
      txt: "text/plain; charset=utf-8",
      pdf: "application/pdf",
      epub: "application/epub+zip",
      webmanifest: "application/manifest+json",
    };
    const contentType = types[ext.toLowerCase()] ?? "application/octet-stream";
    const headers: Record<string, string> = { "content-type": contentType };
    // Caché larga para imágenes y fuentes: son inmutables en la práctica y los
    // scrapers reintentan menos si la respuesta es estable.
    if (/^(image|font)\//.test(contentType)) {
      headers["cache-control"] = "public, max-age=604800";
    }
    return new Response(file, { headers });
  } catch {
    try {
      // Node runtime — Bun.file() is unavailable here, so the custom 404 page was
      // never actually served and every miss fell through to bare "Not found".
      const notFoundPage = fs.readFileSync(path.join(PUBLIC_DIR, "404.html"));
      return new Response(notFoundPage, { status: 404, headers: { "content-type": "text/html; charset=utf-8" } });
    } catch {
      return new Response("Not found", { status: 404 });
    }
  }
}

/**
 * Prepara el cuerpo de un correo de la Bandeja para salir con sus imágenes
 * incrustadas, como hace Gmail: se adjuntan dentro del mensaje y el HTML las
 * referencia con `cid:` en vez de con una URL nuestra.
 *
 * Sólo aplica al correo de persona a persona. El envío masivo sigue con enlace
 * hospedado: adjuntar la misma imagen a cada destinatario multiplicaría los bytes.
 */
async function attachInlineImages(html: string | undefined): Promise<{ html?: string; inlineImages?: InlineImage[] }> {
  if (!html) return {};
  const { html: rewritten, keys } = extractInlineImages(html);
  if (!keys.length) return { html };

  const images: InlineImage[] = [];
  for (const key of keys) {
    const image = await getEmailImageFromS3(key);
    // Si una imagen no está, se manda el correo sin ella: perder el correo entero
    // por una foto sería peor. El cliente mostrará el hueco del alt.
    if (!image) {
      log("warn", "ses", "Inline image missing from S3", { key });
      continue;
    }
    images.push({ cid: key, contentType: image.contentType, data: image.body, filename: key });
  }
  return { html: rewritten, inlineImages: images };
}

/**
 * Quita de S3 las imágenes que ya viajaron dentro de un correo enviado. Mejor
 * esfuerzo: si falla, el barrido diario las recoge. Nunca debe tumbar un envío que
 * ya salió bien.
 */
async function discardSentImages(images: InlineImage[] | undefined): Promise<void> {
  for (const img of images ?? []) {
    try {
      await deleteEmailImageFromS3(img.cid);
    } catch (err) {
      log("warn", "ses", "Could not delete inline image after send", { key: img.cid, error: String(err) });
    }
  }
}

/** Tamaño máximo de un adjunto. Ver MAX_RAW_MESSAGE_BYTES: base64 infla ~33%. */
const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024;

// Extensiones que casi ningún proveedor entrega y que sólo sirven para que nos
// marquen como origen de malware. Bloquearlas aquí evita gastar reputación.
const BLOCKED_ATTACHMENT_EXT = /\.(exe|scr|com|pif|bat|cmd|msi|jar|vbs|js|apk|dll)$/i;

interface AttachmentRef { key: string; filename: string; contentType: string }

/** Baja de S3 los adjuntos que el cliente referenció por llave. */
async function collectAttachments(refs: AttachmentRef[] | undefined): Promise<{ attachments: Attachment[]; keys: string[] }> {
  const attachments: Attachment[] = [];
  const keys: string[] = [];
  for (const ref of refs ?? []) {
    if (!/^[0-9a-f-]{36}$/i.test(ref.key)) continue;
    const file = await getEmailFileFromS3(ref.key);
    if (!file) {
      log("warn", "ses", "Attachment missing from S3", { key: ref.key });
      continue;
    }
    attachments.push({
      // El nombre llega del cliente en el envío, no del que se saneó al subir. Una
      // comilla o una barra rompen el Content-Disposition (que es una cadena
      // entrecomillada) y dejarían colar parámetros de más.
      filename: (ref.filename || "archivo").replace(/[\r\n"\\;\x00-\x1f]/g, "").slice(0, 200) || "archivo",
      // El tipo se toma del objeto guardado, no de lo que diga el cliente ahora.
      contentType: file.contentType,
      data: file.body,
    });
    keys.push(ref.key);
  }
  return { attachments, keys };
}

/** Borra de S3 los adjuntos que ya viajaron dentro del correo. Mejor esfuerzo. */
async function discardSentFiles(keys: string[]): Promise<void> {
  for (const key of keys) {
    try {
      await deleteEmailFileFromS3(key);
    } catch (err) {
      log("warn", "ses", "Could not delete attachment after send", { key, error: String(err) });
    }
  }
}

/** Normaliza y valida una lista de direcciones de Cc/Bcc. */
function parseCopyList(value: unknown, max = 20): string[] {
  if (!Array.isArray(value)) return [];
  const re = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return value
    .map((v) => normalizeAddress(String(v ?? "")))
    .filter((v) => re.test(v))
    .slice(0, max);
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
  const result = checkRateLimit(ip, limit, windowMs);
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
  const admins = (process.env.ADMIN_EMAILS ?? "").split(",").map(e => e.trim().toLowerCase());
  return admins.includes(email.toLowerCase());
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
    // El Token forma parte de la cadena firmada; sin él toda confirmación
    // fallaba (nunca se notó porque el webhook de entrada no verificaba
    // confirmaciones).
    fields = [
      "Message",
      "MessageId",
      "SubscribeURL",
      "Timestamp",
      "Token",
      "TopicArn",
      "Type",
    ];
  }
  return fields.map((f) => `${f}\n${body[f]}`).join("\n") + "\n";
}

async function verifySnsSignature(
  body: Record<string, string>,
): Promise<boolean> {
  // Dos tópicos legítimos: entrada (SES inbound) y salida (rebotes/quejas).
  const allowedTopics = [process.env.SNS_TOPIC_ARN, process.env.SNS_OUTBOUND_TOPIC_ARN].filter(Boolean);
  if (allowedTopics.length && !allowedTopics.includes(body.TopicArn)) return false;

  const certUrl = body.SigningCertURL;
  if (!certUrl) return false;

  try {
    const pem = await fetchSnsCert(certUrl);
    const stringToSign = buildSnsStringToSign(body);

    const { createVerify } = await import("node:crypto");
    // SignatureVersion 1 = SHA1, 2 = SHA256.
    const verifier = createVerify(body.SignatureVersion === "2" ? "SHA256" : "SHA1");
    verifier.update(stringToSign);
    return verifier.verify(pem, body.Signature, "base64");
  } catch (err) {
    log("error", "server", "SNS signature verification failed", { error: String(err) });
    return false;
  }
}

/**
 * Rebotes y quejas de salida (SES → SNS → aquí). El dominio se resuelve por el
 * remitente del correo original, no por el nombre del config set: ese nombre
 * cambia los puntos por guiones y un dominio con guión (`mi-marca.com`) no se
 * puede reconstruir. Sólo el rebote Permanent suprime; un buzón lleno
 * (Transient) no debe bloquear al contacto para siempre.
 */
export async function registrarEventoSes(message: any): Promise<{ suppressed: number }> {
  const eventType = String(message.eventType ?? message.notificationType ?? "").toLowerCase();
  let recipients: { emailAddress?: string }[] = [];
  let reason = "";
  if (eventType === "bounce") {
    const bounce = message.bounce ?? message;
    if (bounce.bounceType !== "Permanent") {
      log("info", "ses", "Transient bounce, not suppressing", { bounceType: bounce.bounceType, source: message.mail?.source });
      return { suppressed: 0 };
    }
    recipients = bounce.bouncedRecipients ?? [];
    reason = "bounce:Permanent";
  } else if (eventType === "complaint") {
    recipients = (message.complaint ?? message).complainedRecipients ?? [];
    reason = "complaint";
  } else {
    return { suppressed: 0 };
  }

  const source = String(message.mail?.source ?? "");
  let domainName = source.includes("@") ? source.split("@").pop()!.replace(/>$/, "").toLowerCase() : "";
  if (!domainName) {
    const configSet = message.mail?.tags?.["ses:configuration-set"]?.[0] ?? "";
    domainName = configSet.replace(/^mailmask-/, "").replace(/-/g, ".");
  }
  if (!domainName) return { suppressed: 0 };

  const { getDomainByName } = await import("./db.js");
  const domainRecord = await getDomainByName(domainName);
  if (!domainRecord) {
    log("warn", "ses", "SES event for unknown domain", { domainName, eventType });
    return { suppressed: 0 };
  }

  let suppressed = 0;
  for (const r of recipients) {
    if (!r.emailAddress) continue;
    await addSuppression(domainRecord.id, r.emailAddress, reason);
    suppressed++;
    log("info", "ses", `Added to suppression (${reason})`, { email: r.emailAddress, domain: domainName });
  }
  return { suppressed };
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

// --- RBAC: domain-level permissions ---

type Permission = "read" | "write" | "manage_members" | "admin";

const ROLE_PERMISSIONS: Record<string, Permission[]> = {
  owner: ["read", "write", "manage_members", "admin"],
  admin: ["read", "write", "manage_members"],
  agent: ["read"],
};

interface AccessResult {
  domain: NonNullable<Awaited<ReturnType<typeof getDomain>>>;
  role: string;
}

// Cancela un preapproval en MercadoPago. Lanza si MP responde error, para que el caller
// decida si aborta o solo lo registra.
async function cancelMpPreapproval(preapprovalId: string, accessToken: string): Promise<void> {
  const res = await fetch(`https://api.mercadopago.com/preapproval/${preapprovalId}`, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ status: "cancelled" }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`MP cancel ${preapprovalId}: ${await res.text()}`);
}

async function checkDomainAccess(
  userEmail: string,
  domainId: string,
  permission: Permission,
): Promise<AccessResult | null> {
  const domain = await getDomain(domainId);
  if (!domain) return null;

  if (domain.ownerEmail === userEmail) {
    return { domain, role: "owner" };
  }

  const agent = await getAgentByEmail(domainId, userEmail);
  if (!agent) return null;

  const perms = ROLE_PERMISSIONS[agent.role] ?? [];
  if (!perms.includes(permission)) return null;

  return { domain, role: agent.role };
}

// --- App ---

const app = new Elysia({ adapter: node() })
  .use(openapi({
    documentation: {
      info: { title: "MailMask API", version: "1.0.0", description: "Email alias/forwarding service API" },
      components: {
        securitySchemes: {
          cookieAuth: { type: "apiKey", in: "cookie", name: "token" },
          bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "API Key (mk_...)" },
        },
      },
    },
    scalar: {
      favicon: "/favicon.svg",
    },
    exclude: {
      tags: ["Auth", "Billing", "Admin", "Webhooks", "Coupons", "Referrals",
             "Export", "Bandeja", "Agents", "Domain Registration"],
      paths: [
        "/", "/login", "/register", "/app", "/composer-demo", "/css/*", "/js/*", "/img/*",
        "/favicon.svg", "/landing", "/pricing", "/bandeja", "/admin",
        "/set-password", "/forgot-password", "/terms", "/privacy",
        "/blog", "/blog/blog.css", "/blog/sounds-demo.js", "/blog/img/*",
        "/blog/:slug", "/robots.txt", "/sitemap.xml", "/llms.txt", "/health", "/healthz", "/docs",
      ],
      staticFile: true,
    },
  }))

  // --- Naked domain redirect ---
  .onRequest(({ request }) => {
    const url = new URL(request.url);
    if (url.hostname === "mailmask.studio") {
      url.hostname = "www.mailmask.studio";
      return Response.redirect(url.toString(), 301);
    }
  })

  // --- CORS ---
  .onRequest(({ request }) => {
    ensureEnv();
    const isDeploy = !!process.env.FLY_APP_NAME;
    const corsOrigin = isDeploy
      ? getMainDomainUrl()
      : request.headers.get("origin") || "http://localhost:8000";
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "access-control-allow-origin": corsOrigin,
          "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS",
          "access-control-allow-headers": "content-type, x-csrf-token",
          "access-control-allow-credentials": "true",
          "access-control-max-age": "86400",
        },
      });
    }
  })
  // --- CSRF protection (double-submit cookie) ---
  .onBeforeHandle(({ request }) => {
    const method = request.method;
    if (method === "GET" || method === "HEAD" || method === "OPTIONS") return;
    const url = new URL(request.url);
    // Skip CSRF for webhook endpoints (they use HMAC/signature validation)
    if (url.pathname.startsWith("/api/webhooks/")) return;
    // Skip CSRF for auth entry points (user doesn't have token yet)
    if (url.pathname.startsWith("/api/auth/") || url.pathname === "/api/referrals/track" || url.pathname === "/api/billing/checkout" || url.pathname === "/api/billing/guest-checkout") return;
    // La vista previa no muta nada y en desarrollo se usa desde la página de demo,
    // que no tiene sesión ni cookie CSRF. En producción el endpoint exige sesión.
    if (url.pathname === "/api/email-preview" && process.env.NODE_ENV !== "production") return;
    // Skip CSRF for Bearer token auth (inherently CSRF-safe)
    const authHeader = request.headers.get("authorization");
    if (authHeader?.startsWith("Bearer ")) return;
    // Validate double-submit cookie
    const cookies = parseCookies(request.headers.get("cookie"));
    const cookieToken = cookies["csrf_token"];
    const headerToken = request.headers.get("x-csrf-token");
    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
      return new Response(JSON.stringify({ error: "Token CSRF inválido" }), {
        status: 403,
        headers: { "content-type": "application/json" },
      });
    }
  })
  .onAfterHandle(({ request, response }) => {
    const isDeploy = !!process.env.FLY_APP_NAME;
    const corsOrigin = isDeploy
      ? getMainDomainUrl()
      : request.headers.get("origin") || "http://localhost:8000";
    if (response instanceof Response) {
      response.headers.set("access-control-allow-origin", corsOrigin);
      response.headers.set("access-control-allow-credentials", "true");
      response.headers.set("strict-transport-security", "max-age=31536000; includeSubDomains");
      response.headers.set("x-frame-options", "DENY");
      response.headers.set("x-content-type-options", "nosniff");
      response.headers.set(
        "referrer-policy",
        "strict-origin-when-cross-origin",
      );
      response.headers.set(
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), payment=(self)",
      );
      response.headers.set(
        "content-security-policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://www.googletagmanager.com https://www.clarity.ms; script-src 'self' https://www.googletagmanager.com https://www.clarity.ms; connect-src 'self' https://www.formmy.app https://www.googletagmanager.com https://*.google-analytics.com https://www.clarity.ms; frame-src https://www.googletagmanager.com",
      );
    }
    return response;
  })
  .onError({ as: "global" }, ({ code, error }) => {
    if (code === "VALIDATION") {
      return new Response(JSON.stringify({ error: "Datos inválidos" }), {
        status: 422,
        headers: { "content-type": "application/json" },
      });
    }
    if (code === "NOT_FOUND") {
      try {
        const html = fs.readFileSync(`${PUBLIC_DIR}/404.html`);
        return new Response(html, { status: 404, headers: { "content-type": "text/html; charset=utf-8" } });
      } catch {
        return new Response("Not found", { status: 404 });
      }
    }
    log("error", "server", "Unhandled error", { error: String(error) });
    return new Response(JSON.stringify({ error: "Error interno" }), {
      status: 500,
      headers: { "content-type": "application/json" },
    });
  })

  // --- Health ---
  // Liveness probe for fly-proxy: proves only that this process serves HTTP.
  // Deliberately does no I/O — /health below returns 503 on a mail backlog or an SES
  // hiccup, and wiring that to the proxy would pull a perfectly serving machine out of
  // rotation (and fail deploys) because forwards piled up. Keep them separate.
  .get("/healthz", () => new Response("ok", {
    headers: { "content-type": "text/plain", "cache-control": "no-store" },
  }))

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
  // Página de prueba del compositor. Sólo en desarrollo: no es parte del producto.
  .get("/composer-demo", () => process.env.NODE_ENV === "production"
    ? new Response("No encontrado", { status: 404 })
    : serveStatic("/composer-demo.html"))
  .get("/css/*", ({ params }) => serveStatic(`/css/${params["*"]}`))
  .get("/js/*", ({ params }) => serveStatic(`/js/${params["*"]}`))
  .get("/img/*", ({ params }) => serveStatic(`/img/${params["*"]}`))
  .get("/favicon.svg", () => serveStatic("/favicon.svg"))
  .get("/landing", () => serveStatic("/landing.html"))
  .get("/pricing", () => serveStatic("/pricing.html"))
  .get("/bandeja", () => serveStatic("/bandeja.html"))
  .get("/admin", async ({ request }) => {
    const user = await getAuthUser(request);
    if (!user || !isAdmin(user.email)) return new Response("Not found", { status: 404 });
    return serveStatic("/admin.html");
  })
  .get("/set-password", () => serveStatic("/set-password.html"))
  .get("/forgot-password", () => serveStatic("/forgot-password.html"))
  .get("/terms", () => serveStatic("/terms.html"))
  .get("/privacy", () => serveStatic("/privacy.html"))
  .get("/docs", () => serveStatic("/docs.html"))
  .get("/blog", () => serveStatic("/blog/index.html"))
  .get("/blog/blog.css", () => serveStatic("/blog/blog.css"))
  .get("/blog/sounds-demo.js", () => serveStatic("/blog/sounds-demo.js"))
  .get("/blog/img/*", ({ params }) => serveStatic(`/blog/img/${params["*"]}`))
  .get("/blog/:slug", async ({ params }) => {
    const slug = params.slug.replace(/[^a-z0-9-]/g, "");
    const resolved = path.resolve(PUBLIC_DIR, "blog", `${slug}.html`);
    if (!resolved.startsWith(PUBLIC_DIR)) {
      return new Response("Not found", { status: 404 });
    }
    try {
      return await serveStatic(`/blog/${slug}.html`);
    } catch {
      return new Response("Not found", { status: 404 });
    }
  })
  .get("/robots.txt", () => serveStatic("/robots.txt"))
  .get("/sitemap.xml", () => serveStatic("/sitemap.xml"))
  // Convention for generative engines: a plain-text summary of what the product is,
  // so assistants cite it accurately instead of inferring from marketing copy.
  .get("/llms.txt", () => serveStatic("/llms.txt"))

  // --- Auth ---

  .post("/api/auth/register", async ({ request, body }) => {
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 5, 60_000);
    if (limited) return limited;

    const email = (body.email ?? "").toLowerCase().trim();
    const password = body.password;
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))
      return new Response(
        JSON.stringify({ error: "Email inválido" }),
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
    generateReferralSlug(email);

    // Handle referral
    const ref = body.ref;
    if (ref && typeof ref === "string") {
      const referrer = await getUserByReferralSlug(ref);
      if (referrer && referrer.email !== email) {
        await setUserReferredBy(email, referrer.email);
        await createReferral(referrer.email, email);
      }
    }

    // Send verification email
    const verifyToken = crypto.randomUUID();
    await setVerifyToken(email, verifyToken);
    const verifyUrl = `${getMainDomainUrl()}/api/auth/verify-email?token=${verifyToken}`;
    try {
      await sendTemplate(email, verifyEmailTemplate({ verifyUrl }));
    } catch (err) {
      log("error", "auth", "Failed to send verification email", { error: String(err) });
    }

    const token = await signJwt({ email });
    const csrfToken = generateCsrfToken();
    const headers = new Headers({ "content-type": "application/json" });
    headers.append("set-cookie", makeAuthCookie(token));
    headers.append("set-cookie", makeCsrfCookie(csrfToken));
    return new Response(JSON.stringify({ ok: true }), { status: 201, headers });
  }, {
    body: t.Object({
      email: t.String(),
      password: t.String({ minLength: 8 }),
      ref: t.Optional(t.String()),
    }),
    detail: { tags: ["Auth"], summary: "Register a new user account" },
  })

  .post("/api/auth/login", async ({ request, body: loginBody }) => {
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 10, 60_000);
    if (limited) return limited;

    const email = (loginBody.email ?? "").toLowerCase().trim();
    const password = loginBody.password;

    // Per-email rate limit: 5 attempts per 1 minute (prevents credential stuffing across IPs)
    const emailRl = checkRateLimit(`login:${email}`, 5, 60_000);
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

    const { valid, needsRehash } = await verifyPassword(password, user.passwordHash);
    if (!valid)
      return new Response(JSON.stringify({ error: "Credenciales inválidas" }), {
        status: 401,
      });

    // Re-hash with stronger iterations if password was stored with legacy settings
    if (needsRehash) {
      const newHash = await hashPassword(password);
      updateUserPassword(email, newHash);
    }

    const token = await signJwt({ email });
    const csrfToken = generateCsrfToken();
    const headers = new Headers({ "content-type": "application/json" });
    headers.append("set-cookie", makeAuthCookie(token));
    headers.append("set-cookie", makeCsrfCookie(csrfToken));
    return new Response(JSON.stringify({ ok: true, email }), { headers });
  }, {
    body: t.Object({
      email: t.String(),
      password: t.String(),
    }),
    detail: { tags: ["Auth"], summary: "Login with email and password" },
  })

  .post("/api/auth/logout", () => {
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        "content-type": "application/json",
        "set-cookie": clearAuthCookie(),
      },
    });
  }, {
    detail: { tags: ["Auth"], summary: "Logout and clear auth cookie" },
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
    const rulesPerDomain = await Promise.all(
      domains.map(async (d) => ({
        domain: d.domain,
        domainId: d.id,
        current: await countRules(d.id),
        limit: limits.rules,
      })),
    );
    const sendsPerDomain = await Promise.all(
      domains.map(async (d) => ({
        domain: d.domain,
        domainId: d.id,
        current: await getSendCount(d.id),
        limit: limits.sends,
      })),
    );

    const referralStats = getReferralStats(user.email);

    // Issue CSRF cookie if user doesn't have one (e.g., existing session before CSRF was deployed)
    const cookies = parseCookies(request.headers.get("cookie"));
    const responseHeaders: Record<string, string> = { "content-type": "application/json" };
    if (!cookies["csrf_token"]) {
      responseHeaders["set-cookie"] = makeCsrfCookie(generateCsrfToken());
    }

    return new Response(
      JSON.stringify({
        email: user.email,
        isAdmin: isAdmin(user.email),
        domainsCount: domains.length,
        subscription: {
          ...(user.subscription ?? { plan: "basico", status: "none" }),
          currentPeriodEnd: user.subscription?.currentPeriodEnd ?? null,
          // Resuelto aquí y no en el navegador: app.js es un script plano que no puede
          // importar TypeScript, y duplicar el mapa de nombres en JS garantizaba que se
          // desincronizara. De paso muere el `charAt(0).toUpperCase()` que escribía
          // "Basico" sin acento.
          planLabel: planLabel(user.subscription?.plan),
        },
        limits,
        addons: listAddons(user.email),
        // Para que el resumen pueda sumar el cobro real sin pedir otro endpoint.
        planPriceCents: planPriceCents(user.subscription?.plan),
        addonCatalog: ADDONS,
        lastOrder: getLastOrder(user.email),
        emailVerified: user.emailVerified ?? false,
        usage: {
          domains: { current: domains.length, limit: limits.domains },
          aliasesPerDomain,
          rulesPerDomain,
          sendsPerDomain,
        },
        referralSlug: referralStats.slug,
        referralStats,
      }),
      {
        headers: responseHeaders,
      },
    );
  }, {
    detail: { tags: ["Auth"], summary: "Get current user profile and usage", security: [{ cookieAuth: [] }] },
  })

  .get("/api/auth/verify-email", async ({ query }) => {
    const token = query.token;
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
  }, {
    query: t.Object({ token: t.String() }),
    detail: { tags: ["Auth"], summary: "Verify user email via token" },
  })

  .post("/api/auth/resend-verification", async ({ request }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autorizado" }), { status: 401, headers: { "content-type": "application/json" } });

    const user = await getUser(auth.email);
    if (!user) return new Response(JSON.stringify({ error: "Usuario no encontrado" }), { status: 404, headers: { "content-type": "application/json" } });
    if (user.emailVerified) return new Response(JSON.stringify({ ok: true, message: "Email ya verificado" }), { headers: { "content-type": "application/json" } });

    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 2, 300_000); // 2 per 5 min
    if (limited) return limited;

    const verifyToken = crypto.randomUUID();
    await setVerifyToken(auth.email, verifyToken);
    const verifyUrl = `${getMainDomainUrl()}/api/auth/verify-email?token=${verifyToken}`;
    try {
      // Misma plantilla que el registro: antes eran dos copias del mismo cuerpo,
      // destinadas a divergir.
      await sendTemplate(auth.email, verifyEmailTemplate({ verifyUrl }));
    } catch (err) {
      log("error", "auth", "Failed to send verification email", { error: String(err) });
      return new Response(JSON.stringify({ error: "Error enviando email de verificación" }), { status: 500, headers: { "content-type": "application/json" } });
    }

    return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
  }, {
    detail: { tags: ["Auth"], summary: "Resend email verification link", security: [{ cookieAuth: [] }] },
  })

  .post("/api/auth/forgot-password", async ({ request, body: forgotBody }) => {
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 3, 60_000);
    if (limited) return limited;

    const email = (forgotBody.email ?? "").toLowerCase().trim();

    const emailLimited = checkRateLimit(`forgot:${email}`, 1, 60_000);
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
      try {
        const messageId = await sendTemplate(email, passwordReset({ resetUrl }));
        log("info", "auth", "Password reset email sent", { email, messageId });
      } catch (err) {
        log("error", "auth", "Failed to send password reset email", { email, error: String(err) });
      }
    }

    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  }, {
    body: t.Object({ email: t.String() }),
    detail: { tags: ["Auth"], summary: "Send password reset email" },
  })

  .post("/api/auth/set-password", async ({ request, body }) => {
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 5, 60_000);
    if (limited) return limited;

    const { token, password } = body;

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
  }, {
    body: t.Object({
      token: t.String(),
      password: t.String({ minLength: 8 }),
    }),
    detail: { tags: ["Auth"], summary: "Set new password using reset token" },
  })

  // --- Referrals ---

  .get("/api/referrals", async ({ request }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    const stats = getReferralStats(auth.email);
    const refs = listReferrals(auth.email);
    return new Response(JSON.stringify({ ...stats, referrals: refs }), { headers: { "content-type": "application/json" } });
  }, {
    detail: { tags: ["Referrals"], summary: "Get referral stats and list", security: [{ cookieAuth: [] }] },
  })

  .put("/api/referrals/slug", async ({ request, body }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 5, 60_000);
    if (limited) return limited;
    const slug = (body.slug ?? "").toLowerCase().trim();
    if (!slug || !/^[a-z0-9-]+$/.test(slug) || slug.length < 3 || slug.length > 30) {
      return new Response(JSON.stringify({ error: "Slug inválido: 3-30 caracteres, solo letras minúsculas, números y guiones" }), { status: 400 });
    }
    const ok = setReferralSlug(auth.email, slug);
    if (!ok) return new Response(JSON.stringify({ error: "Slug no disponible" }), { status: 409 });
    return new Response(JSON.stringify({ ok: true, slug }), { headers: { "content-type": "application/json" } });
  }, {
    body: t.Object({ slug: t.String() }),
    detail: { tags: ["Referrals"], summary: "Update referral slug", security: [{ cookieAuth: [] }] },
  })

  .post("/api/referrals/track", async ({ request, body }) => {
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 20, 60_000);
    if (limited) return limited;
    try {
      const slug = (body.slug ?? "").trim();
      if (slug) {
        const referrer = getUserByReferralSlug(slug);
        if (referrer) {
          recordReferralClick(referrer.email, ip, request.headers.get("user-agent"));
        }
      }
    } catch { /* ignore malformed bodies */ }
    return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
  }, {
    body: t.Object({ slug: t.String() }),
    detail: { tags: ["Referrals"], summary: "Track a referral link click" },
  })

  // --- Domains ---

  .get("/api/domains", async ({ request }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const domains = await listUserDomains(user.email);
    const fullUser = (await getUser(user.email))!;
    const limits = getUserPlanLimits(fullUser);
    const counts = getForwardCounts(domains.map(d => d.id));
    const enriched = domains.map(d => ({
      ...d,
      monthlyForwards: counts.get(d.id) ?? 0,
      forwardPerHour: limits.forwardPerHour,
    }));
    return new Response(JSON.stringify(enriched), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Domains", "SDK"], summary: "List all domains for the authenticated user", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  .post("/api/domains", async ({ request, body }) => {
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
          error: `Tu plan permite máximo ${limits.domains} dominio(s). Puedes agregar el add-on de dominio extra o subir de plan.`,
        }),
        { status: 400 },
      );
    }

    const { domain } = body;

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
    const existing = await (await import("./db.js")).getDomainByName(domain);
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
          spf: {
            type: "TXT",
            name: domain,
            value: "v=spf1 include:amazonses.com ~all",
          },
        },
      }),
      {
        status: 201,
        headers: { "content-type": "application/json" },
      },
    );
  }, {
    body: t.Object({
      domain: t.String(),
    }),
    detail: { tags: ["Domains", "SDK"], summary: "Add a new domain and configure SES", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  .get("/api/domains/:id", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const access = await checkDomainAccess(user.email, params.id, "read");
    if (!access) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }
    const domain = access.domain;

    return new Response(JSON.stringify(domain), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Domains", "SDK"], summary: "Get a single domain by ID", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  .get("/api/domains/:id/health", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const access = await checkDomainAccess(user.email, params.id, "read");
    if (!access)
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });

    const domain = access.domain;
    const d = domain.domain;
    const checks: Record<string, { ok: boolean; detail: string }> = {};

    // 1. Verificado — se le pregunta a SES, no a la base. La bandera local
    // decía "verificado en SES" sin haber consultado a SES nunca, que fue
    // exactamente cómo un dominio borrado de la cuenta pasó meses reportándose
    // sano mientras no podía enviar ni recibir.
    const estadoSes = await checkDomainStatus(d);
    if (!estadoSes.respondio) {
      checks.verified = {
        ok: domain.verified,
        detail: "No se pudo consultar SES; este es el último estado conocido.",
      };
    } else if (estadoSes.verified) {
      checks.verified = { ok: true, detail: "Dominio verificado en SES" };
    } else {
      checks.verified = {
        ok: false,
        detail: "SES no reconoce este dominio — vuelve a verificarlo y revisa los registros DNS",
      };
    }
    if (estadoSes.respondio && estadoSes.verified !== domain.verified) {
      await updateDomain(domain.id, { verified: estadoSes.verified });
    }

    // 2. MX records
    try {
      const mxRecords = await dns.resolveMx(d);
      const sesHost = "inbound-smtp.us-east-1.amazonaws.com";
      const sesRecord = mxRecords.find(r => r.exchange.toLowerCase() === sesHost);
      if (!sesRecord) {
        checks.mx = { ok: false, detail: `MX no apunta a MailMask. Registros actuales: ${mxRecords.map(r => `${r.priority} ${r.exchange}`).join(", ")}` };
      } else {
        const higherPriority = mxRecords.filter(r => r.priority < sesRecord.priority && r.exchange.toLowerCase() !== sesHost);
        if (higherPriority.length > 0) {
          checks.mx = { ok: false, detail: `MX de SES tiene prioridad ${sesRecord.priority}, pero hay otros con mayor prioridad: ${higherPriority.map(r => `${r.priority} ${r.exchange}`).join(", ")}` };
        } else {
          checks.mx = { ok: true, detail: `MX configurado correctamente (prioridad ${sesRecord.priority})` };
        }
      }
    } catch {
      checks.mx = { ok: false, detail: "No se encontraron registros MX" };
    }

    // 3. SPF
    try {
      const txtRecords = await dns.resolveTxt(d);
      const spf = txtRecords.flat().find(r => r.includes("v=spf1") && r.includes("amazonses.com"));
      checks.spf = spf
        ? { ok: true, detail: "SPF configurado correctamente" }
        : { ok: false, detail: "Falta include:amazonses.com en el registro SPF" };
    } catch {
      checks.spf = { ok: false, detail: "No se encontró registro SPF" };
    }

    // 4. DKIM — check via SES API (more reliable than DNS lookup which fails with CNAME flattening)
    const dkimTokens = domain.dkimTokens || [];
    if (dkimTokens.length === 0) {
      checks.dkim = { ok: false, detail: "No hay tokens DKIM configurados" };
    } else {
      try {
        const { SESClient, GetIdentityDkimAttributesCommand } = await import("@aws-sdk/client-ses");
        const sesClient = new SESClient({ region: AWS_REGION });
        const dkimRes = await sesClient.send(new GetIdentityDkimAttributesCommand({ Identities: [d] }));
        const dkimAttrs = dkimRes.DkimAttributes?.[d];
        if (dkimAttrs?.DkimVerificationStatus === "Success") {
          checks.dkim = { ok: true, detail: "DKIM verificado por SES" };
        } else {
          checks.dkim = { ok: false, detail: `DKIM ${dkimAttrs?.DkimVerificationStatus ?? "no configurado"} — verifica los 3 CNAMEs` };
        }
      } catch {
        checks.dkim = { ok: false, detail: "No se pudo verificar DKIM" };
      }
    }

    // 5. Aliases
    const aliases = listAliases(domain.id).filter(a => a.enabled);
    checks.aliases = aliases.length > 0
      ? { ok: true, detail: `${aliases.length} alias${aliases.length === 1 ? "" : "es"} activo${aliases.length === 1 ? "" : "s"}` }
      : { ok: false, detail: "No hay aliases activos — los emails no se reenviarán" };

    // 6. Plan
    const ownerUser = getUser(domain.ownerEmail);
    if (ownerUser) {
      const limits = getUserPlanLimits(ownerUser);
      checks.plan = limits.domains > 0
        ? { ok: true, detail: `Plan ${ownerUser.plan || "basico"} activo` }
        : { ok: false, detail: "Plan sin dominios disponibles" };
    } else {
      checks.plan = { ok: false, detail: "Usuario propietario no encontrado" };
    }

    // Global status
    const allOk = Object.values(checks).every(c => c.ok);
    const hasError = !checks.verified.ok || !checks.plan.ok;
    const status = allOk ? "ok" : hasError ? "error" : "warning";

    let summary = "";
    if (allOk) {
      summary = "Todo configurado correctamente — tu dominio puede enviar y recibir emails";
    } else if (!checks.verified.ok) {
      summary = "Tu dominio no está verificado — configura los registros DNS y verifica";
    } else if (!checks.mx.ok) {
      summary = "Tu dominio no puede recibir emails: el registro MX no apunta a MailMask";
    } else if (!checks.spf.ok || !checks.dkim.ok) {
      summary = "Tu dominio puede tener problemas de entregabilidad — revisa SPF y DKIM";
    } else if (!checks.aliases.ok) {
      summary = "No hay aliases activos — los emails recibidos no se reenviarán";
    } else {
      summary = "Hay problemas con la configuración de tu dominio";
    }

    return new Response(JSON.stringify({ domain: d, checks, status, summary }), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Domains", "SDK"], summary: "Check domain health and DNS configuration", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  .post("/api/domains/:id/verify", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const access = await checkDomainAccess(user.email, params.id, "admin");
    if (!access) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }
    const domain = access.domain;

    // Antes, un dominio marcado como verificado en la base salía por aquí
    // devolviendo `true` sin preguntarle a SES. La intención era no
    // desverificar por un error pasajero, pero el efecto fue peor: cuando la
    // identidad de brendago.design desapareció de SES, MailMask siguió
    // afirmando que estaba verificada y el dominio pasó meses sin poder enviar
    // ni recibir, sin una sola señal.
    //
    // Ahora siempre se pregunta, y el resguardo vive donde corresponde: la
    // bandera sólo baja si SES respondió de verdad (`respondio`), no si la
    // consulta falló.
    const status = await checkDomainStatus(domain.domain);

    if (status.respondio && status.verified !== domain.verified) {
      await updateDomain(domain.id, { verified: status.verified });
      if (!status.verified) {
        log("warn", "ses", "El dominio dejó de estar verificado en SES", {
          domain: domain.domain,
          domainId: domain.id,
        });
      }
    }

    // Identidad verificada no implica recepción: la regla del rule set es
    // otro recurso y puede faltar (brendago.design, sep-2026). Se repara aquí.
    if (status.respondio && status.verified) {
      try {
        await ensureDomainInbound(domain.domain);
      } catch (err) {
        log("warn", "ses", "No se pudo asegurar la regla de recepción", { domain: domain.domain, error: String(err) });
      }
    }

    // Si no se pudo consultar, se reporta lo último que se sabía en vez de
    // inventar un "no verificado" que alarme sin motivo.
    if (!status.respondio) {
      return new Response(
        JSON.stringify({
          domain: domain.domain,
          verified: domain.verified,
          dkimVerified: false,
          stale: true,
          error: "No se pudo consultar SES; este es el último estado conocido.",
        }),
        { headers: { "content-type": "application/json" } },
      );
    }

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
  }, {
    detail: { tags: ["Domains", "SDK"], summary: "Verify domain DNS configuration with SES", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  .delete("/api/domains/:id", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const access = await checkDomainAccess(user.email, params.id, "admin");
    if (!access) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }
    const domain = access.domain;

    // Clean up all SES resources (best effort)
    try { await deleteReceiptRule(domain.domain); } catch { /* best effort */ }
    try { await deleteConfigurationSet(domain.domain); } catch { /* best effort */ }
    try { await deleteDomainIdentity(domain.domain); } catch { /* best effort */ }

    await deleteDomain(params.id);
    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Domains", "SDK"], summary: "Delete a domain and clean up SES resources", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  // --- Aliases ---

  .get("/api/domains/:id/alias", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const access = await checkDomainAccess(user.email, params.id, "read");
    if (!access) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }
    const domain = access.domain;

    const aliases = await listAliases(domain.id);
    return new Response(JSON.stringify(aliases), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Aliases", "SDK"], summary: "List all aliases for a domain", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  .post("/api/domains/:id/alias", async ({ request, params, body }) => {
    const auth = await getAuthUser(request);
    if (!auth)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 20, 60_000);
    if (limited) return limited;
    const fullUser = (await getUser(auth.email))!;

    const access = await checkDomainAccess(auth.email, params.id, "write");
    if (!access) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }
    const domain = access.domain;

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

    const { alias, destinations } = body;

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
  }, {
    body: t.Object({
      alias: t.String(),
      destinations: t.Array(t.String()),
    }),
    detail: { tags: ["Aliases", "SDK"], summary: "Create a new alias for a domain", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  .put("/api/domains/:id/alias/:alias", async ({ request, params, body }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const access = await checkDomainAccess(user.email, params.id, "write");
    if (!access) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }
    const domain = access.domain;

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
  }, {
    body: t.Object({
      enabled: t.Optional(t.Boolean()),
      destinations: t.Optional(t.Array(t.String())),
    }),
    detail: { tags: ["Aliases", "SDK"], summary: "Update an alias", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  .delete("/api/domains/:id/alias/:alias", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const access = await checkDomainAccess(user.email, params.id, "write");
    if (!access) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }
    const domain = access.domain;

    const deleted = await deleteAlias(domain.id, params.alias);
    if (!deleted)
      return new Response(JSON.stringify({ error: "Alias no encontrado" }), {
        status: 404,
      });

    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Aliases", "SDK"], summary: "Delete an alias", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  // --- Rules ---

  .get("/api/domains/:id/rules", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const access = await checkDomainAccess(user.email, params.id, "read");
    if (!access) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }
    const domain = access.domain;

    const rules = await listRules(domain.id);
    return new Response(JSON.stringify(rules), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Rules", "SDK"], summary: "List all rules for a domain", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  .post("/api/domains/:id/rules", async ({ request, params, body }) => {
    const auth = await getAuthUser(request);
    if (!auth)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });
    const fullUser = (await getUser(auth.email))!;

    const access = await checkDomainAccess(auth.email, params.id, "write");
    if (!access) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }
    const domain = access.domain;

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
    } = body;

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

    // ReDoS: la revisión va aquí, al guardar, porque en tiempo de evaluación ya no hay
    // forma de defenderse — ver regex-guard.ts.
    if (match === "regex") {
      const motivo = revisarPatron(value);
      if (motivo) {
        return new Response(JSON.stringify({ error: motivo }), { status: 400 });
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
  }, {
    body: t.Object({
      field: t.Union([t.Literal("to"), t.Literal("from"), t.Literal("subject")]),
      match: t.Union([t.Literal("contains"), t.Literal("equals"), t.Literal("regex")]),
      value: t.String(),
      action: t.Union([t.Literal("forward"), t.Literal("webhook"), t.Literal("discard")]),
      target: t.Optional(t.String()),
      priority: t.Optional(t.Number()),
      enabled: t.Optional(t.Boolean()),
    }),
    detail: { tags: ["Rules", "SDK"], summary: "Create a new rule for a domain", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  .put("/api/domains/:id/rules/:ruleId", async ({ request, params, body }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const access = await checkDomainAccess(user.email, params.id, "write");
    if (!access) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }
    const domain = access.domain;

    const { field, match, value, action, target, priority, enabled } = body;

    // Validate field/match/action if provided
    const validFields = ["to", "from", "subject"];
    const validMatches = ["contains", "equals", "regex"];
    const validActions = ["forward", "webhook", "discard"];

    if (field !== undefined && !validFields.includes(field))
      return new Response(JSON.stringify({ error: "Valor inválido para field" }), { status: 400 });
    if (match !== undefined && !validMatches.includes(match))
      return new Response(JSON.stringify({ error: "Valor inválido para match" }), { status: 400 });
    if (action !== undefined && !validActions.includes(action))
      return new Response(JSON.stringify({ error: "Valor inválido para action" }), { status: 400 });

    // SSRF: validate webhook targets aren't private IPs
    const effectiveAction = action ?? undefined;
    const effectiveTarget = target ?? undefined;
    if (effectiveAction === "webhook" && effectiveTarget && isPrivateUrl(effectiveTarget)) {
      return new Response(
        JSON.stringify({ error: "URL de webhook no permitida (dirección privada)" }),
        { status: 400 },
      );
    }

    // Mismo criterio que al crear: ver regex-guard.ts.
    const effectiveMatch = match ?? undefined;
    const effectiveValue = value ?? undefined;
    if (effectiveMatch === "regex" && effectiveValue) {
      const motivo = revisarPatron(effectiveValue);
      if (motivo) {
        return new Response(JSON.stringify({ error: motivo }), { status: 400 });
      }
    }

    const updated = await updateRule(domain.id, params.ruleId, {
      field, match, value, action, target, priority, enabled,
    });
    if (!updated)
      return new Response(JSON.stringify({ error: "Regla no encontrada" }), {
        status: 404,
      });

    return new Response(JSON.stringify(updated), {
      headers: { "content-type": "application/json" },
    });
  }, {
    body: t.Object({
      field: t.Optional(t.Union([t.Literal("to"), t.Literal("from"), t.Literal("subject")])),
      match: t.Optional(t.Union([t.Literal("contains"), t.Literal("equals"), t.Literal("regex")])),
      value: t.Optional(t.String()),
      action: t.Optional(t.Union([t.Literal("forward"), t.Literal("webhook"), t.Literal("discard")])),
      target: t.Optional(t.String()),
      priority: t.Optional(t.Number()),
      enabled: t.Optional(t.Boolean()),
    }),
    detail: { tags: ["Rules", "SDK"], summary: "Update a rule", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  .delete("/api/domains/:id/rules/:ruleId", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const access = await checkDomainAccess(user.email, params.id, "write");
    if (!access) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }
    const domain = access.domain;

    const deleted = await deleteRule(domain.id, params.ruleId);
    if (!deleted)
      return new Response(JSON.stringify({ error: "Regla no encontrada" }), {
        status: 404,
      });

    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Rules", "SDK"], summary: "Delete a rule", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  // --- Logs ---

  .get("/api/domains/:id/logs", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    const access = await checkDomainAccess(user.email, params.id, "read");
    if (!access) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), {
        status: 404,
      });
    }
    const domain = access.domain;

    const url = new URL(request.url);
    const limit = Math.min(
      parseInt(url.searchParams.get("limit") ?? "50", 10),
      100,
    );

    const logs = await listLogs(domain.id, limit);
    return new Response(JSON.stringify(logs), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Logs", "SDK"], summary: "List forwarding logs for a domain", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  // --- Coupons (public) ---

  .get("/api/coupons/:code", async ({ params, request }) => {
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 10, 60_000);
    if (limited) return limited;
    const code = params.code.toUpperCase().trim();
    const coupon = await getCoupon(code);
    if (!coupon) {
      return new Response(JSON.stringify({ error: "Cupón no encontrado" }), {
        status: 404,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response(JSON.stringify({
      plan: coupon.plan,
      fixedPrice: coupon.fixedPrice,
      description: coupon.description,
    }), { headers: { "content-type": "application/json" } });
  }, {
    detail: { tags: ["Coupons"], summary: "Validate a coupon code" },
  })

  // --- Billing ---

  .post("/api/billing/guest-checkout", async ({ body: { plan = "basico", billing = "monthly", coupon, email: rawEmail }, request }) => {
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 5, 60_000);
    if (limited) return limited;

    const payerEmail = typeof rawEmail === "string" ? rawEmail.toLowerCase().trim() : "";
    if (!payerEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(payerEmail)) {
      return new Response(JSON.stringify({ error: "Ingresa tu email para continuar" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    }

    const planKey = plan as keyof typeof PLANS;
    if (!PLANS[planKey]) {
      return new Response(JSON.stringify({ error: "Plan inválido" }), {
        status: 400,
      });
    }
    const isYearly = billing === "yearly";

    // Validate coupon
    const couponCode = typeof coupon === "string" ? coupon.toUpperCase().trim() : undefined;
    const couponData = couponCode ? await getCoupon(couponCode) : null;
    const activeCoupon = couponData && couponData.plan === planKey ? couponData : undefined;

    const token = crypto.randomUUID();
    await createPendingCheckout(token, isYearly ? `${planKey}:yearly` : planKey);

    const { PreApproval } = await import("mercadopago");
    const mpAccessToken = process.env.MP_ACCESS_TOKEN;
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
      const couponSuffix = activeCoupon && couponCode ? ` [${couponCode}]` : "";
      const amount = activeCoupon
        ? activeCoupon.fixedPrice / 100
        : isYearly ? PLANS[planKey].yearlyPrice / 100 : PLANS[planKey].price / 100;
      if (amount < 1) {
        return new Response(JSON.stringify({ error: "El monto del cupón es inválido. Contacta soporte." }), { status: 400, headers: { "content-type": "application/json" } });
      }
      // deno-lint-ignore no-explicit-any
      const mpBody: any = {
        reason: `MailMask — Plan ${planKey.charAt(0).toUpperCase() + planKey.slice(1)} (${billingLabel})${couponSuffix}`,
        auto_recurring: {
          frequency: isYearly ? 12 : 1,
          frequency_type: "months",
          transaction_amount: amount,
          currency_id: "MXN",
          ...(isYearly ? {} : {
            free_trial: {
              frequency: 1,
              frequency_type: "months",
            },
          }),
        },
        payer_email: payerEmail,
        back_url: backUrl,
        external_reference: token,
        notification_url: `${getMainDomainUrl()}/api/webhooks/mercadopago`,
      };
      const result = await preApproval.create({ body: mpBody });

      // Mark single-use coupon as used AFTER successful MP call
      if (activeCoupon?.singleUse && couponCode) {
        await markCouponUsed(couponCode);
      }

      return new Response(JSON.stringify({ init_point: result.init_point }), {
        headers: { "content-type": "application/json" },
      });
    } catch (err: any) {
      const errDetail = err?.cause ?? err?.message ?? JSON.stringify(err);
      log("error", "billing", "MP guest-checkout error", { error: errDetail, amount });
      return new Response(
        JSON.stringify({ error: "Error al crear suscripción en MercadoPago" }),
        {
          status: 500,
          headers: { "content-type": "application/json" },
        },
      );
    }
  }, {
    body: t.Object({
      plan: t.Optional(t.String()),
      billing: t.Optional(t.String()),
      coupon: t.Optional(t.String()),
      email: t.Optional(t.String()),
    }),
    detail: { tags: ["Billing"], summary: "Create guest checkout session via MercadoPago" },
  })

  .post("/api/billing/checkout", async ({ body: { plan = "basico", billing = "monthly", coupon, payerEmail: rawPayerEmail }, request }) => {
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 5, 60_000);
    if (limited) return limited;

    const user = await getAuthUser(request);
    if (!user)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });

    // MercadoPago exige que `payer_email` sea el correo de la cuenta de MP de quien
    // paga: si no coincide, el checkout muere con "Tu e-mail no coincide con el de la
    // suscripción" y no hay forma de omitir el campo (es obligatorio en la API). Por eso
    // se pregunta aparte, con el correo de MailMask como default. `external_reference`
    // sigue siendo `user.email`, que es lo que usa el webhook para vincular.
    const payerEmail = typeof rawPayerEmail === "string" && rawPayerEmail.trim()
      ? rawPayerEmail.toLowerCase().trim()
      : user.email;
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(payerEmail)) {
      return new Response(JSON.stringify({ error: "El correo de MercadoPago no es válido" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    }

    const planKey = plan as keyof typeof PLANS;
    if (!PLANS[planKey]) {
      return new Response(JSON.stringify({ error: "Plan inválido" }), {
        status: 400,
      });
    }
    const isYearly = billing === "yearly";

    // Validate coupon
    const couponCode = typeof coupon === "string" ? coupon.toUpperCase().trim() : undefined;
    const couponData2 = couponCode ? await getCoupon(couponCode) : null;
    const activeCoupon = couponData2 && couponData2.plan === planKey ? couponData2 : undefined;

    const { PreApproval } = await import("mercadopago");
    const mpAccessToken = process.env.MP_ACCESS_TOKEN;
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
      const couponSuffix = activeCoupon && couponCode ? ` [${couponCode}]` : "";
      const amount = activeCoupon
        ? activeCoupon.fixedPrice / 100
        : isYearly ? PLANS[planKey].yearlyPrice / 100 : PLANS[planKey].price / 100;
      if (amount < 1) {
        return new Response(JSON.stringify({ error: "El monto del cupón es inválido. Contacta soporte." }), { status: 400, headers: { "content-type": "application/json" } });
      }
      // deno-lint-ignore no-explicit-any
      const mpBody: any = {
        reason: `MailMask — Plan ${planKey.charAt(0).toUpperCase() + planKey.slice(1)} (${billingLabel})${couponSuffix}`,
        auto_recurring: {
          frequency: isYearly ? 12 : 1,
          frequency_type: "months",
          transaction_amount: amount,
          currency_id: "MXN",
          ...(isYearly ? {} : {
            free_trial: {
              frequency: getUserReferredBy(user.email) ? 2 : 1,
              frequency_type: "months",
            },
          }),
        },
        payer_email: payerEmail,
        back_url: backUrl,
        external_reference: user.email,
        notification_url: `${getMainDomainUrl()}/api/webhooks/mercadopago`,
      };
      const result = await preApproval.create({ body: mpBody });

      // Mark single-use coupon as used AFTER successful MP call
      if (activeCoupon?.singleUse && couponCode) {
        await markCouponUsed(couponCode);
      }

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
  }, {
    body: t.Object({
      plan: t.Optional(t.String()),
      billing: t.Optional(t.String()),
      coupon: t.Optional(t.String()),
      payerEmail: t.Optional(t.String()),
    }),
    detail: { tags: ["Billing"], summary: "Create authenticated checkout session via MercadoPago", security: [{ cookieAuth: [] }] },
  })

  .post("/api/webhooks/mercadopago", async ({ request }) => {
    // Validate HMAC signature
    const secret = process.env.MP_WEBHOOK_SECRET;
    if (!secret) {
      log("error", "webhook", "MP_WEBHOOK_SECRET not configured");
      return new Response("Server misconfigured", { status: 500 });
    }
    const xSignature = request.headers.get("x-signature") ?? "";
    const xRequestId = request.headers.get("x-request-id") ?? "";
    const url = new URL(request.url);

    // El cuerpo se lee ANTES de validar la firma porque `data.id` no siempre viene en la
    // query (formato IPN antiguo, o notificaciones donde solo llega en el body).
    let rawBody = "";
    // deno-lint-ignore no-explicit-any
    let body: any = {};
    try {
      rawBody = await request.text();
      body = rawBody ? JSON.parse(rawBody) : {};
    } catch (err) {
      log("warn", "webhook", "MP webhook: cuerpo ilegible", { error: String(err), rawLength: rawBody.length });
      return new Response("Bad Request", { status: 400 });
    }

    const queryDataId = url.searchParams.get("data.id") ?? url.searchParams.get("id") ?? "";
    const bodyDataId = String(body?.data?.id ?? body?.id ?? "");
    const dataId = queryDataId || bodyDataId;

    // Parse ts and v1 from x-signature
    const parts = Object.fromEntries(
      xSignature.split(",").map((p) => {
        const [k, ...v] = p.trim().split("=");
        return [k, v.join("=")];
      }),
    );
    const ts = parts["ts"] ?? "";
    const v1 = parts["v1"] ?? "";

    const hmacHex = async (msg: string) => {
      const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
      );
      const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
      return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
    };

    // MercadoPago especifica que los ids alfanuméricos van en minúsculas, y que el
    // segmento se OMITE cuando el valor no viene. Antes se mandaba siempre "id:;" y
    // "request-id:;", lo que producía un 401 en cuanto faltaba alguno — y tras una racha
    // de 401 MP deshabilita la URL de notificación.
    const buildManifest = (id: string, reqId: string) =>
      (id ? `id:${id};` : "") + (reqId ? `request-id:${reqId};` : "") + (ts ? `ts:${ts};` : "");

    // Se prueban las variantes plausibles del id; todas exigen firma válida, así que no
    // se debilita nada. Es tolerancia al formato, no al secreto.
    const candidates = [...new Set([
      buildManifest(dataId.toLowerCase(), xRequestId),
      buildManifest(dataId, xRequestId),
      buildManifest(queryDataId.toLowerCase(), xRequestId),
      buildManifest(bodyDataId.toLowerCase(), xRequestId),
    ])];

    let matched = false;
    for (const candidate of candidates) {
      const computed = await hmacHex(candidate);
      // Comparación en tiempo constante.
      if (computed.length === v1.length && computed.length > 0) {
        let diff = 0;
        for (let i = 0; i < computed.length; i++) diff |= computed.charCodeAt(i) ^ v1.charCodeAt(i);
        if (diff === 0) { matched = true; break; }
      }
    }

    if (!matched) {
      // Un 401 sin datos era indistinguible de "nunca llegó". Esto es lo que permite
      // diagnosticar el próximo incidente sin adivinar.
      log("warn", "webhook", "MP webhook: invalid signature", {
        dataId, queryDataId, bodyDataId, xRequestId, ts,
        v1Received: v1.slice(0, 16),
        type: body?.type ?? body?.topic ?? null,
        manifestTried: candidates[0],
        secretLen: secret.length,
      });
      return new Response("Unauthorized", { status: 401 });
    }

    // La clave de idempotencia es el id del EVENTO, no el del preapproval. Antes se
    // usaba data.id, así que el primer evento de una suscripción bloqueaba todos los
    // siguientes durante 7 días: si MP mandaba "pending" y luego "authorized", el bueno
    // se descartaba en silencio. Es el candidato principal del pago que se perdió.
    const eventKey = xRequestId || `${body.type ?? body.topic ?? "unknown"}:${dataId}:${ts}`;
    log("info", "webhook", "MP webhook received", { type: body.type ?? body.topic, dataId, eventKey });

    // Handle subscription_preapproval events
    if (body.type === "subscription_preapproval" && body.data?.id) {
      try {
        // Idempotency: skip if already successfully processed
        if (await isWebhookProcessed(eventKey)) {
          log("info", "webhook", "MP webhook duplicado, ignorado", { eventKey, dataId });
          return new Response("OK", { status: 200 });
        }

        const mpAccessToken = process.env.MP_ACCESS_TOKEN;
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
        // Sin esto, un 4xx/5xx de MP producía un objeto de error que fallaba por todas
        // las ramas y devolvía 200: pago perdido sin reintento y sin rastro.
        if (!subRes.ok) {
          const errText = await subRes.text().catch(() => "");
          log("error", "webhook", "MP preapproval fetch failed", { status: subRes.status, dataId, body: errText.slice(0, 300) });
          return new Response("Upstream error", { status: 500 }); // 500 para que MP reintente
        }
        const sub = await subRes.json();

        log("info", "webhook", "MP subscription fetched", { payer_email: sub.payer_email, external_reference: sub.external_reference, status: sub.status });

        const externalRef = sub.external_reference ?? "";

        // Add-ons: preapproval propio, aparte de la suscripción base. Se atiende aquí y se
        // sale, para no tocar nunca subPlan/subMpId — la detección de plan por monto de
        // más abajo mapearía $49 a "basico" y le rompería la suscripción al usuario.
        if (externalRef.startsWith("addon:")) {
          const addon = getAddonById(externalRef.slice("addon:".length));
          if (!addon) {
            log("warn", "webhook", "Add-on preapproval sin fila", { externalRef });
          } else if (sub.status === "authorized") {
            const end = new Date();
            end.setDate(end.getDate() + 35);
            updateAddon(addon.id, {
              status: "active",
              mpPreapprovalId: body.data.id,
              currentPeriodEnd: end.toISOString(),
            });
            log("info", "billing", "Add-on activado", { addonId: addon.id, kind: addon.kind, email: addon.userEmail });

            // La clave es el id del add-on y no el del evento: MercadoPago puede
            // reenviar `authorized` para el mismo preapproval indefinidamente, y solo
            // el primero es un cobro.
            const order = recordOrder({
              userEmail: addon.userEmail,
              kind: "charge",
              subject: "addon",
              subjectId: addon.id,
              subjectKey: addon.kind,
              description: addonLabel(addon.kind),
              amountCents: Math.round((sub.auto_recurring?.transaction_amount ?? 0) * 100),
              listPriceCents: addon.priceCents,
              currency: sub.auto_recurring?.currency_id ?? "MXN",
              periodEnd: end.toISOString(),
              mpPreapprovalId: String(body.data.id),
              mpStatus: sub.status,
              eventKey: `addon-activate:${addon.id}`,
              occurredAt: sub.date_created ?? undefined,
              raw: sub,
            });
            if (order) {
              try {
                await sendTemplate(addon.userEmail, addonPurchase({
                  addonLabel: addonLabel(addon.kind),
                  order,
                  nextChargeAt: end.toISOString(),
                }));
              } catch (err) {
                log("error", "billing", "No se pudo mandar el recibo del add-on", { addonId: addon.id, error: String(err) });
              }
            }
          } else if (sub.status === "cancelled" || sub.status === "paused") {
            updateAddon(addon.id, { status: "cancelled", cancelledAt: new Date().toISOString() });
            log("info", "billing", "Add-on cancelado", { addonId: addon.id, kind: addon.kind, mpStatus: sub.status });
            recordOrder({
              userEmail: addon.userEmail,
              kind: "cancellation",
              subject: "addon",
              subjectId: addon.id,
              subjectKey: addon.kind,
              description: addonLabel(addon.kind),
              periodEnd: addon.currentPeriodEnd ?? null,
              mpPreapprovalId: String(body.data.id),
              mpStatus: sub.status,
              // Misma clave que emite el endpoint de cancelar, para que la baja hecha
              // por el usuario y su eco desde MercadoPago sean una sola fila.
              eventKey: `addon-cancel:${addon.id}`,
              raw: sub,
            });
          }
          await markWebhookProcessed(eventKey);
          return new Response("OK", { status: 200 });
        }

        const UUID_RE =
          /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        const isGuestCheckout = UUID_RE.test(externalRef);

        // Resolve email: for guest checkout use payer_email from MP, otherwise external_reference is the email
        let email = isGuestCheckout ? sub.payer_email : externalRef;
        if (!email) email = sub.payer_email;
        if (email) email = email.toLowerCase().trim();

        if (email) {
          if (sub.status === "authorized") {
            // Increment payment count and check referral conversion
            const newPaymentCount = incrementPaymentCount(email);
            if (newPaymentCount === 2) {
              const referral = getReferralByReferred(email);
              if (referral && referral.status === "pending") {
                markReferralConverted(referral.id);
                createReferralCredit(referral.referrerEmail, referral.id);
                log("info", "webhook", "Referral converted, credit created", { referrer: referral.referrerEmail, referred: email });
              }
            }

            // Check if this is a renewal for an existing active user
            const existingUser = await getUser(email);
            const existingSub = existingUser?.subscription;
            const isYearlyBilling = sub.auto_recurring?.frequency === 12;
            const bufferDays = isYearlyBilling ? 370 : 35;

            // Apply referral credits if available (2 credits = 100% = 30 extra days)
            const credits = getUnusedCredits(email);
            if (credits.length >= 2) {
              const toUse = credits.slice(0, 2);
              markCreditsUsed(toUse.map(c => c.id));
              extendSubscriptionPeriod(email, 30);
              log("info", "webhook", "Referral credits applied — 30 day extension", { email, creditsUsed: 2 });
            }

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

              // Try to determine plan from reason (handles coupons with non-standard amounts)
              if (!plan) {
                const reasonMatch = sub.reason?.match(/Plan (\w+)/i);
                if (reasonMatch) {
                  const parsed = reasonMatch[1].toLowerCase() as PlanKey;
                  if (["basico", "freelancer", "developer", "pro", "agencia"].includes(parsed)) {
                    plan = parsed;
                  }
                }
              }

              // Fallback to amount-based lookup for backwards compat
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
                // Se marca procesado: sin esto MP reintenta el mismo evento irresoluble
                // durante días y el log se llena de ruido que tapa incidentes reales.
                await markWebhookProcessed(eventKey);
                return new Response("OK", { status: 200 });
              }

              // Guest checkout: create user if not exists
              if (isGuestCheckout) {
                const created = await createUserIfNotExists(email, await hashPassword(crypto.randomUUID()));
                if (created) log("info", "webhook", "Guest user created", { email });
              }

              const periodEnd = new Date();
              periodEnd.setDate(periodEnd.getDate() + bufferDays);

              // 2nd month free for referred users on first activation
              const referredBy = getUserReferredBy(email);
              let referralBonusDays = 0;
              if (referredBy && (!existingSub || existingSub.status === "none")) {
                periodEnd.setDate(periodEnd.getDate() + 30);
                referralBonusDays = 30;
                log("info", "webhook", "Referred user gets 2nd month free", { email, referrer: referredBy });
              }

              const written = await updateUserSubscription(email, {
                plan,
                status: "active",
                mpSubscriptionId: body.data.id,
                currentPeriodEnd: periodEnd.toISOString(),
              });
              if (!written) {
                // La fila no existe: se estaba logueando "activated" sin haber escrito nada.
                log("error", "webhook", "Subscription NOT activated: usuario inexistente", { email, plan, dataId: body.data.id });
                return new Response("User not found", { status: 500 }); // 500 para que MP reintente
              }
              log("info", "webhook", "Subscription activated", { email, plan, mpId: body.data.id });

              const order = recordOrder({
                userEmail: email,
                kind: "charge",
                subject: "plan",
                subjectKey: plan,
                description: `Plan ${planLabel(plan)} (${sub.auto_recurring?.frequency === 12 ? "anual" : "mensual"})`,
                // El monto real cobrado, no el de lista: la diferencia entre los dos es
                // donde se ve un cupón aplicado, dato que hasta hoy se tiraba.
                amountCents: Math.round((sub.auto_recurring?.transaction_amount ?? 0) * 100),
                listPriceCents: PLANS[plan]?.price ?? null,
                currency: sub.auto_recurring?.currency_id ?? "MXN",
                periodStart: new Date().toISOString(),
                periodEnd: periodEnd.toISOString(),
                mpPreapprovalId: String(body.data.id),
                mpStatus: sub.status,
                eventKey: `plan-activate:${body.data.id}`,
                occurredAt: sub.date_created ?? undefined,
                raw: sub,
              });

              if (isGuestCheckout) {
                // Guest checkout: send welcome email with password-setup link
                const pwToken = crypto.randomUUID();
                await setPasswordToken(email, pwToken);
                const setPasswordUrl = `${getMainDomainUrl()}/set-password?token=${pwToken}`;
                try {
                  await sendTemplate(email, guestWelcome({ plan, setPasswordUrl, order }));
                  log("info", "webhook", "Welcome email sent", { email });
                } catch (err) {
                  log("error", "webhook", "Failed to send welcome email", { email, error: String(err) });
                }
              } else if (order) {
                // El `order` nulo significa evento duplicado: no se reenvía el recibo.
                try {
                  await sendTemplate(email, paymentConfirmation({
                    plan,
                    order,
                    nextChargeAt: periodEnd.toISOString(),
                    referralBonusDays: referralBonusDays || undefined,
                  }));
                  log("info", "webhook", "Payment confirmation sent", { email, orderNumber: order.number });
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
              recordOrder({
                userEmail: email,
                kind: "cancellation",
                subject: "plan",
                subjectKey: currentSub.plan,
                description: `Plan ${planLabel(currentSub.plan)}`,
                periodEnd: currentSub.currentPeriodEnd ?? null,
                mpPreapprovalId: String(body.data.id),
                mpStatus: sub.status,
                eventKey: `plan-cancel:${body.data.id}`,
                raw: sub,
              });
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
        } else {
          log("warn", "webhook", "Preapproval sin email resoluble", { dataId, externalRef });
        }

        // Fuera del `if (email)` a propósito: estaba dentro, así que un evento sin
        // email nunca se marcaba y MercadoPago lo reintentaba para siempre.
        await markWebhookProcessed(eventKey);
      } catch (err) {
        log("error", "webhook", "MP webhook processing error", { error: String(err) });
        return new Response("Internal error", { status: 500 });
      }
    }

    // Handle recurring charges. MP sends these as subscription_authorized_payment,
    // NOT as subscription_preapproval — without this the period end never advances
    // and the dashboard shows an active subscription as expired.
    if (body.type === "subscription_authorized_payment" && body.data?.id) {
      try {
        if (await isWebhookProcessed(eventKey)) {
          return new Response("OK", { status: 200 });
        }

        const mpAccessToken = process.env.MP_ACCESS_TOKEN;
        if (!mpAccessToken) {
          log("error", "webhook", "MP_ACCESS_TOKEN not configured");
          return new Response("Server misconfigured", { status: 500 });
        }

        const apRes = await fetch(
          `https://api.mercadopago.com/authorized_payments/${body.data.id}`,
          {
            headers: { Authorization: `Bearer ${mpAccessToken}` },
            signal: AbortSignal.timeout(10_000),
          },
        );
        // Sin este guard, un 5xx de MercadoPago devolvía un objeto de error que caía
        // por la rama de "no aprobado": registraríamos un cobro fallido que nunca
        // falló y le mandaríamos al cliente un "tu pago falló". Una caída pasajera de
        // MP se convertía en una renovación perdida para siempre, porque además se
        // marcaba el evento como procesado. Simétrico con el guard del preapproval.
        if (!apRes.ok) {
          const errText = await apRes.text().catch(() => "");
          log("error", "webhook", "MP authorized payment fetch failed", { status: apRes.status, dataId, body: errText.slice(0, 300) });
          return new Response("Upstream error", { status: 500 }); // 500 para que MP reintente
        }
        const ap = await apRes.json();
        log("info", "webhook", "MP authorized payment fetched", {
          preapproval_id: ap.preapproval_id,
          status: ap.status,
          paymentStatus: ap.payment?.status,
        });

        const approved = ap.status === "processed" &&
          (!ap.payment?.status || ap.payment.status === "approved");

        // El add-on se resuelve primero porque no vive en users.sub_mp_id.
        const renewingAddon = ap.preapproval_id ? getAddonByMpId(ap.preapproval_id) : null;

        // Resolver al dueño ANTES de mirar si el cobro se aprobó. Antes la rama de "no
        // aprobado" se salía aquí mismo, así que no había a quién registrarle el fallo
        // ni a quién avisarle: el plan simplemente se vencía en silencio.
        let user = renewingAddon ? await getUser(renewingAddon.userEmail) : getUserBySubscriptionId(ap.preapproval_id);
        let email = user?.email;

        if (!email && ap.preapproval_id) {
          const subRes = await fetch(
            `https://api.mercadopago.com/preapproval/${ap.preapproval_id}`,
            {
              headers: { Authorization: `Bearer ${mpAccessToken}` },
              signal: AbortSignal.timeout(10_000),
            },
          );
          // Mismo motivo que arriba: sin el guard, un 5xx de MP hace que el usuario
          // parezca irresoluble y el cobro se descarte con un 200.
          if (!subRes.ok) {
            const errText = await subRes.text().catch(() => "");
            log("error", "webhook", "MP preapproval fetch failed (renovación)", { status: subRes.status, preapprovalId: ap.preapproval_id, body: errText.slice(0, 300) });
            return new Response("Upstream error", { status: 500 });
          }
          const sub = await subRes.json();
          const externalRef = sub.external_reference ?? "";
          const UUID_RE =
            /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
          const candidate = UUID_RE.test(externalRef)
            ? sub.payer_email
            : externalRef || sub.payer_email;
          email = candidate ? String(candidate).toLowerCase().trim() : undefined;
          if (email) user = await getUser(email);
        }

        if (!approved || !ap.preapproval_id) {
          if (email) {
            const concepto = renewingAddon
              ? addonLabel(renewingAddon.kind)
              : `Plan ${planLabel(user?.subscription?.plan)}`;
            const accessUntil = renewingAddon
              ? renewingAddon.currentPeriodEnd
              : user?.subscription?.currentPeriodEnd;

            const failedOrder = recordOrder({
              userEmail: email,
              kind: "failed_charge",
              subject: renewingAddon ? "addon" : "plan",
              subjectId: renewingAddon?.id ?? null,
              subjectKey: renewingAddon?.kind ?? user?.subscription?.plan ?? null,
              description: concepto,
              // Cero porque no se movió dinero; lo que se intentó cobrar va en el
              // precio de lista.
              amountCents: 0,
              listPriceCents: Math.round((ap.transaction_amount ?? 0) * 100),
              currency: ap.currency_id ?? "MXN",
              periodEnd: accessUntil ?? null,
              mpPreapprovalId: ap.preapproval_id ?? null,
              mpAuthorizedPaymentId: String(ap.id),
              mpPaymentId: ap.payment?.id ? String(ap.payment.id) : null,
              mpStatus: ap.status,
              mpStatusDetail: ap.payment?.status_detail ?? ap.payment?.status ?? null,
              eventKey: chargeEventKey(ap),
              occurredAt: ap.date_created ?? undefined,
              raw: ap,
            });

            log("warn", "billing", "Cobro rechazado", {
              email, concepto, mpStatus: ap.status,
              paymentStatus: ap.payment?.status, duplicado: !failedOrder,
            });

            // Limitado a uno cada 3 días: MercadoPago dispara varios eventos de fallo
            // por ciclo, y una tarjeta vencida se convertiría en una ristra de correos
            // y en una queja de spam contra el dominio de envío.
            if (failedOrder && !(await isChargeFailureWarned(email))) {
              try {
                await sendTemplate(email, chargeFailed({
                  concept: concepto,
                  attemptedCents: Math.round((ap.transaction_amount ?? 0) * 100),
                  currency: ap.currency_id ?? "MXN",
                  accessUntil: accessUntil ?? null,
                  reason: ap.payment?.status_detail ?? null,
                }));
                await markChargeFailureWarned(email);
              } catch (err) {
                log("error", "billing", "No se pudo avisar del cobro fallido", { email, error: String(err) });
              }
            }
          } else {
            log("warn", "webhook", "Cobro rechazado sin dueño resoluble", { apId: ap.id, preapprovalId: ap.preapproval_id });
          }
          await markWebhookProcessed(eventKey);
          return new Response("OK", { status: 200 });
        }

        // Renovación mensual de un add-on. Sin esta rama el add-on expiraría aunque el
        // cliente siguiera pagando.
        if (renewingAddon) {
          const prev = renewingAddon.currentPeriodEnd ? new Date(renewingAddon.currentPeriodEnd) : new Date();
          const base = prev > new Date() ? prev : new Date();
          base.setDate(base.getDate() + 35);
          updateAddon(renewingAddon.id, { status: "active", currentPeriodEnd: base.toISOString() });
          log("info", "billing", "Add-on renovado", { addonId: renewingAddon.id, kind: renewingAddon.kind, until: base.toISOString() });

          const order = recordOrder({
            userEmail: renewingAddon.userEmail,
            kind: "charge",
            subject: "addon",
            subjectId: renewingAddon.id,
            subjectKey: renewingAddon.kind,
            description: addonLabel(renewingAddon.kind),
            amountCents: Math.round((ap.transaction_amount ?? 0) * 100),
            listPriceCents: renewingAddon.priceCents,
            currency: ap.currency_id ?? "MXN",
            periodEnd: base.toISOString(),
            mpPreapprovalId: ap.preapproval_id,
            mpAuthorizedPaymentId: String(ap.id),
            mpPaymentId: ap.payment?.id ? String(ap.payment.id) : null,
            mpStatus: ap.status,
            eventKey: chargeEventKey(ap),
            occurredAt: ap.date_created ?? undefined,
            raw: ap,
          });
          if (order) {
            try {
              await sendTemplate(renewingAddon.userEmail, renewalReceipt({
                concept: addonLabel(renewingAddon.kind),
                order,
                nextChargeAt: base.toISOString(),
              }));
            } catch (err) {
              log("error", "billing", "No se pudo mandar el recibo de renovación del add-on", { addonId: renewingAddon.id, error: String(err) });
            }
          }
          await markWebhookProcessed(eventKey);
          return new Response("OK", { status: 200 });
        }

        if (!email || !user?.subscription) {
          log("warn", "webhook", "Recurring charge for unknown user", {
            preapproval_id: ap.preapproval_id,
            email,
          });
          await markWebhookProcessed(eventKey);
          return new Response("OK", { status: 200 });
        }

        const bufferDays = ap.type === "yearly" ? 370 : 35;
        await extendSubscriptionPeriod(email, bufferDays);

        // Self-heal accounts activated manually (no preapproval id stored),
        // so future renewals resolve by id without hitting the MP API.
        if (!user.subscription.mpSubscriptionId) {
          const refreshed = await getUser(email);
          if (refreshed?.subscription) {
            await updateUserSubscription(email, {
              ...refreshed.subscription,
              mpSubscriptionId: ap.preapproval_id,
            });
          }
        }

        log("info", "webhook", "Subscription renewed via authorized payment", { email, bufferDays });

        const renewed = await getUser(email);
        const order = recordOrder({
          userEmail: email,
          kind: "charge",
          subject: "plan",
          subjectKey: user.subscription.plan,
          description: `Plan ${planLabel(user.subscription.plan)} (${ap.type === "yearly" ? "anual" : "mensual"})`,
          amountCents: Math.round((ap.transaction_amount ?? 0) * 100),
          listPriceCents: PLANS[user.subscription.plan]?.price ?? null,
          currency: ap.currency_id ?? "MXN",
          periodStart: user.subscription.currentPeriodEnd ?? null,
          periodEnd: renewed?.subscription?.currentPeriodEnd ?? null,
          mpPreapprovalId: ap.preapproval_id,
          mpAuthorizedPaymentId: String(ap.id),
          mpPaymentId: ap.payment?.id ? String(ap.payment.id) : null,
          mpStatus: ap.status,
          eventKey: chargeEventKey(ap),
          occurredAt: ap.date_created ?? undefined,
          raw: ap,
        });
        // Hasta hoy la renovación no mandaba nada: al cliente se le cobraba en absoluto
        // silencio, mes tras mes.
        if (order) {
          try {
            await sendTemplate(email, renewalReceipt({
              concept: `Plan ${planLabel(user.subscription.plan)}`,
              order,
              nextChargeAt: renewed?.subscription?.currentPeriodEnd ?? null,
            }));
            log("info", "billing", "Recibo de renovación enviado", { email, orderNumber: order.number });
          } catch (err) {
            log("error", "billing", "No se pudo mandar el recibo de renovación", { email, error: String(err) });
          }
        }

        await markWebhookProcessed(eventKey);
      } catch (err) {
        log("error", "webhook", "MP authorized payment processing error", { error: String(err) });
        return new Response("Internal error", { status: 500 });
      }
    }

    // Todo lo que no se maneja arriba llegaba hasta aquí y devolvía 200 sin un solo log.
    // MercadoPago usa "preapproval" a secas en algunas configuraciones de IPN, así que un
    // evento válido podía tirarse en silencio.
    log("warn", "webhook", "MP webhook: tipo no manejado", {
      type: body?.type ?? body?.topic ?? null,
      dataId,
      eventKey,
      action: body?.action ?? null,
    });
    return new Response("OK", { status: 200 });
  }, {
    detail: { tags: ["Webhooks"], summary: "MercadoPago subscription webhook", hide: true },
  })

  .post("/api/billing/cancel", async ({ request }) => {
    const auth = await getAuthUser(request);
    if (!auth)
      return new Response(JSON.stringify({ error: "No autenticado" }), {
        status: 401,
      });
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 3, 60_000);
    if (limited) return limited;
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

    const mpAccessToken = process.env.MP_ACCESS_TOKEN;
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

    // Cascada: sin plan base los add-ons no otorgan nada (getUserPlanLimits devuelve
    // ceros), así que hay que apagar el cobro o le seguiríamos cargando $99/mes.
    for (const addon of listEffectiveAddons(auth.email)) {
      try {
        if (addon.mpPreapprovalId) await cancelMpPreapproval(addon.mpPreapprovalId, mpAccessToken);
        updateAddon(addon.id, { status: "cancelled", cancelledAt: new Date().toISOString() });
      } catch (err) {
        log("error", "billing", "No se pudo cancelar add-on en cascada", { addonId: addon.id, error: String(err) });
      }
    }

    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Billing"], summary: "Cancel active MercadoPago subscription", security: [{ cookieAuth: [] }] },
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
  }, {
    detail: { tags: ["Billing"], summary: "Get current subscription status", security: [{ cookieAuth: [] }] },
  })

  // --- Add-ons ---

  // Endpoint aparte y no dentro de /api/auth/me: el historial crece sin techo y /me se
  // llama en cada carga del dashboard.
  .get("/api/billing/orders", async ({ request, query }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401, headers: { "content-type": "application/json" } });

    const limit = Math.min(Number(query.limit) || 50, 200);
    const rows = listOrders(auth.email, { limit, before: query.before });

    return new Response(JSON.stringify({
      // Se omiten `raw`, `grantedBy` y `eventKey`: son operativos, y `raw` trae datos
      // del pagador que MercadoPago nos manda y que no tenemos por qué devolver.
      orders: rows.map((o) => ({
        id: o.id,
        number: o.number,
        date: o.occurredAt,
        kind: o.kind,
        concept: o.description,
        subject: o.subject,
        amountCents: o.amountCents,
        listPriceCents: o.listPriceCents ?? null,
        currency: o.currency,
        periodStart: o.periodStart ?? null,
        periodEnd: o.periodEnd ?? null,
        failureReason: o.mpStatusDetail ?? null,
        note: o.note ?? null,
        reference: o.mpPaymentId ?? o.mpAuthorizedPaymentId ?? o.mpPreapprovalId ?? null,
      })),
      // Cursor por `createdAt` y no por `occurredAt`: los webhooks llegan tarde y
      // desordenados, así que solo el orden de inserción es monotónico.
      nextCursor: rows.length === limit ? rows[rows.length - 1].createdAt : null,
      invoiceNote: `¿Necesitas factura (CFDI)? Escríbenos a ${SUPPORT_EMAIL} con tu RFC, razón social, uso de CFDI y el folio del cargo.`,
    }), { headers: { "content-type": "application/json" } });
  }, {
    detail: { tags: ["Billing"], summary: "Payment, courtesy and cancellation history", security: [{ cookieAuth: [] }] },
  })

  .get("/api/addons", async ({ request }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    return new Response(JSON.stringify({ catalog: ADDONS, mine: listAddons(auth.email) }), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Billing"], summary: "List add-on catalog and user's add-ons", security: [{ cookieAuth: [] }] },
  })

  .post("/api/addons/checkout", async ({ request, body: addonBody }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 5, 60_000);
    if (limited) return limited;

    const { kind, payerEmail: rawPayerEmail } = addonBody;
    if (!(kind in ADDONS)) {
      return new Response(JSON.stringify({ error: "Add-on inválido" }), { status: 400 });
    }
    const addonKind = kind as AddonKind;

    // Mismo motivo que en /api/billing/checkout: `payer_email` tiene que ser el correo
    // de la cuenta de MercadoPago del pagador, no el de MailMask.
    const payerEmail = typeof rawPayerEmail === "string" && rawPayerEmail.trim()
      ? rawPayerEmail.toLowerCase().trim()
      : auth.email;
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(payerEmail)) {
      return new Response(JSON.stringify({ error: "El correo de MercadoPago no es válido" }), { status: 400 });
    }

    const user = await getUser(auth.email);
    if (!user) return new Response(JSON.stringify({ error: "Usuario no encontrado" }), { status: 404 });

    const limits = getUserPlanLimits(user);
    if (limits.domains === 0) {
      return new Response(JSON.stringify({ error: "Necesitas un plan activo para comprar add-ons" }), { status: 402 });
    }

    if (addonKind.startsWith("sends")) {
      if (user.subscription?.plan !== "basico") {
        return new Response(JSON.stringify({ error: "Tu plan ya incluye envío de emails" }), { status: 400 });
      }
      const existing = listEffectiveAddons(auth.email).find((a) => a.kind.startsWith("sends"));
      if (existing) {
        return new Response(JSON.stringify({ error: "Ya tienes un add-on de envíos activo. Cancélalo antes de cambiarlo." }), { status: 409 });
      }
      // Los `pending` también bloquean: sin esto, dos pestañas o un F5 en el paso de
      // MercadoPago crean dos suscripciones y se le cobra dos veces por un beneficio
      // que de todos modos no se acumula.
      const pending = listAddons(auth.email).find((a) =>
        a.kind.startsWith("sends") && a.status === "pending" &&
        Date.now() - new Date(a.createdAt).getTime() < 30 * 60_000);
      if (pending) {
        return new Response(JSON.stringify({ error: "Ya tienes una compra de envíos en curso. Termínala o espera unos minutos." }), { status: 409 });
      }
    }

    const mpAccessToken = process.env.MP_ACCESS_TOKEN;
    if (!mpAccessToken) {
      return new Response(JSON.stringify({ error: "Billing no configurado" }), { status: 500 });
    }

    const addon = createAddon(auth.email, addonKind);
    try {
      const { default: MercadoPagoConfig, PreApproval } = await import("mercadopago").then((m) => ({
        default: m.MercadoPagoConfig,
        PreApproval: m.PreApproval,
      }));
      const preApproval = new PreApproval(new MercadoPagoConfig({ accessToken: mpAccessToken }));
      const result = await preApproval.create({
        body: {
          // Sin la palabra "Plan": el webhook tiene un regex /Plan (\w+)/i que activaría
          // un plan por accidente. Salimos antes por el prefijo addon:, pero no hay razón
          // para dejar la mina puesta.
          reason: `MailMask — Add-on ${ADDONS[addonKind].label}`,
          auto_recurring: {
            frequency: 1,
            frequency_type: "months",
            transaction_amount: ADDONS[addonKind].price / 100,
            currency_id: "MXN",
          },
          payer_email: payerEmail,
          back_url: `${getMainDomainUrl()}/app?addon=success`,
          external_reference: `addon:${addon.id}`,
          // El tipo del SDK no declara notification_url, pero la API sí lo acepta.
          notification_url: `${getMainDomainUrl()}/api/webhooks/mercadopago`,
          // deno-lint-ignore no-explicit-any
        } as any,
      });
      updateAddon(addon.id, { mpPreapprovalId: result.id });
      return new Response(JSON.stringify({ init_point: result.init_point, addonId: addon.id }), {
        headers: { "content-type": "application/json" },
      });
    } catch (err) {
      updateAddon(addon.id, { status: "expired" });
      log("error", "billing", "Add-on checkout failed", { error: String(err), kind: addonKind });
      return new Response(JSON.stringify({ error: "Error creando la suscripción del add-on" }), { status: 500 });
    }
  }, {
    body: t.Object({ kind: t.String(), payerEmail: t.Optional(t.String()) }),
    detail: { tags: ["Billing"], summary: "Start add-on subscription checkout", security: [{ cookieAuth: [] }] },
  })

  .post("/api/addons/:id/cancel", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 5, 60_000);
    if (limited) return limited;

    const addon = getAddonById(params.id);
    if (!addon || addon.userEmail !== auth.email) {
      return new Response(JSON.stringify({ error: "Add-on no encontrado" }), { status: 404 });
    }
    if (addon.status === "cancelled" || addon.status === "expired") {
      return new Response(JSON.stringify({ error: "El add-on ya está cancelado" }), { status: 400 });
    }
    // Esconder el botón en la UI no basta: la compuerta real es ésta. Una cortesía no
    // se cobra, así que "cancelar" solo destruiría el regalo sin ahorrarle un peso a
    // nadie — y es exactamente lo que la pantalla vieja invitaba a hacer.
    if (addon.source === "courtesy") {
      return new Response(JSON.stringify({
        error: "Este add-on es una cortesía de MailMask. No tiene costo y no se puede cancelar desde aquí — escríbenos si quieres liberarlo.",
      }), { status: 400 });
    }

    const mpAccessToken = process.env.MP_ACCESS_TOKEN;
    if (addon.mpPreapprovalId && mpAccessToken) {
      try {
        await cancelMpPreapproval(addon.mpPreapprovalId, mpAccessToken);
      } catch (err) {
        log("error", "billing", "MP add-on cancel error", { error: String(err), addonId: addon.id });
        return new Response(JSON.stringify({ error: "Error al cancelar en MercadoPago" }), { status: 500 });
      }
    }

    // Se conserva currentPeriodEnd: el usuario mantiene el cupo hasta que termine
    // el periodo que ya pagó (listEffectiveAddons lo sigue contando).
    updateAddon(addon.id, { status: "cancelled", cancelledAt: new Date().toISOString() });
    return new Response(JSON.stringify({ ok: true, activeUntil: addon.currentPeriodEnd ?? null }), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Billing"], summary: "Cancel an add-on subscription", security: [{ cookieAuth: [] }] },
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
  }, {
    detail: { tags: ["Export"], summary: "Export all user data as JSON", security: [{ cookieAuth: [] }] },
  })

  // --- Outbound send ---

  .post("/api/domains/:id/send", async ({ request, params, body: sendBody }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 20, 60_000);
    if (limited) return limited;
    const user = (await getUser(auth.email))!;
    const limits = getUserPlanLimits(user);

    if (limits.sends === 0 || !limits.sendsUnlocked) {
      return new Response(JSON.stringify({ error: "Tu plan no incluye envío de emails. Agrega el add-on de envíos." }), { status: 403 });
    }

    const access = await checkDomainAccess(auth.email, params.id, "write");
    if (!access) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }
    const domain = access.domain;
    if (!domain.verified) {
      return new Response(JSON.stringify({ error: "Dominio no verificado" }), { status: 400 });
    }

    const { to, subject, html, body: textBody, markdown, replyTo, from: fromLocal, fromName } = sendBody;
    if (!to || !subject || (!html && !textBody && !markdown)) {
      return new Response(JSON.stringify({ error: "to, subject y body/html/markdown requeridos" }), { status: 400 });
    }
    if (html && Buffer.byteLength(html, "utf8") > MAX_EMAIL_HTML_BYTES) {
      return new Response(JSON.stringify({ error: "El HTML excede 100 KB; Gmail recorta el mensaje" }), { status: 413 });
    }
    // Un solo lugar decide qué va como text/plain y qué como text/html. Antes se
    // mandaba `(textBody ?? html)` como texto plano: quien leyera en modo texto
    // recibía el marcado crudo.
    const rendered = resolveEmailBody({ markdown, html, body: textBody });

    const recipient = normalizeAddress(to);
    if (await isSuppressed(domain.id, recipient)) {
      return new Response(JSON.stringify({ error: "Destinatario en lista de supresión (bounce/complaint previo)" }), { status: 422 });
    }

    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(recipient)) {
      return new Response(JSON.stringify({ error: "Destinatario inválido" }), { status: 400 });
    }

    // El remitente debe ser un alias real del dominio: sin esto se puede enviar como
    // cualquier dirección del dominio propio. Se compara y se usa el local-part ya
    // saneado, no el valor crudo — "ventas@evil.com" produciría un From inválido.
    let fromLocalPart = "noreply";
    if (fromLocal !== undefined && fromLocal !== null) {
      const candidate = String(fromLocal).split("@")[0].trim().toLowerCase();
      const sendAliases = await listAliases(domain.id);
      const hit = sendAliases.find((a) => a.alias.toLowerCase() === candidate && a.enabled && a.alias !== "*");
      if (!hit) {
        return new Response(JSON.stringify({ error: "El remitente debe ser un alias activo de tu dominio" }), { status: 400 });
      }
      fromLocalPart = hit.alias;
    }

    // Reservar antes de enviar: chequear y luego incrementar deja pasar dos peticiones
    // simultáneas por el mismo hueco.
    const reservedSend = await incrementSendCount(domain.id);
    if (reservedSend > limits.sends) {
      decrementSendCount(domain.id);
      return new Response(JSON.stringify({ error: `Límite diario de envíos alcanzado (${limits.sends})` }), { status: 429 });
    }

    // `sendFromDomain` conserva el display name si el From viene en forma
    // "Nombre <buzon@dominio>" (ses.ts) — el sobre de SES sigue llevando la
    // dirección pelada. Se codifica como header para que un nombre con acentos
    // no meta bytes crudos, y de paso mata cualquier salto de línea.
    const bareFrom = `${fromLocalPart}@${domain.domain}`;
    const fromAddress = fromName?.trim()
      ? `${encodeHeader(fromName.trim())} <${bareFrom}>`
      : bareFrom;
    try {
      const messageId = await sendFromDomain(fromAddress, recipient, subject, rendered.text, {
        html: rendered.html,
        replyTo,
        configSet: getConfigSetName(domain.domain),
      });
      return new Response(JSON.stringify({ ok: true, messageId }), {
        headers: { "content-type": "application/json" },
      });
    } catch (err) {
      decrementSendCount(domain.id); // devolver la cuota reservada
      log("error", "ses", "Outbound send failed", { error: String(err), domainId: domain.id });
      return new Response(JSON.stringify({ error: "Error enviando email" }), { status: 500 });
    }
  }, {
    body: t.Object({
      to: t.String(),
      subject: t.String(),
      body: t.Optional(t.String()),
      html: t.Optional(t.String()),
      markdown: t.Optional(t.String()),
      replyTo: t.Optional(t.String()),
      from: t.Optional(t.String()),
      fromName: t.Optional(t.String()),
    }),
    detail: { tags: ["Send", "SDK"], summary: "Send an email from a domain", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  // --- Bulk send ---

  .post("/api/domains/:id/send-bulk", async ({ request, params, body: bulkBody }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 5, 60_000);
    if (limited) return limited;
    const user = (await getUser(auth.email))!;
    const limits = getUserPlanLimits(user);

    if (limits.sends === 0 || !limits.sendsUnlocked) {
      return new Response(JSON.stringify({ error: "Tu plan no incluye envío de emails. Agrega el add-on de envíos." }), { status: 403 });
    }

    const access = await checkDomainAccess(auth.email, params.id, "write");
    if (!access) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }
    const domain = access.domain;
    if (!domain.verified) {
      return new Response(JSON.stringify({ error: "Dominio no verificado" }), { status: 400 });
    }

    const { recipients, subject, html, from: fromLocal } = bulkBody;
    if (!recipients?.length || !subject || !html) {
      return new Response(JSON.stringify({ error: "recipients[], subject y html requeridos" }), { status: 400 });
    }
    if (!Array.isArray(recipients) || recipients.length > 10000) {
      return new Response(JSON.stringify({ error: "Máximo 10,000 destinatarios por lote" }), { status: 400 });
    }
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    const invalid = recipients.filter((r: string) => typeof r !== "string" || !emailRegex.test(r));
    if (invalid.length) {
      return new Response(JSON.stringify({ error: `Emails inválidos: ${invalid.slice(0, 5).join(", ")}` }), { status: 400, headers: { "content-type": "application/json" } });
    }

    // Sin esto un job de 10,000 sale completo aunque el plan tope en 25 al día.
    const usedToday = await getSendCount(domain.id);
    if (usedToday + recipients.length > limits.sends) {
      return new Response(JSON.stringify({
        error: `El lote excede tu límite diario: te quedan ${Math.max(0, limits.sends - usedToday)} envíos de ${limits.sends}`,
      }), { status: 429, headers: { "content-type": "application/json" } });
    }

    // Mismo saneamiento que en el envío unitario: el local-part sale del alias
    // encontrado, no del valor crudo del body.
    let bulkFromLocal = "noreply";
    if (fromLocal !== undefined && fromLocal !== null) {
      const candidate = String(fromLocal).split("@")[0].trim().toLowerCase();
      const bulkAliases = await listAliases(domain.id);
      const hit = bulkAliases.find((a) => a.alias.toLowerCase() === candidate && a.enabled && a.alias !== "*");
      if (!hit) {
        return new Response(JSON.stringify({ error: "El remitente debe ser un alias activo de tu dominio" }), { status: 400 });
      }
      bulkFromLocal = hit.alias;
    }

    const fromAddress = `${bulkFromLocal}@${domain.domain}`;
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
  }, {
    body: t.Object({
      recipients: t.Array(t.String()),
      subject: t.String(),
      html: t.String(),
      from: t.Optional(t.String()),
    }),
    detail: { tags: ["Send", "SDK"], summary: "Create a bulk email send job", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  .get("/api/domains/:id/bulk/:jobId", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const access = await checkDomainAccess(auth.email, params.id, "read");
    if (!access) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }
    const domain = access.domain;

    const job = await getBulkJob(domain.id, params.jobId);
    if (!job) return new Response(JSON.stringify({ error: "Job no encontrado" }), { status: 404 });

    return new Response(JSON.stringify(job), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Send", "SDK"], summary: "Get bulk send job status", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  // --- Mesa: SSE ---

  .get("/api/bandeja/sse", async ({ request }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response("Unauthorized", { status: 401 });

    const url = new URL(request.url);
    const domainId = url.searchParams.get("domainId");
    if (!domainId) return new Response(JSON.stringify({ error: "domainId required" }), { status: 400 });

    const access = await checkDomainAccess(auth.email, domainId, "read");
    if (!access) return new Response(JSON.stringify({ error: "Sin acceso" }), { status: 403 });

    const stream = new ReadableStream({
      start(controller) {
        const encoder = new TextEncoder();
        controller.enqueue(encoder.encode(": connected\n\n"));

        const cleanup = addSseClient(auth.email, domainId, controller);

        const heartbeat = setInterval(() => {
          try { controller.enqueue(encoder.encode(": ping\n\n")); } catch { clearInterval(heartbeat); }
        }, 30_000);

        // Cleanup on abort
        request.signal.addEventListener("abort", () => {
          clearInterval(heartbeat);
          cleanup();
          try { controller.close(); } catch {}
        });
      },
    });

    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
      },
    });
  }, {
    detail: { hide: true },
  })

  // --- Mesa: conversations ---

  .get("/api/bandeja/conversations", async ({ request }) => {
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

    let convs = await listConversations(domainId, { status, assignedTo });

    // Auto-rebuild from S3 only if domain has zero conversations (including deleted)
    const hasDeletedConvs = convs.length === 0 && listConversations(domainId, { status: "deleted" }).length > 0;
    if (convs.length === 0 && !hasDeletedConvs && domain.domain) {
      try {
        const rebuilt = await rebuildConversationsFromS3(domainId, domain.domain);
        if (rebuilt > 0) {
          convs = await listConversations(domainId, { status, assignedTo });
        }
      } catch (err) {
        console.error("Mesa rebuild from S3 failed:", err);
      }
    }

    return new Response(JSON.stringify(convs), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Bandeja"], summary: "List conversations for a domain", security: [{ cookieAuth: [] }] },
  })

  .get("/api/bandeja/conversations/:id", async ({ request, params }) => {
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

    const [rawMessages, notes] = await Promise.all([
      listMessages(conv.id),
      listNotes(conv.id),
    ]);

    // Fetch body from S3 on demand for inbound messages
    const messages = await Promise.all(rawMessages.map(async (msg) => {
      if (msg.s3Bucket && msg.s3Key && !msg.body) {
        try {
          const raw = await fetchEmailFromS3(msg.s3Bucket, msg.s3Key);
          const attachments = extractAttachments(raw);
          return { ...msg, body: extractPlainBody(raw), html: extractHtmlBody(raw), attachments };
        } catch (err) {
          console.error("Failed to fetch message body from S3:", err);
          return { ...msg, body: "(Error al cargar el mensaje)", html: "", attachments: [] };
        }
      }
      return msg;
    }));

    return new Response(JSON.stringify({ ...conv, messages, notes }), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Bandeja"], summary: "Get conversation detail with messages", security: [{ cookieAuth: [] }] },
  })

  .get("/api/bandeja/conversations/:id/attachments/:msgIdx/:attIdx", async ({ request, params }) => {
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

    const messages = await listMessages(conv.id);
    const msgIdx = parseInt(params.msgIdx, 10);
    const attIdx = parseInt(params.attIdx, 10);
    if (isNaN(msgIdx) || isNaN(attIdx) || msgIdx < 0 || msgIdx >= messages.length) {
      return new Response(JSON.stringify({ error: "Índice inválido" }), { status: 400 });
    }

    const msg = messages[msgIdx];
    if (!msg.s3Bucket || !msg.s3Key) {
      return new Response(JSON.stringify({ error: "Mensaje sin contenido S3" }), { status: 404 });
    }

    try {
      const raw = await fetchEmailFromS3(msg.s3Bucket, msg.s3Key);
      const attachment = extractAttachmentByIndex(raw, attIdx);
      if (!attachment) {
        return new Response(JSON.stringify({ error: "Attachment no encontrado" }), { status: 404 });
      }

      const disposition = attachment.contentType.startsWith("image/") ? "inline" : "attachment";
      return new Response(attachment.data as unknown as BodyInit, {
        headers: {
          "content-type": attachment.contentType,
          "content-disposition": `${disposition}; filename="${attachment.filename.replace(/[\r\n\x00-\x1f"\\]/g, "")}"`,
          "cache-control": "private, max-age=3600",
        },
      });
    } catch (err) {
      console.error("Failed to fetch attachment from S3:", err);
      return new Response(JSON.stringify({ error: "Error al cargar attachment" }), { status: 500 });
    }
  }, {
    detail: { tags: ["Bandeja"], summary: "Download a message attachment", security: [{ cookieAuth: [] }] },
  })

  // Redactar un correo nuevo: crea la conversación y manda el primer mensaje.
  // A diferencia de responder, esto SÍ es correo que origina el usuario, así que pasa
  // por el add-on de envíos y su tope diario.
  .post("/api/bandeja/conversations", async ({ request, body: newBody }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 20, 60_000);
    if (limited) return limited;

    const { domainId, to, subject, body: textBody, html, markdown, fromAlias } = newBody;
    if (!domainId || !to || !subject || (!textBody && !html && !markdown) || !fromAlias) {
      return new Response(JSON.stringify({ error: "domainId, to, subject, fromAlias y body/html/markdown requeridos" }), { status: 400 });
    }
    if (html && Buffer.byteLength(html, "utf8") > MAX_EMAIL_HTML_BYTES) {
      return new Response(JSON.stringify({ error: "El HTML excede 100 KB; Gmail recorta el mensaje" }), { status: 413 });
    }
    const cc = parseCopyList((newBody as Record<string, unknown>).cc);
    const bcc = parseCopyList((newBody as Record<string, unknown>).bcc);
    const attachRefs = (newBody as Record<string, unknown>).attachments as AttachmentRef[] | undefined;

    // Redactar crea identidad saliente nueva, así que pide permiso de escritura —
    // no el owner||agent inline que usa el resto de la Bandeja.
    const access = await checkDomainAccess(auth.email, domainId, "write");
    if (!access) return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    const domain = access.domain;

    // La firma se pega al markdown y no al HTML: así sale también en la parte de
    // texto plano. Pegada al HTML, quien lea en texto vería un correo sin firmar.
    const rendered = resolveEmailBody({
      markdown: markdown ? appendSignature(markdown, domain.signature) : undefined,
      html,
      body: textBody,
    });

    const user = (await getUser(auth.email))!;
    const plan = user.subscription?.plan ?? "basico";
    const mesaLimits = PLAN_MESA_LIMITS[plan as keyof typeof PLAN_MESA_LIMITS] ?? PLAN_MESA_LIMITS.basico;
    if (!mesaLimits.mesaActions) {
      return new Response(JSON.stringify({ error: "Tu plan no permite escribir desde Mesa" }), { status: 403 });
    }

    const limits = getUserPlanLimits(user);
    if (limits.sends === 0 || !limits.sendsUnlocked) {
      return new Response(JSON.stringify({ error: "Tu plan no incluye envío de emails. Agrega el add-on de envíos." }), { status: 403 });
    }
    if (!domain.verified) {
      return new Response(JSON.stringify({ error: "Dominio no verificado" }), { status: 400 });
    }

    // El remitente tiene que ser un alias real y habilitado: si no, es spoofing dentro
    // del propio dominio, y además la respuesta del contacto no se reenviaría a ningún
    // buzón (caería en la Bandeja pero con "No matching alias").
    const aliases = await listAliases(domain.id);
    const local = String(fromAlias).split("@")[0].toLowerCase();
    const match = aliases.find((a) => a.alias.toLowerCase() === local && a.enabled && a.alias !== "*");
    if (!match) {
      return new Response(JSON.stringify({ error: "El remitente debe ser un alias activo de tu dominio" }), { status: 400 });
    }

    const recipient = normalizeAddress(String(to));
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(recipient)) {
      return new Response(JSON.stringify({ error: "Destinatario inválido" }), { status: 400 });
    }
    if (await isSuppressed(domain.id, recipient)) {
      return new Response(JSON.stringify({ error: "Destinatario en lista de supresión (bounce/complaint previo)" }), { status: 422 });
    }

    // Reservar la cuota antes de enviar. Chequear y luego incrementar deja pasar dos
    // peticiones simultáneas por el mismo hueco.
    const reserved = await incrementSendCount(domain.id);
    if (reserved > limits.sends) {
      decrementSendCount(domain.id);
      return new Response(JSON.stringify({ error: `Límite diario de envíos alcanzado (${limits.sends})` }), { status: 429 });
    }

    const fromAddress = `${match.alias}@${domain.domain}`;
    let messageId: string;
    // Fuera del try: hace falta después para borrar de S3 las imágenes ya enviadas y
    // para guardar en la Bandeja el HTML tal como salió.
    let withImages: { html?: string; inlineImages?: InlineImage[] } = {};
    let sentFileKeys: string[] = [];
    try {
      // Sin inReplyTo/references: es el primer mensaje del hilo. El Message-ID lo genera
      // sendFromDomain y se guarda en threadReferences para que la respuesta del contacto
      // reenganche aquí. Ojo: SES puede reescribir ese header en SendRawEmail — si lo
      // hace, el hilo no reengancha. El log "Inbound created new conversation" con
      // unmatchedRefs lo delata en producción.
      withImages = await attachInlineImages(rendered.html);
      const files = await collectAttachments(attachRefs);
      sentFileKeys = files.keys;
      messageId = await sendFromDomain(fromAddress, recipient, String(subject), rendered.text, {
        html: withImages.html,
        inlineImages: withImages.inlineImages,
        attachments: files.attachments.length ? files.attachments : undefined,
        cc: cc.length ? cc : undefined,
        bcc: bcc.length ? bcc : undefined,
        configSet: getConfigSetName(domain.domain),
      });
    } catch (err) {
      decrementSendCount(domain.id);
      log("error", "ses", "Compose send failed", { error: String(err), domainId: domain.id });
      return new Response(JSON.stringify({ error: "Error enviando email" }), { status: 500 });
    }

    // El correo ya salió con imágenes y adjuntos dentro: las copias en S3 son desecho.
    await discardSentImages(withImages.inlineImages);
    await discardSentFiles(sentFileKeys);

    try {
      // Convención invertida a propósito, igual que en las conversaciones entrantes:
      // `from` es el contacto externo y `to` nuestro alias. La lista, el filtro y el
      // reply posterior (que deriva el remitente de conv.to) dependen de esto.
      const conv = await createConversation({
        domainId: domain.id,
        from: recipient,
        to: fromAddress,
        subject: String(subject),
        status: "open",
        priority: "normal",
        lastMessageAt: new Date().toISOString(),
        messageCount: 1,
        tags: [],
        threadReferences: [messageId],
      });

      await addMessage({
        conversationId: conv.id,
        from: fromAddress,
        body: rendered.text,
        // El HTML tal como salió, con `cid:` y no con la URL: esa URL ya no existe
        // —la imagen se borró de S3 tras enviar— y guardarla sería registrar algo
        // que nadie podrá volver a abrir.
        html: withImages.html ?? rendered.html ?? "",
        direction: "outbound",
        createdAt: new Date().toISOString(),
        messageId,
      });

      // El messageId queda en el log a propósito: es la referencia que debería aparecer
      // en el In-Reply-To de la respuesta. Cruzar este log con el de
      // "Inbound threaded into existing conversation" confirma (o desmiente) el threading.
      log("info", "mesa", "Compose sent", {
        conversationId: conv.id,
        domainId: domain.id,
        from: fromAddress,
        to: recipient,
        messageId,
        sendsUsed: reserved,
        sendsLimit: limits.sends,
      });

      return new Response(JSON.stringify({ ok: true, conversationId: conv.id, messageId }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    } catch (err) {
      // El correo ya salió. Es mejor avisar que quedó sin registrar que fingir un
      // fallo y que el usuario lo mande otra vez.
      log("error", "mesa", "Compose sent but not persisted", { error: String(err), domainId: domain.id, messageId });
      return new Response(JSON.stringify({ ok: true, warning: "El correo se envió pero no se pudo guardar en la Bandeja", messageId }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
  }, {
    body: t.Object({
      domainId: t.String(),
      to: t.String(),
      subject: t.String(),
      fromAlias: t.String(),
      body: t.Optional(t.String()),
      html: t.Optional(t.String()),
      markdown: t.Optional(t.String()),
      cc: t.Optional(t.Array(t.String())),
      bcc: t.Optional(t.Array(t.String())),
      attachments: t.Optional(t.Array(t.Object({
        key: t.String(),
        filename: t.String(),
        contentType: t.Optional(t.String()),
      }))),
    }),
    detail: { tags: ["Bandeja"], summary: "Compose a new conversation and send the first email", security: [{ cookieAuth: [] }] },
  })

  // Vista previa: devuelve el mismo HTML que recibiría el destinatario, sin enviar
  // nada ni consumir cuota. Sirve para la demo del compositor y para que el usuario
  // vea el resultado antes de mandar.
  .post("/api/email-preview", async ({ request, body: previewBody }) => {
    // En desarrollo se deja abierto para poder probar el compositor sin montar una
    // cuenta con dominio verificado. En producción exige sesión como todo lo demás.
    const isDev = process.env.NODE_ENV !== "production";
    if (!isDev) {
      const auth = await getAuthUser(request);
      if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    }
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 60, 60_000);
    if (limited) return limited;

    const rendered = resolveEmailBody({
      markdown: previewBody.markdown,
      html: previewBody.html,
      body: previewBody.body,
    });
    return new Response(JSON.stringify({ html: rendered.html ?? "", text: rendered.text }), {
      headers: { "content-type": "application/json" },
    });
  }, {
    body: t.Object({
      markdown: t.Optional(t.String()),
      html: t.Optional(t.String()),
      body: t.Optional(t.String()),
    }),
    detail: { tags: ["Send"], summary: "Render an email preview without sending it", security: [{ cookieAuth: [] }] },
  })

  // --- Imágenes para correos salientes ---
  //
  // Un cliente de correo trae las imágenes de forma ANÓNIMA: no manda nuestra
  // cookie. Por eso el par es subida autenticada + servido público, y no una URL
  // firmada ni un bucket abierto (el bucket es privado y debe seguir así).
  .post("/api/domains/:id/images", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 20, 60_000);
    if (limited) return limited;

    const access = await checkDomainAccess(auth.email, params.id, "write");
    if (!access) return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });

    const form = await request.formData().catch(() => null);
    const file = form?.get("file");
    if (!(file instanceof File)) {
      return new Response(JSON.stringify({ error: "Falta el archivo" }), { status: 400 });
    }

    // Lista blanca de tipos. Sin SVG: es un documento que puede traer script, y se
    // serviría desde nuestro origen.
    const ext = ALLOWED_IMAGE_TYPES[file.type];
    if (!ext) {
      return new Response(JSON.stringify({ error: "Formato no permitido. Usa PNG, JPG, GIF o WebP" }), { status: 415 });
    }
    // 2 MB y no 5: en la Bandeja la imagen viaja DENTRO del correo, base64 la infla
    // ~33% y SendRawEmail topa el mensaje en 10 MB. Con 5 MB un correo con dos fotos
    // ya no salía.
    if (file.size > 2 * 1024 * 1024) {
      return new Response(JSON.stringify({ error: "La imagen no puede pesar más de 2 MB" }), { status: 413 });
    }

    // El nombre es un UUID y no el del archivo: es la única credencial de la ruta
    // pública, así que no debe ser adivinable ni permitir escribir fuera del prefijo.
    const key = `${crypto.randomUUID()}.${ext}`;
    try {
      await putEmailImageToS3(key, new Uint8Array(await file.arrayBuffer()), file.type);
    } catch (err) {
      log("error", "ses", "Email image upload failed", { error: String(err), domainId: access.domain.id });
      return new Response(JSON.stringify({ error: "No se pudo subir la imagen" }), { status: 500 });
    }

    const appUrl = process.env.APP_URL ?? "https://www.mailmask.studio";
    return new Response(JSON.stringify({ ok: true, url: `${appUrl}/api/img/${key}` }), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Send"], summary: "Upload an image to embed in outgoing email", security: [{ cookieAuth: [] }] },
  })

  // Adjuntos. A diferencia de las imágenes NO se sirven por HTTP: viajan dentro del
  // correo y se borran de S3 al enviarlo. Aquí sólo se guardan mientras se redacta.
  .post("/api/domains/:id/attachments", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 20, 60_000);
    if (limited) return limited;

    const access = await checkDomainAccess(auth.email, params.id, "write");
    if (!access) return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });

    const form = await request.formData().catch(() => null);
    const file = form?.get("file");
    if (!(file instanceof File)) {
      return new Response(JSON.stringify({ error: "Falta el archivo" }), { status: 400 });
    }
    // Los saltos de línea y comillas romperían el header Content-Disposition.
    const filename = file.name.replace(/[\r\n"\\\x00-\x1f]/g, "").slice(0, 200) || "archivo";
    if (BLOCKED_ATTACHMENT_EXT.test(filename)) {
      return new Response(JSON.stringify({ error: "Ese tipo de archivo no se puede enviar por correo" }), { status: 415 });
    }
    if (file.size > MAX_ATTACHMENT_BYTES) {
      return new Response(JSON.stringify({ error: "El archivo no puede pesar más de 5 MB" }), { status: 413 });
    }

    const key = crypto.randomUUID();
    try {
      // El navegador manda el Content-Type y es texto libre. Se acota a la forma
      // "tipo/subtipo": así no puede colar parámetros en la cabecera MIME del correo.
      const tipo = /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/i.test(file.type) ? file.type : "application/octet-stream";
      await putEmailFileToS3(key, new Uint8Array(await file.arrayBuffer()), tipo);
    } catch (err) {
      log("error", "ses", "Attachment upload failed", { error: String(err), domainId: access.domain.id });
      return new Response(JSON.stringify({ error: "No se pudo subir el archivo" }), { status: 500 });
    }

    return new Response(JSON.stringify({ ok: true, key, filename, size: file.size }), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Send"], summary: "Upload a file to attach to an outgoing email", security: [{ cookieAuth: [] }] },
  })

  // --- Firma del dominio ---
  .put("/api/domains/:id/signature", async ({ request, params, body: sigBody }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    const access = await checkDomainAccess(auth.email, params.id, "write");
    if (!access) return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });

    const firma = (sigBody.signature ?? "").trim();
    if (firma.length > 2000) {
      return new Response(JSON.stringify({ error: "La firma es demasiado larga" }), { status: 400 });
    }
    // Cadena vacía borra la firma; por eso se guarda null y no "".
    const updated = updateDomain(access.domain.id, { signature: firma || null });
    return new Response(JSON.stringify({ ok: true, signature: updated?.signature ?? null }), {
      headers: { "content-type": "application/json" },
    });
  }, {
    body: t.Object({ signature: t.Optional(t.String()) }),
    detail: { tags: ["Bandeja"], summary: "Set the signature appended to outgoing email", security: [{ cookieAuth: [] }] },
  })

  // --- Respuestas guardadas ---
  .get("/api/domains/:id/canned", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    const access = await checkDomainAccess(auth.email, params.id, "read");
    if (!access) return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    return new Response(JSON.stringify(listCannedResponses(access.domain.id)), {
      headers: { "content-type": "application/json" },
    });
  }, { detail: { tags: ["Bandeja"], summary: "List saved replies", security: [{ cookieAuth: [] }] } })

  .post("/api/domains/:id/canned", async ({ request, params, body: cannedBody }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    const access = await checkDomainAccess(auth.email, params.id, "write");
    if (!access) return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });

    const title = (cannedBody.title ?? "").trim();
    const cuerpo = (cannedBody.body ?? "").trim();
    if (!title || !cuerpo) {
      return new Response(JSON.stringify({ error: "Título y contenido requeridos" }), { status: 400 });
    }
    if (listCannedResponses(access.domain.id).length >= 50) {
      return new Response(JSON.stringify({ error: "Máximo 50 respuestas guardadas por dominio" }), { status: 429 });
    }
    return new Response(JSON.stringify(createCannedResponse(access.domain.id, title.slice(0, 120), cuerpo.slice(0, 10_000))), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  }, {
    body: t.Object({ title: t.Optional(t.String()), body: t.Optional(t.String()) }),
    detail: { tags: ["Bandeja"], summary: "Create a saved reply", security: [{ cookieAuth: [] }] },
  })

  .delete("/api/domains/:id/canned/:cannedId", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    const access = await checkDomainAccess(auth.email, params.id, "write");
    if (!access) return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    const ok = deleteCannedResponse(params.cannedId, access.domain.id);
    return new Response(JSON.stringify({ ok }), { status: ok ? 200 : 404, headers: { "content-type": "application/json" } });
  }, { detail: { tags: ["Bandeja"], summary: "Delete a saved reply", security: [{ cookieAuth: [] }] } })

  // Público a propósito: lo abre el cliente de correo del destinatario, que no
  // tiene sesión. El UUID del nombre es la credencial, y el contenido ya es
  // público por definición: va dentro de un correo enviado.
  .get("/api/img/:key", async ({ params }) => {
    // El key sólo puede ser lo que generamos nosotros. Sin esto, un `..` leería
    // otros objetos del bucket, donde vive el correo entrante.
    if (!/^[0-9a-f-]{36}\.(png|jpg|gif|webp)$/i.test(params.key)) {
      return new Response("No encontrado", { status: 404 });
    }
    const image = await getEmailImageFromS3(params.key);
    if (!image) return new Response("No encontrado", { status: 404 });

    // El Content-Type se deriva de la extensión que nosotros pusimos, no de lo que
    // diga el objeto: así no hay forma de que un tipo inesperado se sirva desde
    // nuestro origen.
    const ext = params.key.split(".").pop()!.toLowerCase();
    const type = ext === "png" ? "image/png"
      : ext === "gif" ? "image/gif"
      : ext === "webp" ? "image/webp"
      : "image/jpeg";

    // Buffer y no Uint8Array: es lo que el tipo de Response acepta sin ceder tipos.
    return new Response(Buffer.from(image.body), {
      headers: {
        "content-type": type,
        "content-disposition": "inline",
        "x-content-type-options": "nosniff",
        "cache-control": "public, max-age=31536000, immutable",
      },
    });
  }, {
    detail: { tags: ["Send"], summary: "Serve an image embedded in an outgoing email" },
  })

  .post("/api/bandeja/conversations/:id/reply", async ({ request, params, body: replyBody }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 20, 60_000);
    if (limited) return limited;

    const { domainId, body: replyBodyText, html, markdown } = replyBody;
    if (!domainId || (!replyBodyText && !html && !markdown)) {
      return new Response(JSON.stringify({ error: "domainId y body/html/markdown requeridos" }), { status: 400 });
    }
    if (html && Buffer.byteLength(html, "utf8") > MAX_EMAIL_HTML_BYTES) {
      return new Response(JSON.stringify({ error: "El HTML excede 100 KB; Gmail recorta el mensaje" }), { status: 413 });
    }
    const cc = parseCopyList((replyBody as Record<string, unknown>).cc);
    const bcc = parseCopyList((replyBody as Record<string, unknown>).bcc);
    const attachRefs = (replyBody as Record<string, unknown>).attachments as AttachmentRef[] | undefined;
    // El cliente decide si cita: al responder de un vistazo la cita estorba, y en un
    // hilo largo es lo que da contexto.
    const quote = (replyBody as Record<string, unknown>).quote !== false;

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
    if (conv.deletedAt) return new Response(JSON.stringify({ error: "Conversación eliminada" }), { status: 400 });

    if (!domain.verified) {
      return new Response(JSON.stringify({ error: "Dominio no verificado" }), { status: 400 });
    }

    // conv.from puede venir con display name si la conversación se reconstruyó desde S3.
    const recipient = normalizeAddress(conv.from);
    if (await isSuppressed(domain.id, recipient)) {
      return new Response(JSON.stringify({ error: "Destinatario en lista de supresión (bounce/complaint previo)" }), { status: 422 });
    }

    // Responder NO consume la cuota del add-on: la Bandeja se vende incluida en todos
    // los planes. El tope de aquí es contra abuso (bucles, scripts), no de producto,
    // y el volumen ya está acotado río arriba por forwardPerHour.
    const replyLimit = checkRateLimit(`reply:${domain.id}`, 200, 3600_000);
    if (!replyLimit.allowed) {
      return new Response(JSON.stringify({ error: "Demasiadas respuestas por hora" }), { status: 429 });
    }

    const fromAddress = `${conv.to.split("@")[0]}@${domain.domain}`;
    const lastRef = conv.threadReferences[conv.threadReferences.length - 1];

    // Cita del último mensaje recibido y firma, en ese orden: la firma va pegada a lo
    // que se escribe, no debajo del texto citado.
    let cuerpoMarkdown = markdown;
    if (cuerpoMarkdown) {
      cuerpoMarkdown = appendSignature(cuerpoMarkdown, domain.signature);
      if (quote) {
        const previos = listMessages(conv.id).filter((m) => m.direction === "inbound");
        const ultimo = previos[previos.length - 1];
        if (ultimo) {
          cuerpoMarkdown = quotePrevious(cuerpoMarkdown, {
            from: ultimo.from,
            date: ultimo.createdAt,
            text: ultimo.body ?? "",
          });
        }
      }
    }
    const rendered = resolveEmailBody({ markdown: cuerpoMarkdown, html, body: replyBodyText });

    let sentFileKeys: string[] = [];
    try {
      const withImages = await attachInlineImages(rendered.html);
      const files = await collectAttachments(attachRefs);
      sentFileKeys = files.keys;
      const messageId = await sendFromDomain(fromAddress, recipient, `Re: ${conv.subject}`, rendered.text, {
        html: withImages.html,
        inlineImages: withImages.inlineImages,
        attachments: files.attachments.length ? files.attachments : undefined,
        cc: cc.length ? cc : undefined,
        bcc: bcc.length ? bcc : undefined,
        configSet: getConfigSetName(domain.domain),
        inReplyTo: lastRef,
        references: conv.threadReferences.join(" "),
      });

      // Ya salió con imágenes y adjuntos dentro: las copias en S3 sobran.
      await discardSentImages(withImages.inlineImages);
      await discardSentFiles(sentFileKeys);

      await addMessage({
        conversationId: conv.id,
        from: fromAddress,
        body: rendered.text,
        // El HTML tal como salió, con `cid:`: la URL de S3 ya no resuelve.
        html: withImages.html ?? rendered.html ?? "",
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
  }, {
    body: t.Object({
      domainId: t.String(),
      body: t.Optional(t.String()),
      html: t.Optional(t.String()),
      markdown: t.Optional(t.String()),
      cc: t.Optional(t.Array(t.String())),
      bcc: t.Optional(t.Array(t.String())),
      quote: t.Optional(t.Boolean()),
      attachments: t.Optional(t.Array(t.Object({
        key: t.String(),
        filename: t.String(),
        contentType: t.Optional(t.String()),
      }))),
    }),
    detail: { tags: ["Bandeja"], summary: "Reply to a conversation", security: [{ cookieAuth: [] }] },
  })

  .post("/api/bandeja/conversations/:id/assign", async ({ request, params, body: assignBody }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const { domainId, assignedTo } = assignBody;
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

    const convToAssign = await getConversation(domainId, params.id);
    if (!convToAssign) return new Response(JSON.stringify({ error: "Conversación no encontrada" }), { status: 404 });
    if (convToAssign.deletedAt) return new Response(JSON.stringify({ error: "Conversación eliminada" }), { status: 400 });

    const updated = await updateConversation(domainId, params.id, { assignedTo: assignedTo ?? undefined });
    if (!updated) return new Response(JSON.stringify({ error: "Conversación no encontrada" }), { status: 404 });

    return new Response(JSON.stringify(updated), {
      headers: { "content-type": "application/json" },
    });
  }, {
    body: t.Object({
      domainId: t.String(),
      assignedTo: t.Optional(t.String()),
    }),
    detail: { tags: ["Bandeja"], summary: "Assign a conversation", security: [{ cookieAuth: [] }] },
  })

  .post("/api/bandeja/conversations/:id/note", async ({ request, params, body: noteBody }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const { domainId, body: noteBodyText } = noteBody;
    if (!domainId || !noteBodyText) return new Response(JSON.stringify({ error: "domainId y body requeridos" }), { status: 400 });

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
    if (conv.deletedAt) return new Response(JSON.stringify({ error: "Conversación eliminada" }), { status: 400 });

    const note = await addNote({
      conversationId: conv.id,
      author: auth.email,
      body: noteBodyText,
      createdAt: new Date().toISOString(),
    });

    return new Response(JSON.stringify(note), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  }, {
    body: t.Object({
      domainId: t.String(),
      body: t.String(),
    }),
    detail: { tags: ["Bandeja"], summary: "Add a note to a conversation", security: [{ cookieAuth: [] }] },
  })

  .patch("/api/bandeja/conversations/:id", async ({ request, params, body: patchInput }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const { domainId, status: newStatus, tags, priority } = patchInput;
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

    const convToPatch = await getConversation(domainId, params.id);
    if (!convToPatch) return new Response(JSON.stringify({ error: "Conversación no encontrada" }), { status: 404 });
    if (convToPatch.deletedAt) return new Response(JSON.stringify({ error: "Conversación eliminada" }), { status: 400 });

    const updates: Record<string, unknown> = {};
    if (newStatus && ["open", "snoozed", "closed"].includes(newStatus)) updates.status = newStatus;
    if (tags && Array.isArray(tags)) updates.tags = tags;
    if (priority && ["normal", "urgent"].includes(priority)) updates.priority = priority;

    const updated = await updateConversation(domainId, params.id, updates);
    if (!updated) return new Response(JSON.stringify({ error: "Conversación no encontrada" }), { status: 404 });

    return new Response(JSON.stringify(updated), {
      headers: { "content-type": "application/json" },
    });
  }, {
    body: t.Object({
      domainId: t.String(),
      status: t.Optional(t.String()),
      tags: t.Optional(t.Array(t.String())),
      priority: t.Optional(t.String()),
    }),
    detail: { tags: ["Bandeja"], summary: "Update conversation status/tags/priority", security: [{ cookieAuth: [] }] },
  })

  .delete("/api/bandeja/conversations/:id", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const url = new URL(request.url);
    const domainId = url.searchParams.get("domainId");
    if (!domainId) return new Response(JSON.stringify({ error: "domainId requerido" }), { status: 400 });

    const domain = await getDomain(domainId);
    if (!domain) return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });

    const user = (await getUser(auth.email))!;
    const plan = user.subscription?.plan ?? "basico";
    const mesaLimits = PLAN_MESA_LIMITS[plan as keyof typeof PLAN_MESA_LIMITS] ?? PLAN_MESA_LIMITS.basico;
    if (!mesaLimits.mesaActions) {
      return new Response(JSON.stringify({ error: "Tu plan no permite eliminar conversaciones" }), { status: 403 });
    }

    const isOwner = domain.ownerEmail === auth.email;
    const agent = !isOwner ? await getAgentByEmail(domainId, auth.email) : null;
    if (!isOwner && !agent) {
      return new Response(JSON.stringify({ error: "Sin acceso" }), { status: 403 });
    }

    const deleted = await softDeleteConversation(domainId, params.id);
    if (!deleted) return new Response(JSON.stringify({ error: "Conversación no encontrada" }), { status: 404 });

    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Bandeja"], summary: "Soft-delete a conversation", security: [{ cookieAuth: [] }] },
  })

  .post("/api/bandeja/conversations/:id/restore", async ({ request, params, body: restoreBody }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const { domainId } = restoreBody;
    if (!domainId) return new Response(JSON.stringify({ error: "domainId requerido" }), { status: 400 });

    const domain = await getDomain(domainId);
    if (!domain) return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });

    const user = (await getUser(auth.email))!;
    const plan = user.subscription?.plan ?? "basico";
    const mesaLimits = PLAN_MESA_LIMITS[plan as keyof typeof PLAN_MESA_LIMITS] ?? PLAN_MESA_LIMITS.basico;
    if (!mesaLimits.mesaActions) {
      return new Response(JSON.stringify({ error: "Tu plan no permite restaurar conversaciones" }), { status: 403 });
    }

    const isOwner = domain.ownerEmail === auth.email;
    const agent = !isOwner ? await getAgentByEmail(domainId, auth.email) : null;
    if (!isOwner && !agent) {
      return new Response(JSON.stringify({ error: "Sin acceso" }), { status: 403 });
    }

    const restored = await restoreConversation(domainId, params.id);
    if (!restored) return new Response(JSON.stringify({ error: "Conversación no encontrada" }), { status: 404 });

    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  }, {
    body: t.Object({
      domainId: t.String(),
    }),
    detail: { tags: ["Bandeja"], summary: "Restore a soft-deleted conversation", security: [{ cookieAuth: [] }] },
  })

  // --- Agents ---

  .post("/api/domains/:id/agents/invite", async ({ request, params, body: inviteBody }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 10, 60_000);
    if (limited) return limited;

    const access = await checkDomainAccess(auth.email, params.id, "manage_members");
    if (!access) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }
    const domain = access.domain;

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

    const { email, name, role = "agent" } = inviteBody;
    if (!email || !name) return new Response(JSON.stringify({ error: "email y name requeridos" }), { status: 400 });
    if (!["admin", "agent"].includes(role)) return new Response(JSON.stringify({ error: "role inválido" }), { status: 400 });

    const existing = await getAgentByEmail(domain.id, email);
    if (existing) return new Response(JSON.stringify({ error: "Este email ya es agente de este dominio" }), { status: 409 });

    const token = await createAgentInvite(domain.id, email, name, role as "agent" | "admin");
    const inviteUrl = `${getMainDomainUrl()}/api/agents/accept?token=${token}`;

    try {
      await sendTemplate(email, mesaInvite({
        inviterEmail: auth.email, domain: domain.domain, role, name, acceptUrl: inviteUrl,
      }));
    } catch (err) {
      log("error", "ses", "Failed to send agent invite", { error: String(err) });
    }

    return new Response(JSON.stringify({ ok: true, inviteUrl }), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  }, {
    body: t.Object({
      email: t.String(),
      name: t.String(),
      role: t.Optional(t.String()),
    }),
    detail: { tags: ["Agents"], summary: "Invite an agent to a domain", security: [{ cookieAuth: [] }] },
  })

  .get("/api/agents/accept", async ({ request }) => {
    const url = new URL(request.url);
    const token = url.searchParams.get("token");
    if (!token) return new Response("Token inválido", { status: 400 });

    const invite = await getAgentInvite(token);
    if (!invite) return new Response("Token inválido o expirado", { status: 400 });

    const existingUser = await getUser(invite.email);
    if (!existingUser) {
      const { hashPassword: hp } = await import("./auth.js");
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
      headers: { location: "/bandeja?welcome=1" },
    });
  }, {
    detail: { tags: ["Agents"], summary: "Accept an agent invitation via token" },
  })

  .get("/api/domains/:id/agents", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const access = await checkDomainAccess(auth.email, params.id, "manage_members");
    if (!access) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }
    const domain = access.domain;

    const agents = await listAgents(domain.id);
    return new Response(JSON.stringify(agents), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Agents"], summary: "List agents for a domain", security: [{ cookieAuth: [] }] },
  })

  .delete("/api/domains/:id/agents/:agentId", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const access = await checkDomainAccess(auth.email, params.id, "manage_members");
    if (!access) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }
    const domain = access.domain;

    const deleted = await deleteAgent(domain.id, params.agentId);
    if (!deleted) return new Response(JSON.stringify({ error: "Agente no encontrado" }), { status: 404 });

    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["Agents"], summary: "Remove an agent from a domain", security: [{ cookieAuth: [] }] },
  })

  // --- SMTP Credentials ---

  .post("/api/domains/:id/smtp-credentials", async ({ request, params, body: smtpBody }) => {
    const user = await getAuthUser(request);
    if (!user) return new Response(JSON.stringify({ error: "No autorizado" }), { status: 401 });
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 5, 60_000);
    if (limited) return limited;

    const access = await checkDomainAccess(user.email, params.id, "admin");
    if (!access) return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });

    const owner = await getUser(access.domain.ownerEmail);
    if (!owner) return new Response(JSON.stringify({ error: "Cuenta no encontrada" }), { status: 404 });
    const limits = getUserPlanLimits(owner);
    if (!limits.smtpRelay) {
      return new Response(JSON.stringify({ error: "SMTP relay no disponible en tu plan. Actualiza a Freelancer o Developer." }), { status: 403 });
    }

    const label = (smtpBody.label ?? "").trim();
    if (!label || label.length > 100) {
      return new Response(JSON.stringify({ error: "Label requerido (máx 100 caracteres)" }), { status: 400 });
    }

    // Create IAM user with restricted SES policy for this domain
    const iamResult = await createSmtpIamCredential(access.domain.domain);

    const credential = createSmtpCredential(params.id, label, iamResult.iamUsername, iamResult.accessKeyId);

    const smtpServer = `email-smtp.${AWS_REGION}.amazonaws.com`;

    return new Response(JSON.stringify({
      id: credential.id,
      label: credential.label,
      server: smtpServer,
      port: 587,
      encryption: "STARTTLS",
      username: iamResult.accessKeyId,
      password: iamResult.smtpPassword, // Only shown once
      createdAt: credential.createdAt,
    }), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  }, {
    body: t.Object({
      label: t.String(),
    }),
    detail: { tags: ["SMTP", "SDK"], summary: "Create SMTP credentials for a domain", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  .get("/api/domains/:id/smtp-credentials", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user) return new Response(JSON.stringify({ error: "No autorizado" }), { status: 401 });

    const access = await checkDomainAccess(user.email, params.id, "read");
    if (!access) return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });

    const credentials = listSmtpCredentials(params.id);
    return new Response(JSON.stringify(credentials), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["SMTP", "SDK"], summary: "List SMTP credentials for a domain", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  .delete("/api/domains/:id/smtp-credentials/:credId", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user) return new Response(JSON.stringify({ error: "No autorizado" }), { status: 401 });

    const access = await checkDomainAccess(user.email, params.id, "admin");
    if (!access) return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });

    const revoked = revokeSmtpCredential(params.id, params.credId);
    if (!revoked) return new Response(JSON.stringify({ error: "Credencial no encontrada" }), { status: 404 });

    // Clean up IAM user, policy and access key
    await revokeSmtpIamCredential(revoked.iamUsername, revoked.accessKeyId);

    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  }, {
    detail: { tags: ["SMTP", "SDK"], summary: "Revoke an SMTP credential", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  // --- SES bounce/complaint events ---

  .post("/api/webhooks/ses-events", async ({ request }) => {
    const body = await request.json();

    // Todo mensaje —incluida la confirmación de suscripción— va firmado. Antes
    // este webhook no verificaba nada: cualquiera podía inventar un rebote y
    // meter a un destinatario ajeno en la lista de supresión.
    if (!body.Type || !body.Signature || !body.SigningCertURL) {
      return new Response(JSON.stringify({ error: "Invalid SNS message" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    }
    const valid = await verifySnsSignature(body);
    if (!valid) {
      log("warn", "server", "SES events: invalid SNS signature");
      return new Response(JSON.stringify({ error: "Invalid signature" }), {
        status: 403,
        headers: { "content-type": "application/json" },
      });
    }

    if (body.Type === "SubscriptionConfirmation" && body.SubscribeURL) {
      const parsed = new URL(body.SubscribeURL);
      if (parsed.hostname.endsWith(".amazonaws.com") && parsed.protocol === "https:") {
        await fetch(body.SubscribeURL);
        log("info", "ses", "SNS subscription confirmed", { endpoint: request.url });
      }
      return new Response("OK", { status: 200 });
    }

    if (body.Type !== "Notification") return new Response("OK", { status: 200 });

    try {
      const message = JSON.parse(body.Message);
      await registrarEventoSes(message);
    } catch (err) {
      log("error", "ses", "SES event processing error", { error: String(err) });
    }

    return new Response("OK", { status: 200 });
  }, {
    detail: { tags: ["Webhooks"], summary: "SES bounce/complaint events via SNS", hide: true },
  })

  .post("/api/webhooks/ses-inbound", async ({ request }) => {
    const body = await request.json();

    // Handle SNS subscription confirmation
    if (body.Type === "SubscriptionConfirmation" && body.SubscribeURL) {
      const parsed = new URL(body.SubscribeURL);
      if (parsed.hostname.endsWith(".amazonaws.com") && parsed.protocol === "https:") {
        await fetch(body.SubscribeURL);
        log("info", "ses", "SNS subscription confirmed", { endpoint: request.url });
      }
      return new Response("OK", { status: 200 });
    }

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
  }, {
    detail: { tags: ["Webhooks"], summary: "SES inbound email via SNS", hide: true },
  })

  // --- Admin: backups ---

  .get("/api/admin/backups", async ({ request }) => {
    const user = await getAuthUser(request);
    if (!user || !isAdmin(user.email))
      return new Response(JSON.stringify({ error: "Acceso denegado" }), { status: 403, headers: { "content-type": "application/json" } });

    try {
      const backups = await listBackups();
      return new Response(JSON.stringify(backups), { headers: { "content-type": "application/json" } });
    } catch (err) {
      log("error", "admin", "Failed to list backups", { error: String(err) });
      return new Response(JSON.stringify([]), { headers: { "content-type": "application/json" } });
    }
  }, {
    detail: { tags: ["Admin"], summary: "List backups", security: [{ cookieAuth: [] }] },
  })

  .get("/api/admin/backups/:key", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user || !isAdmin(user.email))
      return new Response(JSON.stringify({ error: "Acceso denegado" }), { status: 403, headers: { "content-type": "application/json" } });

    try {
      // Database backups are gzipped binaries; decoding them as UTF-8 (as the legacy
      // JSON path does) silently corrupts the file and yields an unrestorable download.
      if (params.key.endsWith(DB_BACKUP_SUFFIX)) {
        const bytes = await getBackupBytesFromS3(params.key);
        return new Response(bytes, {
          headers: {
            "content-type": "application/gzip",
            "content-disposition": `attachment; filename="${params.key}"`,
          },
        });
      }
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
  }, {
    detail: { tags: ["Admin"], summary: "Download a backup by key", security: [{ cookieAuth: [] }] },
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
  }, {
    detail: { tags: ["Admin"], summary: "Delete a backup by key", security: [{ cookieAuth: [] }] },
  })

  .post("/api/admin/backups/trigger", async ({ request }) => {
    const user = await getAuthUser(request);
    if (!user || !isAdmin(user.email))
      return new Response(JSON.stringify({ error: "Acceso denegado" }), { status: 403, headers: { "content-type": "application/json" } });

    // A backup does a full VACUUM INTO plus a gzip of the whole database; letting the
    // button be pressed repeatedly burns I/O and churns S3 for no added safety.
    const limited = await rateLimitGuard(`backup:${user.email}`, 3, 300_000);
    if (limited) return limited;

    try {
      const result = await runDbBackup();
      log("info", "backup", "Manual backup triggered by admin", { email: user.email, key: result.key });
      return new Response(JSON.stringify({
        ok: true, key: result.key, users: result.users, tables: result.tables, gzipBytes: result.gzipBytes,
      }), { headers: { "content-type": "application/json" } });
    } catch (err) {
      log("error", "backup", "Manual backup failed", { error: String(err) });
      return new Response(JSON.stringify({ error: "Backup falló" }), { status: 500, headers: { "content-type": "application/json" } });
    }
  }, {
    detail: { tags: ["Admin"], summary: "Trigger a manual backup", security: [{ cookieAuth: [] }] },
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
        // Sin esto era imposible distinguir desde el admin a quien paga de quien tiene
        // el plan puesto a mano.
        mpSubscriptionId: u.subscription?.mpSubscriptionId ?? null,
        paying: !!u.subscription?.mpSubscriptionId,
      });
    }
    return new Response(JSON.stringify(result), { headers: { "content-type": "application/json" } });
  }, {
    detail: { tags: ["Admin"], summary: "List all users", security: [{ cookieAuth: [] }] },
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
      // Envíos de hoy por dominio: es lo que permite confirmar que un envío real se contó.
      domainsWithAliases.push({
        id: d.id,
        domain: d.domain,
        verified: d.verified,
        aliasCount,
        sendsToday: await getSendCount(d.id),
      });
    }

    const { passwordHash: _, ...safe } = target;
    return new Response(JSON.stringify({
      ...safe,
      domains: domainsWithAliases,
      limits: getUserPlanLimits(target),
      addons: listAddons(target.email),
    }), { headers: { "content-type": "application/json" } });
  }, {
    detail: { tags: ["Admin"], summary: "Get user details by email", security: [{ cookieAuth: [] }] },
  })

  .patch("/api/admin/users/:email", async ({ request, params, body: userPatch }) => {
    const auth = await getAuthUser(request);
    if (!auth || !isAdmin(auth.email))
      return new Response(JSON.stringify({ error: "Acceso denegado" }), { status: 403, headers: { "content-type": "application/json" } });

    const email = decodeURIComponent(params.email);
    const target = await getUser(email);
    if (!target)
      return new Response(JSON.stringify({ error: "Usuario no encontrado" }), { status: 404, headers: { "content-type": "application/json" } });

    const validPlans = ["basico", "freelancer", "developer", "pro", "agencia"];
    const validStatuses = ["active", "past_due", "cancelled", "none"];

    // Update subscription fields
    if (userPatch.plan !== undefined || userPatch.status !== undefined || userPatch.currentPeriodEnd !== undefined) {
      const sub = target.subscription ?? { plan: "basico", status: "none" as const };
      if (userPatch.plan !== undefined && validPlans.includes(userPatch.plan)) sub.plan = userPatch.plan as typeof sub.plan;
      if (userPatch.status !== undefined && validStatuses.includes(userPatch.status)) sub.status = userPatch.status as typeof sub.status;
      if (userPatch.currentPeriodEnd !== undefined) sub.currentPeriodEnd = userPatch.currentPeriodEnd || undefined;
      await updateUserSubscription(email, sub);
    }

    // Update emailVerified
    if (userPatch.emailVerified !== undefined) {
      db.update(usersTable).set({ emailVerified: !!userPatch.emailVerified }).where(eq(usersTable.email, email)).run();
    }

    log("info", "admin", "User updated by admin", { admin: auth.email, target: email, changes: userPatch });
    const updated = await getUser(email);
    const { passwordHash: _, ...safe } = updated!;
    return new Response(JSON.stringify(safe), { headers: { "content-type": "application/json" } });
  }, {
    body: t.Object({
      plan: t.Optional(t.String()),
      status: t.Optional(t.String()),
      currentPeriodEnd: t.Optional(t.String()),
      emailVerified: t.Optional(t.Boolean()),
    }),
    detail: { tags: ["Admin"], summary: "Update a user's subscription or verification status", security: [{ cookieAuth: [] }] },
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
  }, {
    detail: { tags: ["Admin"], summary: "Delete a user by email", security: [{ cookieAuth: [] }] },
  })

  // --- Admin: Coupons ---

  .get("/api/admin/coupons", async ({ request }) => {
    const auth = await getAuthUser(request);
    if (!auth || !isAdmin(auth.email))
      return new Response(JSON.stringify({ error: "Acceso denegado" }), { status: 403, headers: { "content-type": "application/json" } });

    const coupons = await listCoupons();
    return new Response(JSON.stringify(coupons), { headers: { "content-type": "application/json" } });
  }, {
    detail: { tags: ["Admin"], summary: "List all coupons", security: [{ cookieAuth: [] }] },
  })

  .post("/api/admin/coupons", async ({ request, body: couponBody }) => {
    const auth = await getAuthUser(request);
    if (!auth || !isAdmin(auth.email))
      return new Response(JSON.stringify({ error: "Acceso denegado" }), { status: 403, headers: { "content-type": "application/json" } });

    const body = couponBody;
    if (!body?.code || !body?.plan || !body?.fixedPrice || !body?.description) {
      return new Response(JSON.stringify({ error: "Campos requeridos: code, plan, fixedPrice, description" }), { status: 400, headers: { "content-type": "application/json" } });
    }

    const validPlans = ["basico", "freelancer", "developer", "pro", "agencia"];
    if (!validPlans.includes(body.plan)) {
      return new Response(JSON.stringify({ error: "Plan inválido" }), { status: 400, headers: { "content-type": "application/json" } });
    }
    if (Number(body.fixedPrice) < 100) {
      return new Response(JSON.stringify({ error: "Precio mínimo: 100 centavos ($1 MXN)" }), { status: 400, headers: { "content-type": "application/json" } });
    }

    try {
      const coupon = await createCoupon({
        code: String(body.code).toUpperCase().trim(),
        plan: body.plan,
        fixedPrice: Number(body.fixedPrice),
        description: String(body.description),
        singleUse: Boolean(body.singleUse),
        expiresAt: body.expiresAt || undefined,
      });
      log("info", "admin", "Coupon created", { admin: auth.email, code: coupon.code });
      return new Response(JSON.stringify(coupon), { status: 201, headers: { "content-type": "application/json" } });
    } catch (err: any) {
      if (String(err).includes("UNIQUE constraint failed") || String(err).includes("duplicate key")) {
        return new Response(JSON.stringify({ error: "Ya existe un cupón con ese código" }), { status: 409, headers: { "content-type": "application/json" } });
      }
      throw err;
    }
  }, {
    body: t.Object({
      code: t.String(),
      plan: t.String(),
      fixedPrice: t.Number(),
      description: t.String(),
      singleUse: t.Optional(t.Boolean()),
      expiresAt: t.Optional(t.String()),
    }),
    detail: { tags: ["Admin"], summary: "Create a coupon", security: [{ cookieAuth: [] }] },
  })

  .delete("/api/admin/coupons/:code", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth || !isAdmin(auth.email))
      return new Response(JSON.stringify({ error: "Acceso denegado" }), { status: 403, headers: { "content-type": "application/json" } });

    const code = decodeURIComponent(params.code).toUpperCase().trim();
    const deleted = await deleteCoupon(code);
    if (!deleted)
      return new Response(JSON.stringify({ error: "Cupón no encontrado" }), { status: 404, headers: { "content-type": "application/json" } });

    log("info", "admin", "Coupon deleted", { admin: auth.email, code });
    return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
  }, {
    detail: { tags: ["Admin"], summary: "Delete a coupon by code", security: [{ cookieAuth: [] }] },
  })

  // --- Domain Registration (Route 53) ---

  .get("/api/domains/search", async ({ request }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401, headers: { "content-type": "application/json" } });

    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 10, 60_000);
    if (limited) return limited;

    const url = new URL(request.url);
    const q = url.searchParams.get("q")?.toLowerCase().trim();
    if (!q || !q.includes(".")) {
      return new Response(JSON.stringify({ error: "Dominio inválido. Incluye la extensión (ej: miempresa.com)" }), { status: 400, headers: { "content-type": "application/json" } });
    }

    const tld = "." + q.split(".").slice(1).join(".");
    const pricing = TLD_PRICES[tld];
    if (!pricing) {
      return new Response(JSON.stringify({ error: `Extensión ${tld} no soportada. Extensiones disponibles: ${Object.keys(TLD_PRICES).join(", ")}` }), { status: 400, headers: { "content-type": "application/json" } });
    }

    try {
      const { checkAvailability } = await import("./route53.js");
      const result = await checkAvailability(q);
      return new Response(JSON.stringify({
        available: result.available,
        domain: result.domain,
        tld,
        price: pricing.userMxnCents,
        currency: "MXN",
      }), { headers: { "content-type": "application/json" } });
    } catch (err: any) {
      log("error", "route53", "Domain search failed", { domain: q, error: String(err) });
      const msg = err?.name === "UnsupportedTLD"
        ? `La extensión ${tld} no está disponible para registro`
        : "Error al buscar disponibilidad";
      return new Response(JSON.stringify({ error: msg }), { status: 400, headers: { "content-type": "application/json" } });
    }
  }, {
    detail: { tags: ["Domain Registration"], summary: "Search domain availability", security: [{ cookieAuth: [] }] },
  })

  .post("/api/domains/register", async ({ request, body: regBody }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401, headers: { "content-type": "application/json" } });

    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 5, 60_000);
    if (limited) return limited;

    const user = (await getUser(auth.email))!;
    const sub = user.subscription;
    if (!sub || sub.status !== "active") {
      return new Response(JSON.stringify({ error: "Necesitas un plan activo para registrar dominios" }), { status: 402, headers: { "content-type": "application/json" } });
    }

    // Este endpoint COBRA antes de registrar, así que el tope se valida aquí: sin esto un
    // Básico podía pagar por dominios que su plan no admite y habría que reembolsar.
    // Se cuentan también los registros en curso para que dos compras simultáneas no se
    // cuelen por el mismo hueco.
    const regLimits = getUserPlanLimits(user);
    const enCurso = getDomainRegistrationsByUser(auth.email)
      .filter((r: { status: string }) => ["pending_payment", "paid", "registering"].includes(r.status)).length;
    const yaTiene = await countUserDomains(auth.email);
    if (yaTiene + enCurso >= regLimits.domains) {
      return new Response(JSON.stringify({
        error: `Tu plan permite máximo ${regLimits.domains} dominio(s). Agrega el add-on de dominio extra o sube de plan antes de registrar uno nuevo.`,
      }), { status: 400, headers: { "content-type": "application/json" } });
    }

    const { domain } = regBody;
    if (!domain || typeof domain !== "string") {
      return new Response(JSON.stringify({ error: "Dominio requerido" }), { status: 400, headers: { "content-type": "application/json" } });
    }

    const d = domain.toLowerCase().trim();
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
    if (!domainRegex.test(d)) {
      return new Response(JSON.stringify({ error: "Formato de dominio inválido" }), { status: 400, headers: { "content-type": "application/json" } });
    }

    const tld = "." + d.split(".").slice(1).join(".");
    const pricing = TLD_PRICES[tld];
    if (!pricing) {
      return new Response(JSON.stringify({ error: `Extensión ${tld} no soportada` }), { status: 400, headers: { "content-type": "application/json" } });
    }

    // Check availability first
    try {
      const { checkAvailability } = await import("./route53.js");
      const avail = await checkAvailability(d);
      if (!avail.available) {
        return new Response(JSON.stringify({ error: "El dominio no está disponible" }), { status: 409, headers: { "content-type": "application/json" } });
      }
    } catch (err: any) {
      log("error", "route53", "Availability check failed during register", { domain: d, error: String(err) });
      return new Response(JSON.stringify({ error: "Error al verificar disponibilidad" }), { status: 500, headers: { "content-type": "application/json" } });
    }

    // Create registration record
    const registration = createDomainRegistration({
      domainName: d,
      ownerEmail: auth.email,
      tld,
      priceCents: pricing.userMxnCents,
      awsCostCents: pricing.awsUsdCents,
    });

    // Create MP Preference (one-time payment, NOT PreApproval subscription)
    const mpAccessToken = process.env.MP_ACCESS_TOKEN;
    if (!mpAccessToken) {
      return new Response(JSON.stringify({ error: "MercadoPago no configurado" }), { status: 500, headers: { "content-type": "application/json" } });
    }

    try {
      const { Preference } = await import("mercadopago");
      const preference = new Preference({ accessToken: mpAccessToken });
      const backUrl = getMainDomainUrl() + "/app";

      const result = await preference.create({ body: {
        items: [{
          id: registration.id,
          title: `Registro de dominio: ${d} (1 año)`,
          quantity: 1,
          unit_price: pricing.userMxnCents / 100,
          currency_id: "MXN",
        }],
        external_reference: `domain-reg:${registration.id}`,
        back_urls: {
          success: backUrl,
          failure: backUrl,
          pending: backUrl,
        },
        auto_return: "approved",
        notification_url: getMainDomainUrl() + "/api/webhooks/mercadopago-domain",
      }});

      // Store MP preference ID for tracking
      updateDomainRegistration(registration.id, { mpPaymentId: result.id ?? "" });

      return new Response(JSON.stringify({
        initPoint: result.init_point,
        registrationId: registration.id,
      }), { headers: { "content-type": "application/json" } });
    } catch (err: any) {
      log("error", "billing", "MP domain preference error", { domain: d, error: String(err) });
      return new Response(JSON.stringify({ error: "Error al crear pago en MercadoPago" }), { status: 500, headers: { "content-type": "application/json" } });
    }
  }, {
    body: t.Object({
      domain: t.String(),
    }),
    detail: { tags: ["Domain Registration"], summary: "Register a domain via Route 53 + MercadoPago", security: [{ cookieAuth: [] }] },
  })

  .post("/api/webhooks/mercadopago-domain", async ({ request }) => {
    // HMAC validation (same pattern as main webhook)
    const secret = process.env.MP_WEBHOOK_SECRET;
    if (!secret) {
      log("error", "webhook", "MP_WEBHOOK_SECRET not configured");
      return new Response("Server misconfigured", { status: 500 });
    }
    const xSignature = request.headers.get("x-signature") ?? "";
    const xRequestId = request.headers.get("x-request-id") ?? "";
    const url = new URL(request.url);
    const dataId = url.searchParams.get("data.id") ?? "";

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
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(manifest));
    const computed = Array.from(new Uint8Array(sig))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    if (computed !== v1) {
      log("warn", "webhook", "MP domain webhook: invalid signature");
      return new Response("Unauthorized", { status: 401 });
    }

    const body = await request.json();
    log("info", "webhook", "MP domain webhook received", { type: body.type, dataId: body.data?.id });

    // Handle payment notifications
    if (body.type === "payment" && body.data?.id) {
      try {
        const mpAccessToken = process.env.MP_ACCESS_TOKEN;
        if (!mpAccessToken) return new Response("Server misconfigured", { status: 500 });

        // Fetch payment details from MP
        const payRes = await fetch(`https://api.mercadopago.com/v1/payments/${body.data.id}`, {
          headers: { Authorization: `Bearer ${mpAccessToken}` },
          signal: AbortSignal.timeout(10_000),
        });
        const payment = await payRes.json();

        log("info", "webhook", "MP domain payment fetched", { status: payment.status, external_reference: payment.external_reference });

        if (payment.status === "approved" && payment.external_reference?.startsWith("domain-reg:")) {
          const regId = payment.external_reference.replace("domain-reg:", "");
          const reg = getDomainRegistration(regId);
          if (!reg) {
            log("warn", "webhook", "Domain registration not found", { regId });
            return new Response("OK", { status: 200 });
          }
          if (reg.status !== "pending_payment") {
            log("info", "webhook", "Domain registration already processed", { regId, status: reg.status });
            return new Response("OK", { status: 200 });
          }

          // Update to paid and start registration
          updateDomainRegistration(regId, { status: "paid", mpPaymentId: String(body.data.id) });

          // Entra al libro mayor igual que los demás: es un cargo real a una tarjeta
          // real, y dejarlo fuera haría que el historial mienta por omisión.
          recordOrder({
            userEmail: reg.ownerEmail,
            kind: "charge",
            subject: "domain_registration",
            subjectId: reg.id,
            subjectKey: reg.tld,
            description: `Registro de dominio ${reg.domainName}`,
            amountCents: reg.priceCents,
            listPriceCents: reg.priceCents,
            currency: payment.currency_id ?? "MXN",
            periodEnd: reg.expiresAt ?? null,
            mpPaymentId: String(body.data.id),
            mpStatus: payment.status,
            eventKey: `domreg:${regId}`,
            occurredAt: payment.date_approved ?? payment.date_created ?? undefined,
            raw: payment,
          });

          try {
            const { registerDomain } = await import("./route53.js");
            const operationId = await registerDomain(reg.domainName);
            updateDomainRegistration(regId, { status: "registering", route53OperationId: operationId });
            log("info", "webhook", "Domain registration started", { domain: reg.domainName, operationId });
          } catch (err: any) {
            updateDomainRegistration(regId, { status: "failed", lastError: String(err) });
            log("error", "webhook", "Domain registration failed", { domain: reg.domainName, error: String(err) });
          }
        }
      } catch (err: any) {
        log("error", "webhook", "MP domain webhook processing error", { error: String(err) });
      }
    }

    return new Response("OK", { status: 200 });
  }, {
    detail: { tags: ["Webhooks"], summary: "MercadoPago domain registration webhook", hide: true },
  })

  .get("/api/domains/registrations", async ({ request }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401, headers: { "content-type": "application/json" } });

    const registrations = getDomainRegistrationsByUser(auth.email);
    return new Response(JSON.stringify(registrations), { headers: { "content-type": "application/json" } });
  }, {
    detail: { tags: ["Domain Registration"], summary: "List domain registrations for current user", security: [{ cookieAuth: [] }] },
  })

  // --- API Keys ---

  .post("/api/api-keys", async ({ request, body }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401, headers: { "content-type": "application/json" } });
    const ip = getIp(request);
    const limited = await rateLimitGuard(ip, 5, 60_000);
    if (limited) return limited;
    const user = getUser(auth.email);
    if (!user) return new Response(JSON.stringify({ error: "Usuario no encontrado" }), { status: 404, headers: { "content-type": "application/json" } });
    const limits = getUserPlanLimits(user);
    if (!limits.api) return new Response(JSON.stringify({ error: "Tu plan no incluye acceso a la API" }), { status: 403, headers: { "content-type": "application/json" } });
    const { name } = body as { name: string };
    if (!name || typeof name !== "string" || name.length > 50) return new Response(JSON.stringify({ error: "Nombre inválido" }), { status: 400, headers: { "content-type": "application/json" } });
    const { apiKey, plaintextKey } = await createApiKey(auth.email, name.trim());
    return new Response(JSON.stringify({ ...apiKey, key: plaintextKey }), { status: 201, headers: { "content-type": "application/json" } });
  }, {
    body: t.Object({ name: t.String() }),
    detail: { tags: ["API Keys", "SDK"], summary: "Create a new API key", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  .get("/api/api-keys", async ({ request }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401, headers: { "content-type": "application/json" } });
    const user = getUser(auth.email);
    if (!user) return new Response(JSON.stringify({ error: "Usuario no encontrado" }), { status: 404, headers: { "content-type": "application/json" } });
    const limits = getUserPlanLimits(user);
    if (!limits.api) return new Response(JSON.stringify({ error: "Tu plan no incluye acceso a la API" }), { status: 403, headers: { "content-type": "application/json" } });
    const keys = listApiKeys(auth.email);
    return new Response(JSON.stringify(keys), { headers: { "content-type": "application/json" } });
  }, {
    detail: { tags: ["API Keys", "SDK"], summary: "List API keys for the authenticated user", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  })

  .delete("/api/api-keys/:id", async ({ request, params }) => {
    const auth = await getAuthUser(request);
    if (!auth) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401, headers: { "content-type": "application/json" } });
    const revoked = revokeApiKey(params.id, auth.email);
    if (!revoked) return new Response(JSON.stringify({ error: "API key no encontrada" }), { status: 404, headers: { "content-type": "application/json" } });
    return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
  }, {
    detail: { tags: ["API Keys", "SDK"], summary: "Revoke an API key", security: [{ cookieAuth: [] }, { bearerAuth: [] }] },
  });

// --- Bulk send cron (every minute, processes 14 emails/sec) ---

programar("* * * * *", async () => {
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

    // El tope diario se valida al encolar, pero un job puede cruzar la medianoche o
    // convivir con envíos sueltos. Sin esto el bulk vacía la lista sin mirar la cuota.
    const jobDomain = await getDomain(job.domainId);
    const jobOwner = jobDomain ? await getUser(jobDomain.ownerEmail) : null;
    const jobLimit = jobOwner ? getUserPlanLimits(jobOwner).sends : 0;

    // Sin cuota el job no puede avanzar nunca: hay que fallarlo, no dejarlo latiendo.
    // Pasa si el dominio se borró, si el dueño ya no existe, o si la suscripción venció
    // o se canceló mientras el job estaba a medias. Con `break` a secas quedaba en
    // processing y listPendingBulkJobs lo recogía cada minuto durante 7 días.
    if (jobLimit === 0) {
      job.status = "failed";
      job.lastError = "El plan del dominio ya no permite envíos";
      job.completedAt = new Date().toISOString();
      await updateBulkJob(job);
      log("warn", "ses", "Bulk job failed: no send quota available", { jobId: job.id, domainId: job.domainId });
      continue;
    }

    // El job guarda HTML crudo. Se sanea y se le deriva el texto plano una sola vez
    // por lote, no por destinatario: antes se mandaba `job.html` también como parte
    // text/plain y quien leyera en modo texto recibía el marcado.
    const bulkRendered = resolveEmailBody({ html: job.html });

    for (const recipient of batch) {
      // Check suppression
      if (await isSuppressed(job.domainId, recipient)) {
        job.skippedSuppressed++;
        continue;
      }

      // Reservar la cuota. Al toparse se deja el job en processing y se reanuda
      // mañana: bulk_jobs vive 7 días, así que no se pierde nada.
      const used = await incrementSendCount(job.domainId);
      if (used > jobLimit) {
        decrementSendCount(job.domainId);
        log("info", "ses", "Bulk job paused: daily send limit reached", { jobId: job.id, domainId: job.domainId, limit: jobLimit });
        break;
      }

      try {
        await sendFromDomain(job.from, recipient, job.subject, bulkRendered.text, {
          html: bulkRendered.html,
          configSet,
        });
        job.sent++;
      } catch (err) {
        decrementSendCount(job.domainId); // devolver la cuota reservada
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

programar("*/5 * * * *", async () => {
  const queueDepth = await getQueueDepth();
  const deadLetterCount = await getDeadLetterCount();

  if (deadLetterCount > 0) {
    await sendAlert("dead-letter-queue", `Dead-letter queue has ${deadLetterCount} item(s). Emails failed permanently after max retries.\nQueue depth: ${queueDepth}`);
  } else if (queueDepth > 10) {
    await sendAlert("queue-backlog", `Forward queue backlog: ${queueDepth} items pending retry.`);
  }
});

// --- Daily backup cron (4:00 UTC) ---

programar("0 4 * * *", async () => {
  try {
    const result = await runDbBackup();
    log("info", "backup", "Daily backup completed", {
      key: result.key, users: result.users, tables: result.tables, gzipBytes: result.gzipBytes,
    });
  } catch (err) {
    log("error", "backup", "Daily backup failed", { error: String(err) });
    await sendAlert("backup-failure", `Daily backup failed: ${String(err)}`);
  }
});

// Imágenes que se subieron al compositor y nunca se enviaron. Las que sí salieron ya
// se borran al enviar; esto recoge los borradores abandonados, que si no se acumulan
// para siempre. A las 4:20 para no chocar con el respaldo de las 4:00.
programar("20 4 * * *", async () => {
  try {
    const removed = await sweepOrphanEmailImages(24);
    if (removed > 0) log("info", "ses", "Orphan email images swept", { removed });
  } catch (err) {
    log("error", "ses", "Orphan image sweep failed", { error: String(err) });
  }
});

if (esServidor) {
  const port = parseInt(process.env.PORT ?? "8000", 10);
  app.listen({ port, hostname: "0.0.0.0" }, () => {
    console.log(`MailMask running on port ${port}`);
  });
}

// Graceful shutdown. Without these handlers the process ignored SIGINT/SIGTERM and Fly
// waited out its kill timeout — roughly 6 seconds of the deploy downtime window was the
// old machine refusing to die ("Virtual machine exited abruptly" in the logs).
let shuttingDown = false;
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.on(signal, () => {
    if (shuttingDown) return;
    shuttingDown = true;
    log("info", "process", `Received ${signal}, shutting down`);
    try {
      // Elysia exposes stop() on the Node adapter, but guard in case the runtime differs.
      (app as unknown as { stop?: () => void }).stop?.();
    } catch (err) {
      log("warn", "process", "Error stopping server", { error: String(err) });
    }
    try {
      // Checkpoint the WAL so the next boot does not have to recover the journal.
      sqlite.pragma("wal_checkpoint(TRUNCATE)");
      sqlite.close();
    } catch (err) {
      log("warn", "process", "Error closing database", { error: String(err) });
    }
    process.exit(0);
  });
}

process.on("uncaughtException", (err) => {
  log("error", "process", "Uncaught exception", { error: String(err) });
});
process.on("unhandledRejection", (err) => {
  log("error", "process", "Unhandled rejection", { error: String(err) });
});


// Repair receipt rules missing SNS TopicArn (one-time fix for rules created before SNS_TOPIC_ARN was set)
// Receipt rule repair already imported at top
if (esServidor) (async () => {
  try {
    const repaired = await repairReceiptRules();
    if (repaired > 0) log("info", "startup", `Repaired ${repaired} receipt rule(s) with missing TopicArn`);

    // Reconciliar base vs SES: cada dominio debe tener regla de recepción y
    // config set. Una fila puede sobrevivir a sus recursos (restauración de
    // respaldo tras un DELETE) y sin esto nadie lo nota hasta que rebota.
    const { listAllDomains } = await import("./db.js");
    for (const d of listAllDomains()) {
      try {
        const { ruleCreated } = await ensureDomainInbound(d.domain);
        if (ruleCreated) log("warn", "startup", `Recreated missing receipt rule for ${d.domain}`);
      } catch (err) {
        log("warn", "startup", "Could not reconcile domain with SES", { domain: d.domain, error: String(err) });
      }
    }

    // Las filas escritas antes de que la clave de supresión fuera consistente quedaron
    // con las mayúsculas de SES y ya no matcheaban. Idempotente.
    const normalized = normalizeSuppressionKeys();
    if (normalized > 0) log("info", "startup", `Normalized ${normalized} suppression key(s) to lowercase`);

    const appUrl = process.env.APP_URL ?? "https://www.mailmask.studio";
    const subStatus = await ensureSnsSubscription(appUrl, "inbound");
    log("info", "startup", `SNS subscription (inbound): ${subStatus}`);
    const outStatus = await ensureSnsSubscription(appUrl, "outbound");
    log("info", "startup", `SNS subscription (outbound): ${outStatus}`);
  } catch (err) {
    log("error", "startup", "Startup repair failed", { error: String(err) });
  }
})();

export { app };
