import { Elysia } from "elysia";
import {
  getUser, createUser, createDomain, getDomain, listUserDomains,
  updateDomain, deleteDomain, countUserDomains, createAlias, getAlias,
  listAliases, updateAlias, deleteAlias, countAliases, createRule,
  listRules, deleteRule, listLogs, PRICING,
} from "./db.ts";
import {
  hashPassword, verifyPassword, signJwt, makeAuthCookie,
  clearAuthCookie, getAuthUser,
} from "./auth.ts";
import { checkRateLimit } from "./rate-limit.ts";
import { verifyDomain, checkDomainStatus, createReceiptRule, deleteReceiptRule } from "./ses.ts";
import { processInbound } from "./forwarding.ts";

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
    };
    return new Response(file, {
      headers: { "content-type": types[ext] ?? "application/octet-stream" },
    });
  } catch {
    return new Response("Not found", { status: 404 });
  }
}

function getIp(request: Request): string {
  return request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    request.headers.get("cf-connecting-ip") ?? "unknown";
}

function rateLimitGuard(ip: string, limit: number, windowMs: number): Response | null {
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

const MAX_ALIASES_PER_DOMAIN = 25;
const MAX_RULES_PER_DOMAIN = 10;

// --- App ---

const app = new Elysia()

  // --- CORS ---
  .onRequest(({ request }) => {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS",
          "access-control-allow-headers": "content-type",
          "access-control-max-age": "86400",
        },
      });
    }
  })
  .onAfterHandle(({ response }) => {
    if (response instanceof Response) {
      response.headers.set("access-control-allow-origin", "*");
    }
    return response;
  })

  // --- Health ---
  .get("/health", () => ({ status: "ok", service: "mailmask", timestamp: new Date().toISOString() }))

  // --- Static pages ---
  .get("/", () => serveStatic("/landing.html"))
  .get("/login", () => serveStatic("/login.html"))
  .get("/register", () => serveStatic("/register.html"))
  .get("/app", () => serveStatic("/app.html"))
  .get("/js/*", ({ params }) => serveStatic(`/js/${params["*"]}`))
  .get("/favicon.svg", () => serveStatic("/favicon.svg"))

  // --- Auth ---

  .post("/api/auth/register", async ({ request }) => {
    const ip = getIp(request);
    const limited = rateLimitGuard(ip, 5, 60_000);
    if (limited) return limited;

    const { email, password } = await request.json();
    if (!email || !password) return new Response(JSON.stringify({ error: "Email y contraseña requeridos" }), { status: 400 });
    if (password.length < 8) return new Response(JSON.stringify({ error: "Contraseña mínimo 8 caracteres" }), { status: 400 });

    const existing = await getUser(email);
    if (existing) return new Response(JSON.stringify({ error: "Este email ya está registrado" }), { status: 409 });

    const hash = await hashPassword(password);
    await createUser(email, hash);

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
    const limited = rateLimitGuard(ip, 10, 60_000);
    if (limited) return limited;

    const { email, password } = await request.json();
    if (!email || !password) return new Response(JSON.stringify({ error: "Email y contraseña requeridos" }), { status: 400 });

    const user = await getUser(email);
    if (!user) return new Response(JSON.stringify({ error: "Credenciales inválidas" }), { status: 401 });

    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) return new Response(JSON.stringify({ error: "Credenciales inválidas" }), { status: 401 });

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
    const user = await getAuthUser(request);
    if (!user) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });
    const domains = await listUserDomains(user.email);
    return new Response(JSON.stringify({ email: user.email, domainsCount: domains.length }), {
      headers: { "content-type": "application/json" },
    });
  })

  // --- Domains ---

  .get("/api/domains", async ({ request }) => {
    const user = await getAuthUser(request);
    if (!user) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const domains = await listUserDomains(user.email);
    return new Response(JSON.stringify(domains), {
      headers: { "content-type": "application/json" },
    });
  })

  .post("/api/domains", async ({ request }) => {
    const user = await getAuthUser(request);
    if (!user) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const ip = getIp(request);
    const limited = rateLimitGuard(ip, 10, 60_000);
    if (limited) return limited;

    const { domain } = await request.json();
    if (!domain || typeof domain !== "string") {
      return new Response(JSON.stringify({ error: "Dominio requerido" }), { status: 400 });
    }

    // Validate domain format
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
      return new Response(JSON.stringify({ error: "Formato de dominio inválido" }), { status: 400 });
    }

    // Check if domain already registered
    const existing = await (await import("./db.ts")).getDomainByName(domain);
    if (existing) {
      return new Response(JSON.stringify({ error: "Este dominio ya está registrado" }), { status: 409 });
    }

    // Verify with SES
    let dnsRecords;
    try {
      dnsRecords = await verifyDomain(domain);
    } catch (err) {
      return new Response(JSON.stringify({ error: "Error verificando dominio con SES", details: String(err) }), { status: 500 });
    }

    // Create receipt rule for inbound
    try {
      await createReceiptRule(domain);
    } catch (err) {
      console.warn("Could not create receipt rule (may already exist):", err);
    }

    const newDomain = await createDomain(
      user.email,
      domain,
      dnsRecords.dkimTokens,
      dnsRecords.verificationToken,
    );

    // Return DNS records the customer needs to configure
    return new Response(JSON.stringify({
      domain: newDomain,
      dnsRecords: {
        mx: { type: "MX", name: domain, value: "10 inbound-smtp.us-east-1.amazonaws.com", priority: 10 },
        verification: { type: "TXT", name: `_amazonses.${domain}`, value: dnsRecords.verificationToken },
        dkim: dnsRecords.dkimTokens.map((token: string) => ({
          type: "CNAME",
          name: `${token}._domainkey.${domain}`,
          value: `${token}.dkim.amazonses.com`,
        })),
      },
    }), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  })

  .get("/api/domains/:id", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }

    return new Response(JSON.stringify(domain), {
      headers: { "content-type": "application/json" },
    });
  })

  .post("/api/domains/:id/verify", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }

    const status = await checkDomainStatus(domain.domain);
    await updateDomain(domain.id, { verified: status.verified });

    return new Response(JSON.stringify({
      domain: domain.domain,
      verified: status.verified,
      dkimVerified: status.dkimVerified,
    }), {
      headers: { "content-type": "application/json" },
    });
  })

  .delete("/api/domains/:id", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }

    // Clean up SES receipt rule
    try {
      await deleteReceiptRule(domain.domain);
    } catch { /* best effort */ }

    await deleteDomain(params.id);
    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  })

  // --- Aliases ---

  .get("/api/domains/:id/aliases", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }

    const aliases = await listAliases(domain.id);
    return new Response(JSON.stringify(aliases), {
      headers: { "content-type": "application/json" },
    });
  })

  .post("/api/domains/:id/aliases", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }

    const count = await countAliases(domain.id);
    if (count >= MAX_ALIASES_PER_DOMAIN) {
      return new Response(JSON.stringify({ error: `Máximo ${MAX_ALIASES_PER_DOMAIN} aliases por dominio` }), { status: 400 });
    }

    const { alias, destinations } = await request.json();
    if (!alias || !destinations?.length) {
      return new Response(JSON.stringify({ error: "Alias y destinos requeridos" }), { status: 400 });
    }

    // Validate alias format (alphanumeric, dots, hyphens, or * for catch-all)
    if (alias !== "*" && !/^[a-zA-Z0-9._-]+$/.test(alias)) {
      return new Response(JSON.stringify({ error: "Formato de alias inválido" }), { status: 400 });
    }

    const existing = await getAlias(domain.id, alias);
    if (existing) {
      return new Response(JSON.stringify({ error: "Este alias ya existe" }), { status: 409 });
    }

    const newAlias = await createAlias(domain.id, alias, destinations);
    return new Response(JSON.stringify(newAlias), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  })

  .put("/api/domains/:id/aliases/:alias", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }

    const body = await request.json();
    const updated = await updateAlias(domain.id, params.alias, body);
    if (!updated) return new Response(JSON.stringify({ error: "Alias no encontrado" }), { status: 404 });

    return new Response(JSON.stringify(updated), {
      headers: { "content-type": "application/json" },
    });
  })

  .delete("/api/domains/:id/aliases/:alias", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }

    const deleted = await deleteAlias(domain.id, params.alias);
    if (!deleted) return new Response(JSON.stringify({ error: "Alias no encontrado" }), { status: 404 });

    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  })

  // --- Rules ---

  .get("/api/domains/:id/rules", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }

    const rules = await listRules(domain.id);
    return new Response(JSON.stringify(rules), {
      headers: { "content-type": "application/json" },
    });
  })

  .post("/api/domains/:id/rules", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }

    const existingRules = await listRules(domain.id);
    if (existingRules.length >= MAX_RULES_PER_DOMAIN) {
      return new Response(JSON.stringify({ error: `Máximo ${MAX_RULES_PER_DOMAIN} reglas por dominio` }), { status: 400 });
    }

    const { field, match, value, action, target, priority = 0, enabled = true } = await request.json();
    if (!field || !match || !value || !action) {
      return new Response(JSON.stringify({ error: "Campos requeridos: field, match, value, action" }), { status: 400 });
    }

    const validFields = ["to", "from", "subject"];
    const validMatches = ["contains", "equals", "regex"];
    const validActions = ["forward", "webhook", "discard"];

    if (!validFields.includes(field) || !validMatches.includes(match) || !validActions.includes(action)) {
      return new Response(JSON.stringify({ error: "Valores inválidos para field, match o action" }), { status: 400 });
    }

    if (action !== "discard" && !target) {
      return new Response(JSON.stringify({ error: "Target requerido para acciones forward y webhook" }), { status: 400 });
    }

    const rule = await createRule(domain.id, { field, match, value, action, target: target ?? "", priority, enabled });
    return new Response(JSON.stringify(rule), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  })

  .delete("/api/domains/:id/rules/:ruleId", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }

    const deleted = await deleteRule(domain.id, params.ruleId);
    if (!deleted) return new Response(JSON.stringify({ error: "Regla no encontrada" }), { status: 404 });

    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  })

  // --- Logs ---

  .get("/api/domains/:id/logs", async ({ request, params }) => {
    const user = await getAuthUser(request);
    if (!user) return new Response(JSON.stringify({ error: "No autenticado" }), { status: 401 });

    const domain = await getDomain(params.id);
    if (!domain || domain.ownerEmail !== user.email) {
      return new Response(JSON.stringify({ error: "Dominio no encontrado" }), { status: 404 });
    }

    const url = new URL(request.url);
    const limit = Math.min(parseInt(url.searchParams.get("limit") ?? "50"), 100);

    const logs = await listLogs(domain.id, limit);
    return new Response(JSON.stringify(logs), {
      headers: { "content-type": "application/json" },
    });
  })

  // --- Webhook: SES inbound via SNS ---

  .post("/api/webhooks/ses-inbound", async ({ request }) => {
    const body = await request.json();
    const result = await processInbound(body);
    return new Response(JSON.stringify(result), {
      headers: { "content-type": "application/json" },
    });
  })

  // --- Start ---
  .listen(parseInt(Deno.env.get("PORT") ?? "8000"));

console.log(`MailMask corriendo en http://localhost:${app.server?.port}`);

export { app };
