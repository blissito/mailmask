// Asistente de /app: cliente de Ghosty Studio, historial del dock y adjuntos.
//
// El navegador sólo habla con `/api/asistente/*`; MailMask firma con HMAC y abre el
// turno en Ghosty, que corre el agente "mailmask" con un MCP apuntando a nuestro `/mcp`
// y `Authorization: Bearer ${turn.token}` (el `mt_` de 5 min que acuñamos por turno).
//
// Dos runtimes, elegidos con `GHOSTY_RUNTIME`:
// - `fleet` (por defecto): claude-worker, `POST /api/v2/fleet-agents/:id/message-stream`.
// - `partner`: `POST /api/v2/partner/turns`, motor solo-MCP del patrón partner.
// Los dos hablan el mismo SSE: `data: {type:"chunk"|"tool"|"done"|"error"}` más `: hb`.
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { sqlite } from "./pg.js";
import { getDomain, getUser, getAgentByEmail, derechosDeDominio } from "./db.js";

// --- Configuración ---

export type GhostyRuntime = "fleet" | "partner";

export function ghostyRuntime(): GhostyRuntime {
  return process.env.GHOSTY_RUNTIME === "partner" ? "partner" : "fleet";
}

function ghostyBaseUrl(): string {
  return (process.env.GHOSTY_BASE_URL ?? "https://www.ghosty.studio").replace(/\/+$/, "");
}

// Inyectable para las pruebas: un Ghosty simulado sin red.
let ghostyFetch: typeof fetch = (input, init) => fetch(input, init);
export function setGhostyFetch(f: typeof fetch | null): void {
  ghostyFetch = f ?? ((input, init) => fetch(input, init));
}

// --- Firma (credencial por partner de Ghosty: gpk_ + gps_) ---
//
// Canónico = `${ts}.${keyId}.${rawBody}`, HMAC-SHA256 en hex con el secreto `gps_…`,
// `ts` en segundos epoch. Es exactamente `credentialCanonical`/`signWithSecret` de
// ghosty-studio (`app/lib/partner/partners.server.ts`); Ghosty acepta ±300 s.
export function signGhostyRequest(keyId: string, secret: string, rawBody: string, ts = Math.floor(Date.now() / 1000)): Record<string, string> {
  const sig = createHmac("sha256", secret).update(`${ts}.${keyId}.${rawBody}`).digest("hex");
  return { "X-Ghosty-Key": keyId, "X-Ghosty-Ts": String(ts), "X-Ghosty-Sig": sig };
}

// --- Identidad hacia Ghosty ---

/** Id estable y opaco del usuario: Ghosty no necesita (ni debe guardar) su correo. */
export function userKey(email: string): string {
  return createHash("sha256").update(email.trim().toLowerCase()).digest("hex").slice(0, 24);
}

export function assistantGroupId(email: string, nonce: string | null | undefined): string {
  return `web-${userKey(email)}${nonce ? `-${nonce}` : ""}`;
}

export function getAssistantNonce(email: string): string | null {
  const row = sqlite.prepare("SELECT assistant_nonce AS n FROM users WHERE email = ?").get(email) as { n: string | null } | undefined;
  return row?.n ?? null;
}

export function rotateAssistantNonce(email: string): string {
  const nonce = crypto.randomUUID().slice(0, 8);
  sqlite.prepare("UPDATE users SET assistant_nonce = ? WHERE email = ?").run(nonce, email);
  return nonce;
}

// --- Adjuntos ---

export type AssistantAttachment = { url: string; name?: string; contentType?: string; size?: number };

/** Mismo formato que `renderAttachmentMarkdown` del dock: así se re-hidrata al recargar. */
export function attachmentMarkdown(a: AssistantAttachment): string {
  const name = a.name || "archivo";
  return a.contentType?.startsWith("image/") ? `![${name}](${a.url})` : `[${name}](${a.url})`;
}

// URL firmada a nuestra propia ruta (`/api/asistente/files/*`) y no un presign de S3:
// la CSP del /app sólo deja `img-src 'self'`, así que las miniaturas del dock no
// cargarían desde el bucket, y Ghosty la puede descargar igual sin sesión.
export const UPLOAD_URL_TTL_S = 7 * 24 * 3600;

function uploadSig(key: string, exp: number): string {
  return createHmac("sha256", process.env.JWT_SECRET ?? "").update(`assistant-upload.${key}.${exp}`).digest("hex");
}

export function signedUploadUrl(baseUrl: string, key: string, now = Date.now()): string {
  const exp = Math.floor(now / 1000) + UPLOAD_URL_TTL_S;
  const path = key.split("/").map(encodeURIComponent).join("/");
  return `${baseUrl}/api/asistente/files/${path}?exp=${exp}&sig=${uploadSig(key, exp)}`;
}

export function verifyUploadSig(key: string, exp: string | null, sig: string | null): boolean {
  const e = Number(exp);
  if (!sig || !Number.isFinite(e) || e < Math.floor(Date.now() / 1000)) return false;
  const want = Buffer.from(uploadSig(key, e));
  const got = Buffer.from(sig);
  return want.length === got.length && timingSafeEqual(want, got);
}

/** Sólo se aceptan adjuntos subidos por ESTE usuario a nuestra ruta firmada. */
export function isOwnUpload(url: string, email: string): boolean {
  try {
    const u = new URL(url);
    return u.pathname.startsWith(`/api/asistente/files/${userKey(email)}/`) && verifyUploadSig(
      decodeURIComponent(u.pathname.slice("/api/asistente/files/".length)),
      u.searchParams.get("exp"),
      u.searchParams.get("sig"),
    );
  } catch {
    return false;
  }
}

// --- Contexto de pantalla ---

const TAB_ALLOWLIST = new Set([
  "aliases", "mascaras", "rules", "reglas", "logs", "dns", "send", "envios", "webhooks",
  "smtp", "members", "equipo", "settings", "ajustes", "activation", "health", "salud",
  "billing", "domains", "transfer", "mailboxes", "buzones",
]);

/**
 * Línea de contexto para el system prompt a partir de lo que el dock dice que se ve.
 * Nada del cliente se copia al prompt tal cual: el dominio se carga por id y sólo si el
 * usuario tiene acceso, y la pestaña pasa por una lista cerrada.
 */
export function buildScreenContext(email: string, screen: unknown): string | null {
  if (!screen || typeof screen !== "object") return null;
  const s = screen as { domainId?: unknown; tab?: unknown };
  const lines: string[] = [];
  if (typeof s.domainId === "string" && /^[A-Za-z0-9-]{1,64}$/.test(s.domainId)) {
    const domain = getDomain(s.domainId);
    if (domain && (domain.ownerEmail === email || getAgentByEmail(domain.id, email))) {
      const owner = getUser(domain.ownerEmail);
      const d = owner ? derechosDeDominio(domain, owner) : null;
      const estado = !d ? "desconocido" : d.activado ? "activado" : d.esGratis ? "gratis" : "bloqueado (falta activarlo: guarda el correo pero no lo reenvía)";
      lines.push(`Dominio en pantalla: ${domain.domain} (domainId ${domain.id}).`);
      lines.push(`Verificado en SES: ${domain.verified ? "sí" : "no (faltan registros DNS o no se ha verificado)"}. Plan del dominio: ${estado}.`);
      const salud = !domain.verified
        ? "Último diagnóstico conocido: error técnico, el dominio no está verificado."
        : d?.bloqueado
          ? "Último diagnóstico conocido: aviso, falta activar este dominio."
          : "Último diagnóstico conocido: sin errores técnicos registrados; usa domain_health para el detalle.";
      lines.push(salud);
    }
  }
  if (typeof s.tab === "string" && TAB_ALLOWLIST.has(s.tab)) lines.push(`Pestaña abierta: ${s.tab}.`);
  return lines.length ? lines.join("\n") : null;
}

// --- Turno en Ghosty ---

export type TurnInput = {
  email: string;
  text: string;
  attachments: AssistantAttachment[];
  appendSystemPrompt?: string;
  turnToken: string;
  signal?: AbortSignal;
};

export function buildTurnRequest(t: TurnInput): { url: string; body: Record<string, unknown> } {
  const groupId = assistantGroupId(t.email, getAssistantNonce(t.email));
  if (ghostyRuntime() === "partner") {
    // Los turnos partner son sólo texto: los adjuntos van como links que el agente abre.
    const text = [t.text, ...t.attachments.map(attachmentMarkdown)].filter(Boolean).join("\n");
    const body: Record<string, unknown> = { tenant: { externalId: userKey(t.email) }, groupId, text, token: t.turnToken };
    if (process.env.GHOSTY_PARTNER_AGENT) body.agent = process.env.GHOSTY_PARTNER_AGENT;
    if (t.appendSystemPrompt) body.appendSystemPrompt = t.appendSystemPrompt;
    return { url: `${ghostyBaseUrl()}/api/v2/partner/turns`, body };
  }
  const body: Record<string, unknown> = { groupId, text: t.text, turnToken: t.turnToken };
  if (t.attachments.length) {
    body.parts = t.attachments.map((a) => ({ kind: "file", file: { name: a.name, mimeType: a.contentType || "application/octet-stream", uri: a.url } }));
  }
  if (t.appendSystemPrompt) body.appendSystemPrompt = t.appendSystemPrompt;
  return { url: `${ghostyBaseUrl()}/api/v2/fleet-agents/${encodeURIComponent(process.env.GHOSTY_AGENT_ID ?? "")}/message-stream`, body };
}

export async function openGhostyTurn(t: TurnInput): Promise<{ ok: true; body: ReadableStream<Uint8Array> } | { ok: false; reason: string }> {
  const keyId = process.env.GHOSTY_PARTNER_KEY;
  const secret = process.env.GHOSTY_PARTNER_SECRET;
  if (!keyId || !secret) return { ok: false, reason: "GHOSTY_PARTNER_KEY/GHOSTY_PARTNER_SECRET sin configurar" };
  if (ghostyRuntime() === "fleet" && !process.env.GHOSTY_AGENT_ID) return { ok: false, reason: "GHOSTY_AGENT_ID sin configurar" };
  const { url, body } = buildTurnRequest(t);
  const raw = JSON.stringify(body);
  try {
    const res = await ghostyFetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "text/event-stream", ...signGhostyRequest(keyId, secret, raw) },
      body: raw,
      signal: t.signal,
    });
    if (!res.ok || !res.body) {
      const detail = await res.text().catch(() => "");
      return { ok: false, reason: `HTTP ${res.status} ${detail.slice(0, 300)}` };
    }
    return { ok: true, body: res.body };
  } catch (err) {
    return { ok: false, reason: String((err as Error)?.message ?? err) };
  }
}

// --- SSE: re-emitir y capturar ---

/** Corta el buffer en frames completos (`\n\n`). Lo que queda en `rest` se re-alimenta. */
export function splitSseFrames(buffer: string): { frames: string[]; rest: string } {
  const frames: string[] = [];
  let rest = buffer;
  let nl: number;
  while ((nl = rest.indexOf("\n\n")) !== -1) {
    frames.push(rest.slice(0, nl));
    rest = rest.slice(nl + 2);
  }
  return { frames, rest };
}

function frameEvent(frame: string): Record<string, unknown> | null {
  const line = frame.split("\n").find((l) => l.startsWith("data: "));
  if (!line) return null;
  try {
    const o = JSON.parse(line.slice(6));
    return o && typeof o === "object" ? o : null;
  } catch {
    return null;
  }
}

export type TurnOutcome = { reply: string; status: "ok" | "failed" | "stopped"; error?: string };

/**
 * Re-emite el SSE de Ghosty frame por frame (un `enqueue` por evento, sin esperar a
 * juntar) y a la vez acumula la respuesta para guardarla. `done.value` es autoritativo
 * y pisa los `chunk`. Si el navegador corta («Detener» o cerró la pestaña), se aborta
 * el fetch a Ghosty y se guarda lo que alcanzó a llegar como `stopped`.
 */
export function relayTurn(
  upstream: ReadableStream<Uint8Array>,
  upstreamAbort: AbortController,
  onFinish: (o: TurnOutcome) => void,
): ReadableStream<Uint8Array> {
  const reader = upstream.getReader();
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  let buffer = "";
  let chunks = "";
  let final = "";
  let error: string | undefined;
  let finished = false;
  const finish = (status: TurnOutcome["status"]) => {
    if (finished) return;
    finished = true;
    const reply = (final || chunks).trim();
    onFinish({ reply, status: error && status === "ok" ? "failed" : status, error });
  };
  const handle = (frame: string, controller: ReadableStreamDefaultController<Uint8Array>) => {
    controller.enqueue(encoder.encode(`${frame}\n\n`));
    const evt = frameEvent(frame);
    if (!evt) return;
    if (evt.type === "chunk" && typeof evt.value === "string") chunks += evt.value;
    else if (evt.type === "done" && typeof evt.value === "string") final = evt.value;
    else if (evt.type === "error") error = typeof evt.message === "string" ? evt.message : "error";
  };

  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          buffer += decoder.decode();
          const { frames, rest } = splitSseFrames(buffer + (buffer.trim() ? "\n\n" : ""));
          buffer = rest;
          for (const f of frames) handle(f, controller);
          finish("ok");
          controller.close();
          return;
        }
        buffer += decoder.decode(value, { stream: true });
        const { frames, rest } = splitSseFrames(buffer);
        buffer = rest;
        for (const f of frames) handle(f, controller);
      } catch (err) {
        if (upstreamAbort.signal.aborted) {
          finish("stopped");
        } else {
          error = error ?? String((err as Error)?.message ?? err);
          const msg = { type: "error", message: "Se cortó la conexión con el asistente" };
          try { controller.enqueue(encoder.encode(`data: ${JSON.stringify(msg)}\n\n`)); } catch { /* cerrado */ }
          finish("failed");
        }
        try { controller.close(); } catch { /* ya cerrado */ }
      }
    },
    cancel() {
      upstreamAbort.abort();
      reader.cancel().catch(() => {});
      finish("stopped");
    },
  });
}

// --- Historial del dock ---

export const HISTORY_PAGE_SIZE = 40;

export type AssistantMessageRow = { id: string; role: string; content: string; status: string; createdAt: string };

// Monotónico: dos mensajes en el mismo milisegundo romperían el orden y la paginación.
let lastTs = 0;
function nowIso(): string {
  const t = Math.max(Date.now(), lastTs + 1);
  lastTs = t;
  return new Date(t).toISOString();
}

export function saveAssistantMessage(email: string, role: "user" | "assistant", content: string, status: "ok" | "failed" | "stopped" = "ok"): AssistantMessageRow {
  const row = { id: crypto.randomUUID(), role, content, status, createdAt: nowIso() };
  sqlite
    .prepare("INSERT INTO assistant_messages (id, user_email, role, content, status, created_at) VALUES (?, ?, ?, ?, ?, ?)")
    .run(row.id, email, row.role, row.content, row.status, row.createdAt);
  return row;
}

export function getMessagePage(email: string, beforeIso?: string | null): { messages: AssistantMessageRow[]; hasMore: boolean } {
  const before = beforeIso && !Number.isNaN(Date.parse(beforeIso)) ? new Date(beforeIso).toISOString() : null;
  const rows = sqlite
    .prepare(`SELECT id, role, content, status, created_at AS createdAt FROM assistant_messages
              WHERE user_email = ? ${before ? "AND created_at < ?" : ""} ORDER BY created_at DESC LIMIT ?`)
    .all(...(before ? [email, before, HISTORY_PAGE_SIZE + 1] : [email, HISTORY_PAGE_SIZE + 1])) as AssistantMessageRow[];
  const hasMore = rows.length > HISTORY_PAGE_SIZE;
  return { messages: (hasMore ? rows.slice(0, HISTORY_PAGE_SIZE) : rows).reverse(), hasMore };
}

export function clearAssistantMessages(email: string): void {
  sqlite.prepare("DELETE FROM assistant_messages WHERE user_email = ?").run(email);
}

/** Lo que el modelo conoce de MailMask y que no cambia entre turnos. */
export const ASSISTANT_BASE_PROMPT = [
  "Estás dentro del panel de MailMask (/app) hablando con el dueño de la cuenta.",
  "Opera su cuenta con las herramientas del MCP `mailmask`; nunca le pidas su API key.",
  "Las acciones destructivas (borrar dominio, máscara, buzón o registro DNS, trasladar el dominio, quitar a una persona) piden confirmación: si una herramienta responde que necesita confirmación, dile que apruebe la tarjeta y no reintentes.",
  "El pago siempre lo hace el usuario: comparte el enlace, nunca digas que ya quedó pagado.",
].join("\n");
