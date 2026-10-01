// Salida única de los buzones: lo que manda Apple Mail pasa por la app.
//
// Antes la ruta `ses` de Stalwart iba directo a SES, así que lo enviado desde un buzón
// no aparecía en la Bandeja (los hilos quedaban con sólo lo entrante), no descontaba de
// los envíos diarios del dominio y no entraba al log. Ahora esa ruta apunta a un relay
// LMTP mínimo que corre en la MISMA caja que Stalwart (`box/outbound-relay/`, sólo en
// 127.0.0.1:2525), y ese relay hace `POST /api/internal/outbound` aquí. La app hace lo
// mismo que con cualquier envío: valida al remitente, aplica la lista de supresión,
// reserva cuota, manda por SES, registra y engancha el hilo.
//
// Por qué así: la ruta `Relay` de Stalwart trae gratis la semántica de cola. Si el relay
// contesta 4xx (la app caída, timeout, SES caído) el mensaje se queda en la cola de
// Stalwart y se reintenta; si contesta 5xx, Stalwart le devuelve a quien envió un aviso
// de no entrega (DSN). Nada se pierde y nada se salta la app en silencio. LMTP y no SMTP
// porque LMTP contesta POR DESTINATARIO: un suprimido se rechaza solo, sin tumbar al resto.
// Los MTA Hooks no sirven: el de salida corre DESPUÉS de cada intento y sólo admite
// `continue`/`cancel`. Y nada de puerto TCP en Fly: el relay habla HTTPS como cualquiera.
//
// La ruta interna se autentica con HMAC del cuerpo y una marca de tiempo (±300 s) con
// `OUTBOUND_RELAY_SECRET`; nunca con cookie. La identidad del usuario ya la comprobó
// Stalwart con `mustMatchSender`, y aquí se comprueba además que el `From` visible
// coincida con el sobre, porque Stalwart sólo mira el sobre.

import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import PostalMime from "postal-mime";
import {
  getDomainByName, getAlias, getUser, derechosDeDominio, isSuppressed,
  incrementSendCount, decrementSendCount, addLog, claimOnce, releaseClaim,
  findConversationByThread, createConversation, updateConversation, addMessage, indexMessage,
  type Domain, type DerechosDominio,
} from "./db.js";
import { sendRawFromDomain, stripHeaders, getConfigSetName, threadRefsFor, normalizeAddress, MAX_RAW_MESSAGE_BYTES } from "./ses.js";
import { notifyBandeja } from "./sse-hub.js";
import { emitEvent } from "./webhooks.js";
import { log } from "./logger.js";

/**
 * Registra un envío saliente en `email_logs` con status `sent`. El webhook de
 * eventos de SES lo mueve a delivered/bounced/complained por `sesMessageId`.
 * Antes los envíos por API y bulk no dejaban rastro: la pestaña Logs sólo
 * mostraba reenvíos, y un envío que rebotaba era invisible.
 */
export function logOutbound(domainId: string, from: string, to: string, subject: string, body: string, sesMessageId: string, logDays: number): void {
  try {
    addLog({
      domainId, timestamp: new Date().toISOString(),
      from, to, subject,
      status: "sent", forwardedTo: to,
      sizeBytes: Buffer.byteLength(body ?? "", "utf8"),
      sesMessageId: sesMessageId || undefined,
    }, logDays);
  } catch (err) {
    log("warn", "ses", "Could not log outbound send", { domainId, error: String(err) });
  }
}

// --- Decisiones (puras respecto al transporte; las pruebas las llaman directo) ---

/** Rechazo con código SMTP. 4xx = Stalwart reintenta; 5xx = DSN a quien envió. */
export interface SmtpReject { code: number; message: string }

export interface SenderContext {
  domain: Domain;
  address: string;
  limits: DerechosDominio;
}

/** SES acepta hasta 50 destinos por llamada; lo que pase de ahí Stalwart lo manda en otra transacción. */
export const MAX_RELAY_RECIPIENTS = 50;

/**
 * ¿Puede esta dirección mandar por aquí? Tiene que ser una máscara CON buzón de un
 * dominio verificado y activado: el relay es la salida de los buzones, no un SMTP
 * abierto para cualquier dirección de un dominio que tengamos.
 */
export function resolveSender(rawAddress: string): SenderContext | SmtpReject {
  const address = normalizeAddress(rawAddress ?? "").toLowerCase();
  const at = address.lastIndexOf("@");
  if (at < 1) return { code: 550, message: "5.1.7 Remitente inválido" };
  const local = address.slice(0, at);
  const domain = getDomainByName(address.slice(at + 1));
  if (!domain) return { code: 550, message: "5.7.1 El dominio del remitente no está en MailMask" };
  if (!domain.verified) return { code: 550, message: "5.7.1 El dominio del remitente no está verificado" };

  const row = getAlias(domain.id, local);
  if (!row || !row.enabled || !row.mailboxEnabled) {
    return { code: 550, message: "5.7.1 El remitente no es un buzón activo de MailMask" };
  }

  const limits = derechosDeDominio(domain, getUser(domain.ownerEmail));
  if (limits.sends === 0 || !limits.sendsUnlocked) {
    return { code: 550, message: "5.7.1 El correo nuevo viene con el dominio activado ($99/mes)" };
  }
  return { domain, address, limits };
}

export function checkRecipient(ctx: SenderContext, rcpt: string): SmtpReject | null {
  const addr = normalizeAddress(rcpt ?? "").toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(addr)) return { code: 553, message: "5.1.3 Destinatario inválido" };
  // Insistirle a un buzón que rebotó Permanent daña la reputación del dominio en SES.
  // Se rechaza sólo ese destinatario; el resto del mensaje sigue.
  if (isSuppressed(ctx.domain.id, addr)) {
    return { code: 550, message: `5.1.1 ${addr} está en la lista de supresión (rebote o queja previa)` };
  }
  return null;
}

function headerBlock(raw: string): string {
  const sep = raw.search(/\r?\n\r?\n/);
  return sep >= 0 ? raw.slice(0, sep) : raw;
}

/**
 * Lo que se le quita al mensaje antes de SES. Las firmas DKIM ajenas: SES firma por el
 * dominio y rechaza con `554 Duplicate header 'DKIM-Signature'` si encuentra otra (el
 * dominio se crea en Stalwart con `dkimManagement: Manual` para que no firme, pero esto
 * es la segunda llave). `Bcc`: si un cliente lo deja en los headers, cada destinatario
 * vería la copia oculta. `Return-Path` lo pone quien entrega.
 */
export function prepareForSes(raw: string): string {
  return stripHeaders(raw, [
    "DKIM-Signature", "DomainKey-Signature",
    "ARC-Seal", "ARC-Message-Signature", "ARC-Authentication-Results",
    "Bcc", "Return-Path",
  ]);
}

/** ¿Es un error que se arregla reintentando? Lo que no, va como 5xx y acaba en DSN. */
function isPermanentSesError(err: any): boolean {
  const name = String(err?.name ?? err?.Code ?? "");
  return ["MessageRejected", "MailFromDomainNotVerifiedException", "InvalidParameterValue"].includes(name)
    || /excede el tamaño máximo/.test(String(err?.message ?? ""));
}

export interface RelayDeps {
  sendRaw: (raw: string, source: string, destinations: string[], configSet?: string) => Promise<string>;
}

const defaultDeps: RelayDeps = { sendRaw: sendRawFromDomain };

/** Por destinatario: `"ok"` o `"rejected:<código> <motivo>"`, que el relay LMTP traduce. */
export type PerRcpt = Record<string, string>;

export type RelayResult =
  | { ok: true; sesMessageId: string; perRcpt: PerRcpt; duplicate?: boolean; conversationId?: string }
  | ({ ok: false } & SmtpReject);

/**
 * El envío completo de un mensaje que Stalwart entregó. Repite las comprobaciones de
 * MAIL FROM y RCPT TO a propósito: es la función que se prueba sola y la que no puede
 * fiarse de que el transporte ya las hizo.
 */
export async function relayOutbound(
  envelope: { mailFrom: string; rcptTo: string[] },
  raw: string,
  deps: RelayDeps = defaultDeps,
): Promise<RelayResult> {
  if (Buffer.byteLength(raw, "utf8") > MAX_RAW_MESSAGE_BYTES) {
    return { ok: false, code: 552, message: "5.3.4 El correo excede el tamaño máximo" };
  }

  let parsed: Awaited<ReturnType<typeof PostalMime.parse>>;
  try {
    parsed = await PostalMime.parse(raw);
  } catch {
    return { ok: false, code: 554, message: "5.6.0 Mensaje ilegible" };
  }

  // La identidad es el `From` visible: es lo que ve el destinatario y lo que SES firma.
  // El sobre puede venir vacío (`<>`, avisos del propio servidor), pero si viene, debe
  // ser la misma dirección: Stalwart comprueba que el sobre sea del usuario autenticado
  // y nada más, así que un `From:` distinto sería suplantar a otra máscara del dominio.
  const headerFrom = (parsed.from?.address ?? "").toLowerCase();
  const envFrom = normalizeAddress(envelope.mailFrom ?? "").toLowerCase();
  if (!headerFrom) return { ok: false, code: 550, message: "5.7.1 El mensaje no trae remitente (From)" };
  if (envFrom && envFrom !== headerFrom) {
    return { ok: false, code: 550, message: "5.7.1 El From del mensaje no coincide con el buzón que envía" };
  }

  const sender = resolveSender(headerFrom);
  if ("code" in sender) return { ok: false, ...sender };
  const { domain, address, limits } = sender;

  const rcpts = [...new Set(envelope.rcptTo.map((r) => normalizeAddress(r).toLowerCase()).filter(Boolean))];
  if (!rcpts.length) return { ok: false, code: 554, message: "5.5.1 Sin destinatarios" };
  if (rcpts.length > MAX_RELAY_RECIPIENTS) return { ok: false, code: 452, message: "4.5.3 Demasiados destinatarios" };

  // Resultado por destinatario: un suprimido se rechaza solo y el resto sale.
  const perRcpt: PerRcpt = {};
  const accepted: string[] = [];
  for (const r of rcpts) {
    const bad = checkRecipient(sender, r);
    if (bad) perRcpt[r] = `rejected:${bad.code} ${bad.message}`;
    else { perRcpt[r] = "ok"; accepted.push(r); }
  }
  // Nadie aceptado: no se envía ni se cobra nada.
  if (!accepted.length) return { ok: true, sesMessageId: "", perRcpt };

  const messageId = (parsed.messageId ?? "").trim();
  const subject = parsed.subject ?? "";

  // Idempotencia: si SES aceptó pero el 250 no le llegó a Stalwart (deploy, red),
  // Stalwart reintenta el mismo mensaje. Sin esto el destinatario lo recibiría dos
  // veces y la cuota se cobraría doble. Se reclama ANTES de enviar —así dos reintentos
  // simultáneos tampoco salen los dos— y se suelta si el envío falla.
  const idemKey = createHash("sha256")
    .update(`${domain.id}\n${messageId || createHash("sha256").update(raw).digest("hex")}\n${[...accepted].sort().join(",")}`)
    .digest("hex");
  if (!claimOnce("relay-sent", idemKey, 3)) {
    log("info", "ses", "Relay: mensaje repetido, ya había salido", { domainId: domain.id, messageId });
    return { ok: true, sesMessageId: "", perRcpt, duplicate: true };
  }

  // Cuenta como `POST /send`: un mensaje es un envío, lleve los Cc que lleve. Responder
  // desde Apple Mail también cuenta (desde la app no se distingue una respuesta de un
  // correo nuevo sin confiar en headers que pone el cliente), y es lo que cierra el
  // hueco de "50/día que el 465 se salta".
  const reserved = incrementSendCount(domain.id);
  if (reserved > limits.sends) {
    decrementSendCount(domain.id);
    releaseClaim("relay-sent", idemKey);
    return { ok: false, code: 550, message: `5.7.0 Límite diario de envíos del dominio alcanzado (${limits.sends}). Vuelve a intentarlo mañana.` };
  }

  let sesMessageId: string;
  try {
    sesMessageId = await deps.sendRaw(prepareForSes(raw), address, accepted, getConfigSetName(domain.domain));
  } catch (err: any) {
    decrementSendCount(domain.id);
    releaseClaim("relay-sent", idemKey);
    const permanent = isPermanentSesError(err);
    log(permanent ? "warn" : "error", "ses", "Relay: SES no aceptó el mensaje", {
      domainId: domain.id, from: address, error: String(err), permanent,
    });
    return permanent
      ? { ok: false, code: 554, message: `5.7.1 SES rechazó el mensaje: ${String(err?.message ?? err).slice(0, 200)}` }
      : { ok: false, code: 451, message: "4.4.0 Error temporal al enviar; se reintentará" };
  }

  // De aquí en adelante el correo YA salió: nada puede devolver error, o Stalwart lo
  // reintentaría y saldría dos veces (la idempotencia lo frenaría, pero el log mentiría).
  const text = parsed.text ?? "";
  const html = parsed.html ?? "";
  logOutbound(domain.id, address, accepted.join(", "), subject, html || text, sesMessageId, limits.logDays);
  emitEvent(domain.id, "email.sent", {
    to: accepted[0], recipients: accepted, subject, from: address, messageId, sesMessageId, via: "mailbox",
  });

  let conversationId: string | undefined;
  try {
    conversationId = threadIntoBandeja({ domain, address, parsed, rcpts: accepted, messageId, sesMessageId, text, html, subject });
  } catch (err) {
    log("error", "mesa", "Relay: salió pero no se pudo guardar en la Bandeja", { domainId: domain.id, messageId, error: String(err) });
  }

  log("info", "ses", "Relay: enviado desde buzón", {
    domainId: domain.id, from: address, recipients: accepted.length, messageId, sesMessageId,
    sendsUsed: reserved, sendsLimit: limits.sends, conversationId,
  });
  return { ok: true, sesMessageId, perRcpt, conversationId };
}

/**
 * Engancha el enviado en su hilo de la Bandeja, o abre uno. Convención invertida, la
 * misma que al redactar: `from` = el contacto externo, `to` = nuestra máscara.
 *
 * Si todos los destinatarios son del propio dominio (escribirle a `hola@` desde un
 * buzón) no se abre conversación de salida: ese correo vuelve a entrar por SES y la
 * Bandeja lo registra como entrante, que es lo que es.
 */
function threadIntoBandeja(o: {
  domain: Domain; address: string; parsed: any; rcpts: string[];
  messageId: string; sesMessageId: string; text: string; html: string; subject: string;
}): string | undefined {
  const { domain, address, parsed, rcpts, messageId, sesMessageId, text, html, subject } = o;
  const own = (a: string) => a.toLowerCase().endsWith(`@${domain.domain.toLowerCase()}`);

  const refs: string[] = [];
  if (parsed.inReplyTo) refs.push(...String(parsed.inReplyTo).split(/\s+/).filter((r) => r.startsWith("<")));
  if (parsed.references) refs.push(...String(parsed.references).split(/\s+/).filter((r) => r.startsWith("<")));
  const uniqueRefs = [...new Set(refs)];
  const ownRefs = threadRefsFor({ messageId: messageId || `<${sesMessageId}@email.amazonses.com>`, sesMessageId });

  const now = new Date().toISOString();
  let conv = uniqueRefs.length ? findConversationByThread(domain.id, "", uniqueRefs) : null;

  if (conv) {
    if (messageId && conv.threadReferences.includes(messageId)) return conv.id; // ya registrado
  } else {
    const headerRcpts = [...(parsed.to ?? []), ...(parsed.cc ?? [])]
      .map((a: any) => String(a?.address ?? "").toLowerCase())
      .filter(Boolean);
    const contact = [...headerRcpts, ...rcpts].find((a) => !own(a));
    if (!contact) return undefined;
    conv = createConversation({
      domainId: domain.id,
      from: contact,
      to: address,
      subject,
      status: "open",
      priority: "normal",
      lastMessageAt: now,
      messageCount: 1,
      tags: [],
      threadReferences: [...new Set([...uniqueRefs, ...ownRefs])],
    });
    const msg = addMessage({
      conversationId: conv.id, from: address, body: text, html, direction: "outbound",
      createdAt: now, messageId: messageId || undefined, sesMessageId: sesMessageId || undefined,
    });
    indexMessage({ messageId: msg.id, conversationId: conv.id, domainId: domain.id, from: address, subject, text });
    notifyBandeja(domain.id, "new_conversation", { conversationId: conv.id, from: contact, subject });
    return conv.id;
  }

  const msg = addMessage({
    conversationId: conv.id, from: address, body: text, html, direction: "outbound",
    createdAt: now, messageId: messageId || undefined, sesMessageId: sesMessageId || undefined,
  });
  indexMessage({ messageId: msg.id, conversationId: conv.id, domainId: domain.id, from: address, subject: conv.subject, text });
  updateConversation(domain.id, conv.id, {
    threadReferences: [...new Set([...conv.threadReferences, ...ownRefs])],
    lastMessageAt: now,
    messageCount: conv.messageCount + 1,
  });
  notifyBandeja(domain.id, "conv_replied", {
    conversationId: conv.id, messageId: msg.id, lastMessageAt: now,
    messageCount: conv.messageCount + 1, actor: address,
  });
  return conv.id;
}

// --- Ruta interna: POST /api/internal/outbound ---

export const RELAY_SIGNATURE_WINDOW_S = 300;

/** `sha256=<hex>` de HMAC(secreto, `${timestamp}.${cuerpo}`): el mismo esquema que los webhooks. */
export function signRelayBody(secret: string, timestamp: string, body: string): string {
  return "sha256=" + createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
}

function json(status: number, data: unknown): Response {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });
}

/**
 * Cuerpo: `{ mailFrom, rcptTo[], raw }` con `raw` = MIME en base64. Respuestas, que el
 * relay de la caja traduce a LMTP:
 * - 200 `{ perRcpt, sesMessageId }`: lo que se decidió por destinatario.
 * - 422 `{ error, code }`: política sobre el mensaje entero (`code` es el SMTP: 5xx → DSN,
 *   4xx → reintento).
 * - 401 firma mala o vencida, 400 cuerpo ilegible, 503 SES caído: todo eso es 451 en la
 *   caja. Una firma mala es un error de configuración y no puede rebotar el correo.
 */
export async function handleInternalOutbound(request: Request, deps: RelayDeps = defaultDeps): Promise<Response> {
  const secret = process.env.OUTBOUND_RELAY_SECRET ?? "";
  // Sin secreto, cerrado: no hay forma de que esto quede abierto por un despiste.
  if (!secret) return json(401, { error: "Relay no configurado" });

  const timestamp = request.headers.get("x-mailmask-timestamp") ?? "";
  const signature = request.headers.get("x-mailmask-signature") ?? "";
  const ts = Number(timestamp);
  if (!timestamp || !Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > RELAY_SIGNATURE_WINDOW_S) {
    return json(401, { error: "Marca de tiempo ausente o vencida" });
  }

  let body: string;
  try {
    body = await request.text();
  } catch {
    return json(400, { error: "Cuerpo ilegible" });
  }
  const expected = Buffer.from(signRelayBody(secret, timestamp, body));
  const given = Buffer.from(signature);
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) {
    log("warn", "ses", "Relay: firma inválida en /api/internal/outbound");
    return json(401, { error: "Firma inválida" });
  }

  let payload: { mailFrom?: unknown; rcptTo?: unknown; raw?: unknown };
  try {
    payload = JSON.parse(body);
  } catch {
    return json(400, { error: "JSON inválido" });
  }
  if (!Array.isArray(payload.rcptTo) || typeof payload.raw !== "string") {
    return json(400, { error: "mailFrom, rcptTo[] y raw (base64) requeridos" });
  }
  const raw = Buffer.from(payload.raw, "base64").toString("utf8");

  try {
    const r = await relayOutbound({ mailFrom: String(payload.mailFrom ?? ""), rcptTo: payload.rcptTo.map(String) }, raw, deps);
    if (r.ok) return json(200, { perRcpt: r.perRcpt, sesMessageId: r.sesMessageId, duplicate: r.duplicate ?? false, conversationId: r.conversationId });
    if (r.code === 451) return json(503, { error: r.message, code: r.code });
    return json(422, { error: r.message, code: r.code });
  } catch (err) {
    log("error", "ses", "Relay: error inesperado", { error: String(err) });
    return json(503, { error: "Error temporal", code: 451 });
  }
}
