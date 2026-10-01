// Salida única de los buzones: Stalwart entrega aquí, por SMTP, lo que manda Apple Mail.
//
// Antes la ruta `ses` de Stalwart iba directo a SES, así que lo enviado desde un buzón
// no aparecía en la Bandeja (los hilos quedaban con sólo lo entrante), no descontaba de
// los envíos diarios del dominio y no entraba al log. Ahora esa ruta apunta a este
// listener y la app hace lo mismo que con cualquier envío: valida al remitente, aplica
// la lista de supresión, reserva cuota, manda por SES, registra y engancha el hilo.
//
// Por qué SMTP y no un webhook: la ruta `Relay` de Stalwart trae gratis la semántica de
// cola. Si la app está caída o contesta 4xx, el mensaje se queda en la cola de Stalwart
// y se reintenta; si contesta 5xx, Stalwart le devuelve a quien envió un aviso de no
// entrega (DSN) con nuestro texto. Nada se pierde y nada se salta la app en silencio.
// Los MTA Hooks de Stalwart no sirven para esto: el de salida (`delivery`) corre
// DESPUÉS de cada intento de entrega y sólo admite `continue`/`cancel`.
//
// El TLS lo termina el borde de Fly (handler `tls` en `fly.toml`); aquí llega en claro
// por la red interna. La autenticación es una sola credencial compartida con Stalwart
// (`OUTBOUND_RELAY_SECRET`): la identidad del usuario ya la comprobó Stalwart con
// `mustMatchSender`, y aquí se comprueba además que el `From` visible coincida con el
// sobre, porque Stalwart sólo mira el sobre.

import { createHash, timingSafeEqual } from "node:crypto";
import { SMTPServer, type SMTPServerSession } from "smtp-server";
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

export type RelayResult =
  | { ok: true; sesMessageId: string; duplicate?: boolean; conversationId?: string }
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
  for (const r of rcpts) {
    const bad = checkRecipient(sender, r);
    if (bad) return { ok: false, ...bad };
  }

  const messageId = (parsed.messageId ?? "").trim();
  const subject = parsed.subject ?? "";

  // Idempotencia: si SES aceptó pero el 250 no le llegó a Stalwart (deploy, red),
  // Stalwart reintenta el mismo mensaje. Sin esto el destinatario lo recibiría dos
  // veces y la cuota se cobraría doble. Se reclama ANTES de enviar —así dos reintentos
  // simultáneos tampoco salen los dos— y se suelta si el envío falla.
  const idemKey = createHash("sha256")
    .update(`${domain.id}\n${messageId || createHash("sha256").update(raw).digest("hex")}\n${[...rcpts].sort().join(",")}`)
    .digest("hex");
  if (!claimOnce("relay-sent", idemKey, 3)) {
    log("info", "ses", "Relay: mensaje repetido, ya había salido", { domainId: domain.id, messageId });
    return { ok: true, sesMessageId: "", duplicate: true };
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
    sesMessageId = await deps.sendRaw(prepareForSes(raw), address, rcpts, getConfigSetName(domain.domain));
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
  logOutbound(domain.id, address, rcpts.join(", "), subject, html || text, sesMessageId, limits.logDays);
  emitEvent(domain.id, "email.sent", {
    to: rcpts[0], recipients: rcpts, subject, from: address, messageId, sesMessageId, via: "mailbox",
  });

  let conversationId: string | undefined;
  try {
    conversationId = threadIntoBandeja({ domain, address, parsed, rcpts, messageId, sesMessageId, text, html, subject });
  } catch (err) {
    log("error", "mesa", "Relay: salió pero no se pudo guardar en la Bandeja", { domainId: domain.id, messageId, error: String(err) });
  }

  log("info", "ses", "Relay: enviado desde buzón", {
    domainId: domain.id, from: address, recipients: rcpts.length, messageId, sesMessageId,
    sendsUsed: reserved, sendsLimit: limits.sends, conversationId,
  });
  return { ok: true, sesMessageId, conversationId };
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

// --- Transporte SMTP ---

function reject(r: SmtpReject): Error {
  const err = new Error(r.message) as Error & { responseCode: number };
  err.responseCode = r.code;
  return err;
}

function secretMatches(given: string, expected: string): boolean {
  const a = Buffer.from(given ?? "", "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Arranca el listener. Sin `OUTBOUND_RELAY_SECRET` igual escucha —para que el chequeo
 * TCP de Fly pase y un deploy no se trabe— pero rechaza toda autenticación: sin
 * secreto, cerrado. Y sin autenticarse no se acepta ni un MAIL FROM.
 */
export function startOutboundRelay(o: { port?: number; host?: string; secret?: string; deps?: RelayDeps } = {}): SMTPServer {
  const secret = o.secret ?? process.env.OUTBOUND_RELAY_SECRET ?? "";
  const user = process.env.OUTBOUND_RELAY_USER ?? "stalwart";
  const deps = o.deps ?? defaultDeps;

  const server = new SMTPServer({
    name: "relay.mailmask.studio",
    banner: "MailMask relay",
    // El TLS lo termina el borde de Fly; aquí no hay certificado ni STARTTLS que ofrecer.
    secure: false,
    disabledCommands: ["STARTTLS"],
    allowInsecureAuth: true,
    authMethods: ["PLAIN", "LOGIN"],
    authOptional: false,
    size: MAX_RAW_MESSAGE_BYTES,
    disableReverseLookup: true,
    logger: false,
    onAuth(auth, _session, cb) {
      if (!secret || auth.username !== user || !secretMatches(auth.password ?? "", secret)) {
        log("warn", "ses", "Relay: autenticación rechazada", { user: auth.username });
        return cb(reject({ code: 535, message: "5.7.8 Credenciales inválidas" }));
      }
      cb(null, { user });
    },
    onMailFrom(address, _session, cb) {
      // `<>` (avisos del servidor) se decide en DATA con el From del mensaje.
      if (!address.address) return cb();
      const s = resolveSender(address.address);
      cb("code" in s ? reject(s) : undefined);
    },
    onRcptTo(address, session: SMTPServerSession, cb) {
      if (session.envelope.rcptTo.length >= MAX_RELAY_RECIPIENTS) {
        return cb(reject({ code: 452, message: "4.5.3 Demasiados destinatarios en esta transacción" }));
      }
      const from = session.envelope.mailFrom && session.envelope.mailFrom.address;
      if (!from) return cb();
      const s = resolveSender(from);
      if ("code" in s) return cb(reject(s));
      const bad = checkRecipient(s, address.address);
      cb(bad ? reject(bad) : undefined);
    },
    onData(stream, session, cb) {
      const chunks: Buffer[] = [];
      stream.on("data", (c: Buffer) => chunks.push(c));
      stream.on("error", (err) => cb(reject({ code: 451, message: `4.3.0 ${String(err)}` })));
      stream.on("end", async () => {
        if ((stream as any).sizeExceeded) {
          return cb(reject({ code: 552, message: "5.3.4 El correo excede el tamaño máximo" }));
        }
        try {
          const r = await relayOutbound({
            mailFrom: session.envelope.mailFrom ? session.envelope.mailFrom.address : "",
            rcptTo: session.envelope.rcptTo.map((r) => r.address),
          }, Buffer.concat(chunks).toString("utf8"), deps);
          if (r.ok) return cb(null, `2.0.0 Ok: queued as ${r.sesMessageId || "duplicate"}`);
          cb(reject(r));
        } catch (err) {
          // Lo inesperado se reintenta: fallar seguro es no perder el correo.
          log("error", "ses", "Relay: error inesperado", { error: String(err) });
          cb(reject({ code: 451, message: "4.3.0 Error temporal; se reintentará" }));
        }
      });
    },
  });

  server.on("error", (err) => log("error", "ses", "Relay SMTP: error del listener", { error: String(err) }));
  const port = o.port ?? parseInt(process.env.OUTBOUND_RELAY_PORT ?? "2525", 10);
  server.listen(port, o.host ?? "0.0.0.0");
  if (!secret) log("warn", "ses", "Relay SMTP sin OUTBOUND_RELAY_SECRET: escucha pero rechaza toda autenticación", { port });
  return server;
}
