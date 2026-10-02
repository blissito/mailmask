// Relay LMTP de salida de los buzones. Corre en la caja de Stalwart, SÓLO en 127.0.0.1.
//
// La ruta `ses` de Stalwart entrega aquí (LMTP, sin TLS: es loopback) y este proceso
// hace `POST https://www.mailmask.studio/api/internal/outbound` firmado con HMAC. La app
// decide (buzón válido, supresión, tope diario), manda por SES, registra y engancha la
// Bandeja (ver `outbound-relay.ts` en la raíz del repo).
//
// LMTP y no SMTP porque contesta POR DESTINATARIO: un suprimido se rechaza solo y el
// resto sale. Y la traducción de respuestas falla SEGURO: todo lo que no sea una decisión
// explícita de la app (red, timeout, 5xx, firma rechazada) es `451`, así que el mensaje
// se queda en la cola de Stalwart y se reintenta. Nunca se pierde ni se va directo a SES.
//
// Entorno (archivo /etc/mailmask-relay.env):
//   OUTBOUND_RELAY_SECRET   firma HMAC hacia la app y clave de AUTH desde Stalwart
//   RELAY_AUTH_USER         usuario de AUTH (default stalwart)
//   RELAY_REQUIRE_AUTH      "false" si Stalwart no autentica por LMTP (sigue siendo loopback)
//   RELAY_LISTEN_HOST       default 127.0.0.1 — no cambiarlo
//   RELAY_PORT              default 2525
//   RELAY_APP_URL           default https://www.mailmask.studio/api/internal/outbound
//   RELAY_TIMEOUT_MS        default 30000

import { createHmac, timingSafeEqual } from "node:crypto";
import { pathToFileURL } from "node:url";
import { SMTPServer } from "smtp-server";

const MAX_BYTES = 9 * 1024 * 1024; // el mismo tope que la app (MAX_RAW_MESSAGE_BYTES)

function log(level, msg, extra = {}) {
  // stdout → journal (`journalctl -u mailmask-outbound-relay`).
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, msg, ...extra }));
}

function smtpError(code, message) {
  const err = new Error(message);
  err.responseCode = code;
  return err;
}

const TEMPFAIL = () => smtpError(451, "4.4.0 MailMask no respondió; se reintentará");

export function sign(secret, timestamp, body) {
  return "sha256=" + createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
}

/**
 * Traduce la respuesta de la app a una respuesta LMTP por destinatario.
 * Devuelve un arreglo (una entrada por RCPT, en orden) o un Error para todos.
 */
export function translate(status, data, rcpts) {
  if (status === 200 && data && typeof data.perRcpt === "object") {
    return rcpts.map((r) => {
      const v = data.perRcpt[r.toLowerCase()];
      if (v === "ok") return `2.0.0 Ok: ${data.sesMessageId || "sent"}`;
      const m = typeof v === "string" && v.match(/^rejected:(\d{3}) ?(.*)$/);
      if (m) return smtpError(Number(m[1]), m[2] || "5.0.0 Rechazado");
      // La app no habló de este destinatario: mejor reintentar que inventar.
      return TEMPFAIL();
    });
  }
  // Política sobre el mensaje entero: la app manda el código SMTP.
  if (status === 422 && data && /^[45]\d\d$/.test(String(data.code))) {
    return smtpError(Number(data.code), String(data.error ?? "Rechazado por MailMask"));
  }
  return TEMPFAIL();
}

export function startRelay(o = {}) {
  const env = process.env;
  const secret = o.secret ?? env.OUTBOUND_RELAY_SECRET ?? "";
  const user = o.user ?? env.RELAY_AUTH_USER ?? "stalwart";
  const requireAuth = o.requireAuth ?? env.RELAY_REQUIRE_AUTH !== "false";
  const appUrl = o.appUrl ?? env.RELAY_APP_URL ?? "https://www.mailmask.studio/api/internal/outbound";
  const timeoutMs = o.timeoutMs ?? Number(env.RELAY_TIMEOUT_MS ?? 30000);
  const host = o.host ?? env.RELAY_LISTEN_HOST ?? "127.0.0.1";
  const port = o.port ?? Number(env.RELAY_PORT ?? 2525);
  if (!secret) throw new Error("Falta OUTBOUND_RELAY_SECRET");

  const server = new SMTPServer({
    lmtp: true,
    name: "mailmask-relay",
    banner: "MailMask relay",
    secure: false,
    disabledCommands: ["STARTTLS"],
    allowInsecureAuth: true, // loopback
    authOptional: !requireAuth,
    authMethods: ["PLAIN", "LOGIN"],
    size: MAX_BYTES,
    disableReverseLookup: true,
    logger: false,
    onAuth(auth, _session, cb) {
      const a = Buffer.from(auth.password ?? "");
      const b = Buffer.from(secret);
      if (auth.username !== user || a.length !== b.length || !timingSafeEqual(a, b)) {
        log("warn", "AUTH rechazado", { user: auth.username });
        return cb(smtpError(535, "5.7.8 Credenciales inválidas"));
      }
      cb(null, { user });
    },
    onData(stream, session, cb) {
      const chunks = [];
      let done = false;
      const finish = (err, res) => { if (!done) { done = true; cb(err, res); } };
      stream.on("data", (c) => chunks.push(c));
      stream.on("error", () => finish(TEMPFAIL()));
      stream.on("end", async () => {
        if (stream.sizeExceeded) return finish(smtpError(552, "5.3.4 El correo excede el tamaño máximo"));
        const rcpts = session.envelope.rcptTo.map((r) => r.address);
        const body = JSON.stringify({
          mailFrom: session.envelope.mailFrom ? session.envelope.mailFrom.address : "",
          rcptTo: rcpts,
          raw: Buffer.concat(chunks).toString("base64"),
        });
        const ts = String(Math.floor(Date.now() / 1000));
        let status = 0;
        let data = null;
        try {
          const res = await fetch(appUrl, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-mailmask-timestamp": ts,
              "x-mailmask-signature": sign(secret, ts, body),
            },
            body,
            redirect: "error", // un 301 perdería el cuerpo; mejor reintentar y que se note
            signal: AbortSignal.timeout(timeoutMs),
          });
          status = res.status;
          data = await res.json().catch(() => null);
        } catch (err) {
          log("error", "La app no respondió", { error: String(err), rcpts: rcpts.length });
          return finish(TEMPFAIL());
        }
        const out = translate(status, data, rcpts);
        log(status === 200 ? "info" : "warn", "Entregado a MailMask", {
          status, rcpts: rcpts.length, sesMessageId: data?.sesMessageId, error: data?.error,
        });
        if (out instanceof Error) return finish(out);
        finish(null, out);
      });
    },
  });
  server.on("error", (err) => log("error", "Error del listener", { error: String(err) }));
  server.listen(port, host, () => log("info", "Escuchando", { host, port, appUrl, requireAuth }));
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = startRelay();
  for (const sig of ["SIGTERM", "SIGINT"]) process.on(sig, () => server.close(() => process.exit(0)));
}
