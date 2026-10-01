// Salida única de los buzones (outbound-relay.ts): lo que manda Apple Mail vía Stalwart
// pasa por la app — cuota, supresión, log y Bandeja — y no directo a SES.
// SES es un doble inyectado; el transporte SMTP se ejercita con un socket de verdad.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import * as net from "node:net";

const suffix = Date.now();
const owner = `relay-${suffix}@example.com`;
const domainName = `relay-${suffix}.com`;
const ana = `ana@${domainName}`;

// deno-lint-ignore no-explicit-any
let db: any;
// deno-lint-ignore no-explicit-any
let relay: any;
// deno-lint-ignore no-explicit-any
let sqlite: any;
let domainId = "";

const sent: { raw: string; source: string; destinations: string[]; configSet?: string }[] = [];
let sesBehavior: "ok" | "transient" | "rejected" = "ok";
const deps = {
  sendRaw: async (raw: string, source: string, destinations: string[], configSet?: string) => {
    if (sesBehavior === "transient") throw Object.assign(new Error("Throttling"), { name: "Throttling" });
    if (sesBehavior === "rejected") throw Object.assign(new Error("Email address is not verified."), { name: "MessageRejected" });
    sent.push({ raw, source, destinations, configSet });
    return `ses-${crypto.randomUUID()}`;
  },
};

function mime(o: { from?: string; to?: string; cc?: string; bcc?: string; subject?: string; messageId?: string; inReplyTo?: string; body?: string; dkim?: boolean } = {}): string {
  const h = [
    ...(o.dkim ? ["DKIM-Signature: v=1; a=rsa-sha256; d=otro.com; b=abc", " def"] : []),
    `From: Ana <${o.from ?? ana}>`,
    `To: ${o.to ?? "cliente@gmail.com"}`,
    ...(o.cc ? [`Cc: ${o.cc}`] : []),
    ...(o.bcc ? [`Bcc: ${o.bcc}`] : []),
    `Subject: ${o.subject ?? "Cotización"}`,
    `Message-ID: ${o.messageId ?? `<${crypto.randomUUID()}@apple.test>`}`,
    ...(o.inReplyTo ? [`In-Reply-To: ${o.inReplyTo}`, `References: ${o.inReplyTo}`] : []),
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
  ];
  return [...h, "", o.body ?? "Hola, va la propuesta."].join("\r\n");
}

before(async () => {
  db = await import("./db.ts");
  relay = await import("./outbound-relay.ts");
  ({ sqlite } = await import("./pg.ts"));
  db.createUser(owner, "x");
  const d = db.createDomain(owner, domainName, ["dk"], "vf");
  domainId = d.id;
  sqlite.prepare("UPDATE domains SET verified = 1 WHERE id = ?").run(domainId);
  const addon = db.createAddon(owner, "domain", domainId);
  db.updateAddon(addon.id, { status: "active", currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString() });
  db.createAlias(domainId, "ana", []);
  sqlite.prepare("UPDATE alias SET mailbox_enabled = 1 WHERE domain_id = ? AND alias = 'ana'").run(domainId);
  db.createAlias(domainId, "hola", ["destino@example.com"]);
});

const env = (rcptTo: string[], mailFrom = ana) => ({ mailFrom, rcptTo });

describe("Relay de salida: lo que manda un buzón pasa por la app", () => {
  it("sale por SES limpio, cuenta un envío, queda en el log y abre conversación", async () => {
    sesBehavior = "ok";
    const before_ = db.getSendCount(domainId);
    const raw = mime({ dkim: true, bcc: "oculto@x.com", messageId: "<m1@apple.test>" });
    const r = await relay.relayOutbound(env(["cliente@gmail.com", "oculto@x.com"]), raw, deps);
    assert.equal(r.ok, true);

    const s = sent[sent.length - 1];
    assert.equal(s.source, ana);
    assert.deepEqual(s.destinations, ["cliente@gmail.com", "oculto@x.com"]);
    assert.equal(s.configSet, `mailmask-${domainName.replace(/\./g, "-")}`);
    // Doble firma DKIM = 554 de SES; Bcc en headers = la copia oculta deja de serlo.
    assert.doesNotMatch(s.raw, /DKIM-Signature/i);
    assert.doesNotMatch(s.raw, /^Bcc:/im);
    assert.match(s.raw, /^Message-ID: <m1@apple\.test>/m);

    assert.equal(db.getSendCount(domainId), before_ + 1, "un mensaje es un envío");

    const logRow = sqlite.prepare("SELECT * FROM email_logs WHERE domain_id = ? AND ses_message_id = ?").get(domainId, r.sesMessageId);
    assert.ok(logRow, "debe quedar en email_logs");
    assert.equal(logRow.status, "sent");

    const conv = db.getConversation(domainId, r.conversationId);
    assert.equal(conv.from, "cliente@gmail.com", "from = contacto externo");
    assert.equal(conv.to, ana, "to = nuestra máscara");
    assert.ok(conv.threadReferences.includes("<m1@apple.test>"));
    assert.ok(conv.threadReferences.includes(`<${r.sesMessageId}@email.amazonses.com>`));
    const msgs = db.listMessages(conv.id);
    assert.equal(msgs.length, 1);
    assert.equal(msgs[0].direction, "outbound");
    assert.equal(msgs[0].sesMessageId, r.sesMessageId);
  });

  it("la respuesta desde Apple Mail engancha en el hilo que abrió el entrante", async () => {
    const conv = db.createConversation({
      domainId, from: "lead@empresa.mx", to: ana, subject: "Duda", status: "open", priority: "normal",
      lastMessageAt: new Date().toISOString(), messageCount: 1, tags: [], threadReferences: ["<in-1@empresa.mx>"],
    });
    const r = await relay.relayOutbound(env(["lead@empresa.mx"]),
      mime({ to: "lead@empresa.mx", subject: "Re: Duda", inReplyTo: "<in-1@empresa.mx>", messageId: "<m2@apple.test>" }), deps);
    assert.equal(r.ok, true);
    assert.equal(r.conversationId, conv.id, "no abre conversación nueva");
    const after_ = db.getConversation(domainId, conv.id);
    assert.equal(after_.messageCount, 2);
    assert.ok(after_.threadReferences.includes("<m2@apple.test>"));
    assert.equal(db.listMessages(conv.id).at(-1).direction, "outbound");
  });

  it("un reintento de Stalwart del mismo mensaje no sale dos veces ni cobra doble", async () => {
    const raw = mime({ messageId: "<m3@apple.test>" });
    const first = await relay.relayOutbound(env(["cliente@gmail.com"]), raw, deps);
    const n = sent.length;
    const count = db.getSendCount(domainId);
    const again = await relay.relayOutbound(env(["cliente@gmail.com"]), raw, deps);
    assert.equal(first.ok, true);
    assert.equal(again.ok, true);
    assert.equal(again.duplicate, true);
    assert.equal(sent.length, n);
    assert.equal(db.getSendCount(domainId), count);
  });

  it("🔴 un From distinto del sobre es suplantar otra máscara: 550", async () => {
    const n = sent.length;
    const r = await relay.relayOutbound(env(["cliente@gmail.com"]), mime({ from: `hola@${domainName}` }), deps);
    assert.equal(r.ok, false);
    assert.equal(r.code, 550);
    assert.equal(sent.length, n);
  });

  it("una máscara sin buzón no puede usar el relay", async () => {
    const from = `hola@${domainName}`;
    const r = await relay.relayOutbound(env(["cliente@gmail.com"], from), mime({ from }), deps);
    assert.equal(r.ok, false);
    assert.equal(r.code, 550);
    assert.ok("code" in relay.resolveSender(`nadie@otro-${suffix}.com`));
  });

  it("aplica la lista de supresión", async () => {
    db.addSuppression(domainId, "rebota@gmail.com", "bounce");
    const n = sent.length;
    const r = await relay.relayOutbound(env(["rebota@gmail.com"]), mime({ to: "rebota@gmail.com" }), deps);
    assert.equal(r.ok, false);
    assert.equal(r.code, 550);
    assert.match(r.message, /supresión/);
    assert.equal(sent.length, n);
  });

  it("SES caído = 451 (Stalwart reintenta) y devuelve la cuota; el reintento sí sale", async () => {
    const raw = mime({ messageId: "<m4@apple.test>" });
    const count = db.getSendCount(domainId);
    sesBehavior = "transient";
    const r = await relay.relayOutbound(env(["cliente@gmail.com"]), raw, deps);
    assert.equal(r.ok, false);
    assert.equal(r.code, 451);
    assert.equal(db.getSendCount(domainId), count, "la cuota reservada se devuelve");

    sesBehavior = "ok";
    const retry = await relay.relayOutbound(env(["cliente@gmail.com"]), raw, deps);
    assert.equal(retry.ok, true);
    assert.notEqual(retry.duplicate, true, "el fallo soltó la marca de idempotencia");
  });

  it("un rechazo de SES es permanente: 554 y DSN", async () => {
    sesBehavior = "rejected";
    const r = await relay.relayOutbound(env(["cliente@gmail.com"]), mime(), deps);
    sesBehavior = "ok";
    assert.equal(r.ok, false);
    assert.equal(r.code, 554);
  });

  it("escribirle sólo a una máscara del propio dominio sale, pero no abre conversación de salida", async () => {
    const to = `hola@${domainName}`;
    const r = await relay.relayOutbound(env([to]), mime({ to }), deps);
    assert.equal(r.ok, true);
    assert.equal(r.conversationId, undefined);
  });

  it("con el tope diario lleno: 550 y nada sale", async () => {
    // Llena el contador del día hasta el tope del dominio activado.
    const limit = db.derechosDeDominio(db.getDomain(domainId), db.getUser(owner)).sends;
    while (db.getSendCount(domainId) < limit) db.incrementSendCount(domainId);
    const n = sent.length;
    const r = await relay.relayOutbound(env(["cliente@gmail.com"]), mime(), deps);
    assert.equal(r.ok, false);
    assert.equal(r.code, 550);
    assert.match(r.message, /Límite diario/);
    assert.equal(db.getSendCount(domainId), limit, "no se queda con la reserva");
    assert.equal(sent.length, n);
    sqlite.prepare("DELETE FROM send_counts WHERE domain_id = ?").run(domainId);
  });
});

// --- Transporte: un cliente SMTP mínimo sobre un socket real ---

function smtpSession(port: number) {
  const sock = net.connect(port, "127.0.0.1");
  let buf = "";
  const waiters: ((line: string) => void)[] = [];
  sock.on("data", (d) => {
    buf += d.toString();
    let i;
    // Una respuesta termina en una línea "NNN " (sin guion).
    while ((i = buf.search(/^\d{3} .*\r\n/m)) >= 0) {
      const end = buf.indexOf("\r\n", i) + 2;
      const resp = buf.slice(0, end);
      buf = buf.slice(end);
      waiters.shift()?.(resp);
    }
  });
  const next = () => new Promise<string>((r) => waiters.push(r));
  return {
    greeting: next(),
    async cmd(line: string): Promise<string> {
      const p = next();
      sock.write(line + "\r\n");
      return await p;
    },
    close: () => sock.destroy(),
  };
}

describe("Relay de salida: transporte SMTP", () => {
  // deno-lint-ignore no-explicit-any
  let server: any;
  // deno-lint-ignore no-explicit-any
  let closed: any;
  const port = 25000 + Math.floor(Math.random() * 20000);
  const portNoSecret = port + 1;
  const plain = (u: string, p: string) => Buffer.from(`\0${u}\0${p}`).toString("base64");

  before(() => {
    server = relay.startOutboundRelay({ port, host: "127.0.0.1", secret: "s3cret", deps });
    closed = relay.startOutboundRelay({ port: portNoSecret, host: "127.0.0.1", secret: "", deps });
  });
  after(async () => {
    await new Promise((r) => server.close(r));
    await new Promise((r) => closed.close(r));
  });

  it("sin autenticarse no acepta remitente, y con la clave mala da 535", async () => {
    const c = smtpSession(port);
    assert.match(await c.greeting, /^220/);
    assert.match(await c.cmd("EHLO stalwart"), /^250/);
    assert.match(await c.cmd(`MAIL FROM:<${ana}>`), /^530/);
    assert.match(await c.cmd(`AUTH PLAIN ${plain("stalwart", "mala")}`), /^535/);
    c.close();
  });

  it("sin OUTBOUND_RELAY_SECRET escucha pero cierra: 535 aun con cualquier clave", async () => {
    const c = smtpSession(portNoSecret);
    await c.greeting;
    await c.cmd("EHLO stalwart");
    assert.match(await c.cmd(`AUTH PLAIN ${plain("stalwart", "")}`), /^535/);
    c.close();
  });

  it("transacción completa: rechaza al remitente ajeno y al suprimido, entrega el resto con 250", async () => {
    const c = smtpSession(port);
    await c.greeting;
    await c.cmd("EHLO stalwart");
    assert.match(await c.cmd(`AUTH PLAIN ${plain("stalwart", "s3cret")}`), /^235/);
    assert.match(await c.cmd(`MAIL FROM:<hola@${domainName}>`), /^550/, "máscara sin buzón");
    assert.match(await c.cmd("RSET"), /^250/);
    assert.match(await c.cmd(`MAIL FROM:<${ana}>`), /^250/);
    assert.match(await c.cmd("RCPT TO:<rebota@gmail.com>"), /^550/, "suprimido: sólo ese destinatario");
    assert.match(await c.cmd("RCPT TO:<cliente@gmail.com>"), /^250/);
    assert.match(await c.cmd("DATA"), /^354/);
    const n = sent.length;
    const body = mime({ messageId: "<smtp-1@apple.test>" }).replace(/\r\n\./g, "\r\n..");
    const resp = await c.cmd(body + "\r\n.");
    assert.match(resp, /^250 .*queued as ses-/);
    assert.equal(sent.length, n + 1);
    assert.deepEqual(sent[sent.length - 1].destinations, ["cliente@gmail.com"]);
    c.close();
  });

  it("si SES falla, contesta 4xx: el mensaje se queda en la cola de Stalwart", async () => {
    const c = smtpSession(port);
    await c.greeting;
    await c.cmd("EHLO stalwart");
    await c.cmd(`AUTH PLAIN ${plain("stalwart", "s3cret")}`);
    await c.cmd(`MAIL FROM:<${ana}>`);
    await c.cmd("RCPT TO:<cliente@gmail.com>");
    await c.cmd("DATA");
    sesBehavior = "transient";
    const resp = await c.cmd(mime({ messageId: "<smtp-2@apple.test>" }) + "\r\n.");
    sesBehavior = "ok";
    assert.match(resp, /^451/);
    c.close();
  });
});
