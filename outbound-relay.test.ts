// Salida única de los buzones (outbound-relay.ts): lo que manda Apple Mail vía Stalwart
// pasa por la app — cuota, supresión, log y Bandeja — y no directo a SES.
// SES es un doble inyectado; la ruta interna se ejercita con Requests firmados de verdad.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";

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
    assert.deepEqual(r.perRcpt, { "cliente@gmail.com": "ok", "oculto@x.com": "ok" });

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

  it("supresión por destinatario: el suprimido se rechaza solo y el resto sale", async () => {
    db.addSuppression(domainId, "rebota@gmail.com", "bounce");
    const n = sent.length;
    const solo = await relay.relayOutbound(env(["rebota@gmail.com"]), mime({ to: "rebota@gmail.com" }), deps);
    assert.equal(solo.ok, true);
    assert.match(solo.perRcpt["rebota@gmail.com"], /^rejected:550 .*supresión/);
    assert.equal(sent.length, n, "nadie aceptado: no sale nada");

    const mixto = await relay.relayOutbound(env(["rebota@gmail.com", "cliente@gmail.com"]),
      mime({ to: "rebota@gmail.com, cliente@gmail.com" }), deps);
    assert.equal(mixto.perRcpt["cliente@gmail.com"], "ok");
    assert.match(mixto.perRcpt["rebota@gmail.com"], /^rejected:550/);
    assert.deepEqual(sent[sent.length - 1].destinations, ["cliente@gmail.com"]);
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

// --- Ruta interna: POST /api/internal/outbound ---

describe("Relay de salida: ruta interna firmada", () => {
  const SECRET = "s3cret-relay";
  const prev = process.env.OUTBOUND_RELAY_SECRET;
  before(() => { process.env.OUTBOUND_RELAY_SECRET = SECRET; });
  after(() => { if (prev === undefined) delete process.env.OUTBOUND_RELAY_SECRET; else process.env.OUTBOUND_RELAY_SECRET = prev; });

  function req(payload: unknown, o: { secret?: string; ts?: number; cookie?: string; signature?: string } = {}) {
    const body = JSON.stringify(payload);
    const ts = String(o.ts ?? Math.floor(Date.now() / 1000));
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "x-mailmask-timestamp": ts,
      "x-mailmask-signature": o.signature ?? relay.signRelayBody(o.secret ?? SECRET, ts, body),
    };
    if (o.cookie) headers.cookie = o.cookie;
    return new Request("http://localhost/api/internal/outbound", { method: "POST", headers, body });
  }
  const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64");

  it("firma con otra clave: 401 y nada sale", async () => {
    const n = sent.length;
    const res = await relay.handleInternalOutbound(req({ mailFrom: ana, rcptTo: ["cliente@gmail.com"], raw: b64(mime()) }, { secret: "otra" }), deps);
    assert.equal(res.status, 401);
    assert.equal(sent.length, n);
  });

  it("marca de tiempo vencida (> 300 s): 401 aunque la firma cuadre", async () => {
    const res = await relay.handleInternalOutbound(
      req({ mailFrom: ana, rcptTo: ["cliente@gmail.com"], raw: b64(mime()) }, { ts: Math.floor(Date.now() / 1000) - 301 }), deps);
    assert.equal(res.status, 401);
  });

  it("sin OUTBOUND_RELAY_SECRET en el servidor: cerrado", async () => {
    delete process.env.OUTBOUND_RELAY_SECRET;
    try {
      const res = await relay.handleInternalOutbound(req({ mailFrom: ana, rcptTo: ["c@gmail.com"], raw: b64(mime()) }, { secret: "" }), deps);
      assert.equal(res.status, 401);
    } finally {
      process.env.OUTBOUND_RELAY_SECRET = SECRET;
    }
  });

  it("firmada: 200 con resultado por destinatario", async () => {
    const res = await relay.handleInternalOutbound(
      req({ mailFrom: ana, rcptTo: ["cliente@gmail.com", "rebota@gmail.com"], raw: b64(mime({ messageId: "<route-1@apple.test>" })) }), deps);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.perRcpt["cliente@gmail.com"], "ok");
    assert.match(data.perRcpt["rebota@gmail.com"], /^rejected:550/);
    assert.match(data.sesMessageId, /^ses-/);
  });

  it("idempotente: el mismo mensaje otra vez no sale de nuevo", async () => {
    const payload = { mailFrom: ana, rcptTo: ["cliente@gmail.com"], raw: b64(mime({ messageId: "<route-2@apple.test>" })) };
    await relay.handleInternalOutbound(req(payload), deps);
    const n = sent.length;
    const res = await relay.handleInternalOutbound(req(payload), deps);
    const data = await res.json();
    assert.equal(res.status, 200);
    assert.equal(data.duplicate, true);
    assert.equal(data.perRcpt["cliente@gmail.com"], "ok");
    assert.equal(sent.length, n);
  });

  it("política sobre el mensaje entero: 422 con el código SMTP (From ≠ sobre → 550)", async () => {
    const res = await relay.handleInternalOutbound(
      req({ mailFrom: ana, rcptTo: ["cliente@gmail.com"], raw: b64(mime({ from: `hola@${domainName}` })) }), deps);
    assert.equal(res.status, 422);
    assert.equal((await res.json()).code, 550);
  });

  it("SES caído: 503 (la caja lo vuelve 451 y Stalwart reintenta)", async () => {
    sesBehavior = "transient";
    try {
      const res = await relay.handleInternalOutbound(
        req({ mailFrom: ana, rcptTo: ["cliente@gmail.com"], raw: b64(mime()) }), deps);
      assert.equal(res.status, 503);
    } finally {
      sesBehavior = "ok";
    }
  });

  it("montada en la app: exenta de CSRF y una cookie no sirve de nada", async () => {
    const { app } = await import("./main.ts");
    const res = await app.fetch(req({ mailFrom: ana, rcptTo: ["c@gmail.com"], raw: b64(mime()) },
      { signature: "sha256=00", cookie: "token=algo; csrf_token=x" }));
    assert.equal(res.status, 401, "ni 403 de CSRF ni sesión por cookie: sólo la firma");
  });
});
