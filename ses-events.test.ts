// Rebotes y quejas de salida. La lógica se prueba directo en registrarEventoSes
// (la firma SNS real necesita el certificado de Amazon); el webhook se prueba
// sólo en lo que se puede sin firma: que rechaza lo que no viene firmado.

import { describe, it, before } from "node:test";
import assert from "node:assert/strict";

import { app, registrarEventoSes } from "./main.ts";
import { createUser, createDomain, isSuppressed } from "./db.ts";

const uid = Math.random().toString(36).slice(2, 8);
let plainId = "";
let hyphenId = "";

function evento(tipo: "Bounce" | "Complaint", source: string, email: string, extra: Record<string, unknown> = {}) {
  const base: any = { notificationType: tipo, mail: { source, tags: {} } };
  if (tipo === "Bounce") base.bounce = { bounceType: "Permanent", bouncedRecipients: [{ emailAddress: email }], ...extra };
  else base.complaint = { complainedRecipients: [{ emailAddress: email }] };
  return base;
}

describe("registrarEventoSes", () => {
  before(() => {
    createUser(`ev-${uid}@example.com`, "x");
    plainId = createDomain(`ev-${uid}@example.com`, `ev${uid}.com`, [], "t").id;
    hyphenId = createDomain(`ev-${uid}@example.com`, `mi-marca-${uid}.com`, [], "t").id;
  });

  it("un rebote Permanent suprime al destinatario", async () => {
    const r = await registrarEventoSes(evento("Bounce", `hola@ev${uid}.com`, "Muerto@Example.com"));
    assert.equal(r.suppressed, 1);
    assert.ok(isSuppressed(plainId, "muerto@example.com"));
  });

  it("un rebote Transient no suprime", async () => {
    const r = await registrarEventoSes(evento("Bounce", `hola@ev${uid}.com`, "lleno@example.com", { bounceType: "Transient" }));
    assert.equal(r.suppressed, 0);
    assert.ok(!isSuppressed(plainId, "lleno@example.com"));
  });

  it("una queja suprime", async () => {
    const r = await registrarEventoSes(evento("Complaint", `hola@ev${uid}.com`, "quejoso@example.com"));
    assert.equal(r.suppressed, 1);
    assert.ok(isSuppressed(plainId, "quejoso@example.com"));
  });

  it("resuelve un dominio con guión por el remitente, no por el config set", async () => {
    const msg = evento("Bounce", `Ventas <ventas@mi-marca-${uid}.com>`, "nadie@example.com");
    msg.mail.tags = { "ses:configuration-set": [`mailmask-mi-marca-${uid}-com`] };
    const r = await registrarEventoSes(msg);
    assert.equal(r.suppressed, 1);
    assert.ok(isSuppressed(hyphenId, "nadie@example.com"));
  });

  it("ignora dominios que no son nuestros", async () => {
    const r = await registrarEventoSes(evento("Bounce", "x@ajeno.example", "a@example.com"));
    assert.equal(r.suppressed, 0);
  });
});

describe("POST /api/webhooks/ses-events", () => {
  const post = (body: unknown) => app.fetch(new Request("http://localhost/api/webhooks/ses-events", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  }));

  it("rechaza un mensaje sin firma con 400 y no suprime", async () => {
    const res = await post({ Type: "Notification", Message: JSON.stringify(evento("Bounce", `hola@ev${uid}.com`, "falso@example.com")) });
    assert.equal(res.status, 400);
    assert.ok(!isSuppressed(plainId, "falso@example.com"));
  });

  it("rechaza una firma inválida con 403", async () => {
    const res = await post({
      Type: "Notification", MessageId: "m", Timestamp: "t", TopicArn: "arn:aws:sns:us-east-1:1:x",
      Message: "{}", Signature: "AAAA", SignatureVersion: "1",
      SigningCertURL: "https://evil.example.com/cert.pem",
    });
    assert.equal(res.status, 403);
  });

  it("no confirma una suscripción sin firma", async () => {
    const res = await post({ Type: "SubscriptionConfirmation", SubscribeURL: "https://sns.us-east-1.amazonaws.com/confirm" });
    assert.equal(res.status, 400);
  });
});
