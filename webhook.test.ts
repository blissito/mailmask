import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  isWebhookProcessed, markWebhookProcessed, isMessageProcessed, markMessageProcessed,
  chargeEventKey, isChargeFailureWarned, markChargeFailureWarned,
} from "./db.ts";

// --- HMAC signature computation ---

async function computeHmac(secret: string, dataId: string, requestId: string, ts: string): Promise<string> {
  const manifest = `id:${dataId};request-id:${requestId};ts:${ts};`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(manifest));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

describe("HMAC signature", () => {
  it("computation is deterministic", async () => {
    const sig1 = await computeHmac("test-secret-123", "12345", "req-1", "1700000000");
    const sig2 = await computeHmac("test-secret-123", "12345", "req-1", "1700000000");
    assert.equal(sig1, sig2);
  });

  it("changes with different data", async () => {
    const sig1 = await computeHmac("test-secret-123", "12345", "req-1", "1700000000");
    const sig2 = await computeHmac("test-secret-123", "99999", "req-1", "1700000000");
    assert.notEqual(sig1, sig2);
  });

  it("changes with different secret", async () => {
    const sig1 = await computeHmac("secret-a", "12345", "req-1", "1700000000");
    const sig2 = await computeHmac("secret-b", "12345", "req-1", "1700000000");
    assert.notEqual(sig1, sig2);
  });
});

describe("Webhook idempotency", () => {
  it("not processed initially", () => {
    const id = `test-webhook-${crypto.randomUUID()}`;
    assert.equal(isWebhookProcessed(id), false);
  });

  it("processed after marking", () => {
    const id = `test-webhook-${crypto.randomUUID()}`;
    markWebhookProcessed(id);
    assert.equal(isWebhookProcessed(id), true);
  });
});

describe("SNS message dedup", () => {
  it("not processed initially", () => {
    const id = `test-sns-${crypto.randomUUID()}`;
    assert.equal(isMessageProcessed(id), false);
  });

  it("processed after marking", () => {
    const id = `test-sns-${crypto.randomUUID()}`;
    markMessageProcessed(id);
    assert.equal(isMessageProcessed(id), true);
  });
});

describe("Claves de cobro", () => {
  // Estas claves son el contrato de idempotencia del libro mayor. Se prueban aquí, sin
  // HTTP, porque son lo único que impide que un reintento de MercadoPago duplique un
  // cargo o le mande al cliente el mismo aviso tres veces.

  it("un reintento del mismo cargo produce la misma clave", () => {
    const ap = { id: 4001, status: "processed", payment: { id: 77001, status: "approved" } };
    assert.equal(chargeEventKey(ap), chargeEventKey({ ...ap, retry_attempt: 2 }));
  });

  it("un rechazo y su reintento aprobado son eventos distintos", () => {
    // Si compartieran clave, el cobro exitoso se descartaría como duplicado y al
    // cliente se le cobraría sin extenderle el periodo.
    const rechazado = { id: 4002, status: "processed", payment: { id: 77002, status: "rejected" } };
    const aprobado = { id: 4003, status: "processed", payment: { id: 77003, status: "approved" } };
    assert.notEqual(chargeEventKey(rechazado), chargeEventKey(aprobado));
  });

  it("dos cobros distintos del mismo preapproval no colisionan", () => {
    const agosto = { id: 5001, status: "processed", payment: { id: 88001, status: "approved" } };
    const septiembre = { id: 5002, status: "processed", payment: { id: 88002, status: "approved" } };
    assert.notEqual(chargeEventKey(agosto), chargeEventKey(septiembre));
  });

  it("sobrevive a un payload sin payment", () => {
    assert.equal(chargeEventKey({ id: 6001, status: "recycling" }), "ap:6001:recycling:0");
  });
});

describe("Limitador del aviso de cobro fallido", () => {
  it("solo deja pasar el primero", async () => {
    // MercadoPago dispara varios eventos de rechazo por ciclo; sin esto una tarjeta
    // vencida se convierte en una ristra de correos y en una queja de spam.
    const email = `fallido-${crypto.randomUUID()}@test.com`;
    assert.equal(isChargeFailureWarned(email), false);
    markChargeFailureWarned(email);
    assert.equal(isChargeFailureWarned(email), true);
  });

  it("es por usuario, no global", () => {
    const a = `fallido-a-${crypto.randomUUID()}@test.com`;
    const b = `fallido-b-${crypto.randomUUID()}@test.com`;
    markChargeFailureWarned(a);
    assert.equal(isChargeFailureWarned(b), false);
  });
});
