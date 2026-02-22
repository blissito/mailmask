import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { isWebhookProcessed, markWebhookProcessed, isMessageProcessed, markMessageProcessed } from "./db.ts";

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
