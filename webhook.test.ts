import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { isWebhookProcessed, markWebhookProcessed, isMessageProcessed, markMessageProcessed, _getKv } from "./db.ts";

// --- HMAC signature computation (extracted from main.ts for testing) ---

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

Deno.test("HMAC signature computation is deterministic", async () => {
  const secret = "test-secret-123";
  const sig1 = await computeHmac(secret, "12345", "req-1", "1700000000");
  const sig2 = await computeHmac(secret, "12345", "req-1", "1700000000");
  assertEquals(sig1, sig2);
});

Deno.test("HMAC signature changes with different data", async () => {
  const secret = "test-secret-123";
  const sig1 = await computeHmac(secret, "12345", "req-1", "1700000000");
  const sig2 = await computeHmac(secret, "99999", "req-1", "1700000000");
  assertEquals(sig1 !== sig2, true);
});

Deno.test("HMAC signature changes with different secret", async () => {
  const sig1 = await computeHmac("secret-a", "12345", "req-1", "1700000000");
  const sig2 = await computeHmac("secret-b", "12345", "req-1", "1700000000");
  assertEquals(sig1 !== sig2, true);
});

// --- Webhook idempotency ---

Deno.test("webhook dedup - not processed initially", async () => {
  const id = `test-webhook-${crypto.randomUUID()}`;
  const result = await isWebhookProcessed(id);
  assertEquals(result, false);
});

Deno.test("webhook dedup - processed after marking", async () => {
  const id = `test-webhook-${crypto.randomUUID()}`;
  await markWebhookProcessed(id);
  const result = await isWebhookProcessed(id);
  assertEquals(result, true);

  // Cleanup
  const kv = _getKv();
  await kv.delete(["webhook-processed", id]);
});

// --- SNS message dedup ---

Deno.test("SNS dedup - not processed initially", async () => {
  const id = `test-sns-${crypto.randomUUID()}`;
  const result = await isMessageProcessed(id);
  assertEquals(result, false);
});

Deno.test("SNS dedup - processed after marking", async () => {
  const id = `test-sns-${crypto.randomUUID()}`;
  await markMessageProcessed(id);
  const result = await isMessageProcessed(id);
  assertEquals(result, true);

  // Cleanup
  const kv = _getKv();
  await kv.delete(["sns-processed", id]);
});
