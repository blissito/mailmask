import { assertEquals, assertExists } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { _setKv } from "./db.ts";

// Use in-memory KV for test isolation
const testKv = await Deno.openKv(":memory:");
_setKv(testKv);

import { evaluateRules } from "./forwarding.ts";
import { enqueueForward, dequeueForward, listForwardQueue, moveToDeadLetter, getQueueDepth, getDeadLetterCount, _getKv, type ForwardQueueItem } from "./db.ts";
import type { Rule } from "./db.ts";

// --- evaluateRules tests ---

function makeRule(overrides: Partial<Rule>): Rule {
  return {
    id: "r1",
    domainId: "d1",
    field: "from",
    match: "contains",
    value: "test",
    action: "forward",
    target: "dest@example.com",
    priority: 0,
    enabled: true,
    createdAt: new Date().toISOString(),
    ...overrides,
  };
}

Deno.test("evaluateRules - contains match", async () => {
  const rules = [makeRule({ field: "from", match: "contains", value: "spam" })];
  const result = await evaluateRules(rules, { to: "a@b.com", from: "spammer@evil.com", subject: "hi" });
  assertExists(result);
  assertEquals(result!.id, "r1");
});

Deno.test("evaluateRules - contains no match", async () => {
  const rules = [makeRule({ field: "from", match: "contains", value: "spam" })];
  const result = await evaluateRules(rules, { to: "a@b.com", from: "friend@good.com", subject: "hi" });
  assertEquals(result, null);
});

Deno.test("evaluateRules - equals match (case insensitive)", async () => {
  const rules = [makeRule({ field: "subject", match: "equals", value: "HELLO" })];
  const result = await evaluateRules(rules, { to: "a@b.com", from: "x@y.com", subject: "hello" });
  assertExists(result);
});

Deno.test("evaluateRules - equals no match (partial)", async () => {
  const rules = [makeRule({ field: "subject", match: "equals", value: "hello" })];
  const result = await evaluateRules(rules, { to: "a@b.com", from: "x@y.com", subject: "hello world" });
  assertEquals(result, null);
});

Deno.test("evaluateRules - regex match", async () => {
  const rules = [makeRule({ field: "from", match: "regex", value: "^admin@" })];
  const result = await evaluateRules(rules, { to: "a@b.com", from: "admin@example.com", subject: "hi" });
  assertExists(result);
});

Deno.test("evaluateRules - regex no match", async () => {
  const rules = [makeRule({ field: "from", match: "regex", value: "^admin@" })];
  const result = await evaluateRules(rules, { to: "a@b.com", from: "user@example.com", subject: "hi" });
  assertEquals(result, null);
});

Deno.test("evaluateRules - invalid regex doesn't crash", async () => {
  const rules = [makeRule({ field: "from", match: "regex", value: "[invalid" })];
  const result = await evaluateRules(rules, { to: "a@b.com", from: "admin@example.com", subject: "hi" });
  assertEquals(result, null);
});

Deno.test("evaluateRules - disabled rule skipped", async () => {
  const rules = [makeRule({ field: "from", match: "contains", value: "spam", enabled: false })];
  const result = await evaluateRules(rules, { to: "a@b.com", from: "spammer@evil.com", subject: "hi" });
  assertEquals(result, null);
});

Deno.test("evaluateRules - priority order (first match wins)", async () => {
  const rules = [
    makeRule({ id: "r1", field: "from", match: "contains", value: "user", priority: 0, action: "discard" }),
    makeRule({ id: "r2", field: "from", match: "contains", value: "user", priority: 1, action: "forward" }),
  ];
  const result = await evaluateRules(rules, { to: "a@b.com", from: "user@x.com", subject: "hi" });
  assertEquals(result!.id, "r1");
  assertEquals(result!.action, "discard");
});

// --- Queue tests ---

Deno.test("enqueue and dequeue forward", async () => {
  const item = await enqueueForward({
    rawContent: "raw email content",
    from: "sender@test.com",
    to: "dest@test.com",
    domainId: "test-domain",
    domainName: "test.com",
    originalTo: "alias@test.com",
    subject: "Test subject",
    logDays: 15,
  }, "SES throttle");

  assertExists(item.id);
  assertEquals(item.attemptCount, 0);
  assertEquals(item.lastError, "SES throttle");

  const queue = await listForwardQueue();
  const found = queue.find((q) => q.id === item.id);
  assertExists(found);

  await dequeueForward(item.id);
  const afterDequeue = await listForwardQueue();
  assertEquals(afterDequeue.find((q) => q.id === item.id), undefined);
});

Deno.test("moveToDeadLetter removes from queue", async () => {
  const item = await enqueueForward({
    rawContent: "raw",
    from: "a@b.com",
    to: "c@d.com",
    domainId: "d1",
    domainName: "b.com",
    originalTo: "x@b.com",
    subject: "test",
    logDays: 15,
  }, "error");

  await moveToDeadLetter({ ...item, attemptCount: 3 });

  const queue = await listForwardQueue();
  assertEquals(queue.find((q) => q.id === item.id), undefined);

  // Verify it's in dead-letter
  const kv = _getKv();
  const dl = await kv.get(["dead-letter", item.id]);
  assertExists(dl.value);

  // Cleanup
  await kv.delete(["dead-letter", item.id]);
});
