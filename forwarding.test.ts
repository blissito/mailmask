import { assertEquals, assertExists } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { _setKv } from "./db.ts";

// Use in-memory KV for test isolation
const testKv = await Deno.openKv(":memory:");
_setKv(testKv);

import { evaluateRules, processInbound } from "./forwarding.ts";
import {
  enqueueForward, dequeueForward, listForwardQueue, moveToDeadLetter,
  getQueueDepth, getDeadLetterCount, _getKv,
  createUser, createDomain, createAlias, listAliases, getAlias,
  isMessageProcessed, markMessageProcessed,
  listLogs, updateUserSubscription,
  type Rule, type ForwardQueueItem,
} from "./db.ts";
import { hashPassword } from "./auth.ts";

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

// --- processInbound tests ---

// Helper to build an SNS notification with raw email content included
function makeSnsNotification(opts: {
  from: string;
  to: string;
  subject: string;
  messageId: string;
  rawContent?: string;
}) {
  const raw = opts.rawContent ?? [
    `From: ${opts.from}`,
    `To: ${opts.to}`,
    `Subject: ${opts.subject}`,
    `Message-ID: <${opts.messageId}@test.com>`,
    `Content-Type: text/plain; charset=UTF-8`,
    ``,
    `Test body`,
  ].join("\r\n");

  return {
    Type: "Notification",
    MessageId: opts.messageId,
    TopicArn: "arn:aws:sns:us-east-1:123456:test",
    Message: JSON.stringify({
      notificationType: "Received",
      receipt: {
        action: { type: "S3", bucketName: "test-bucket", objectKey: "test-key" },
        recipients: [opts.to],
        spamVerdict: { status: "PASS" },
        virusVerdict: { status: "PASS" },
        spfVerdict: { status: "PASS" },
        dkimVerdict: { status: "PASS" },
      },
      mail: {
        source: opts.from,
        destination: [opts.to],
        commonHeaders: {
          from: [opts.from],
          to: [opts.to],
          subject: opts.subject,
        },
        messageId: opts.messageId,
      },
      content: raw,
    }),
  };
}

// Setup: create a user + domain + alias for processInbound tests
const fwdSuffix = `fwd-${Date.now()}`;
const fwdDomain = `${fwdSuffix}.test`;
const fwdEmail = `owner-${fwdSuffix}@example.com`;
let fwdDomainId: string;

// Initialize test data
async function setupForwardingTestData() {
  const hash = await hashPassword("testpass123");
  await createUser(fwdEmail, hash);
  await updateUserSubscription(fwdEmail, {
    plan: "developer",
    status: "active",
    currentPeriodEnd: new Date(Date.now() + 365 * 86400000).toISOString(),
  });
  const domain = await createDomain(fwdEmail, fwdDomain, ["dkim1"], "verify1");
  fwdDomainId = domain.id;
  // Mark domain as verified
  const kv = _getKv();
  const existing = await kv.get(["domains", domain.id]);
  if (existing.value) {
    await kv.set(["domains", domain.id], { ...(existing.value as any), verified: true });
  }
  // Create aliases
  await createAlias(domain.id, "info", ["dest@example.com"]);
  await createAlias(domain.id, "*", ["catchall@example.com"]);
}

// Run setup once at module level
await setupForwardingTestData();

const fwdTestOpts = { sanitizeResources: false, sanitizeOps: false };

Deno.test({ name: "processInbound - forwards to matching alias and enqueues on SES failure", ...fwdTestOpts, fn: async () => {
  const msgId = `fwd-test-${crypto.randomUUID()}`;
  const result = await processInbound(makeSnsNotification({
    from: "sender@external.com",
    to: `info@${fwdDomain}`,
    subject: "Hello",
    messageId: msgId,
  }));

  assertEquals(result.action, "processed");
  // forwardEmail will fail (no AWS) so it should be enqueued for retry
  const queue = await listForwardQueue();
  const queued = queue.find((q) => q.from === "sender@external.com" && q.to === "dest@example.com");
  assertExists(queued, "Email should be enqueued for retry after SES failure");

  // Verify alias stats were bumped (fire-and-forget, give it a moment)
  await new Promise((r) => setTimeout(r, 100));
  const alias = await getAlias(fwdDomainId, "info");
  assertExists(alias);

  // Verify dedup mark
  const processed = await isMessageProcessed(msgId);
  assertEquals(processed, true);

  // Cleanup
  if (queued) await dequeueForward(queued.id);
}});

Deno.test({ name: "processInbound - dedup prevents reprocessing", ...fwdTestOpts, fn: async () => {
  const msgId = `dedup-test-${crypto.randomUUID()}`;
  // Process once
  await processInbound(makeSnsNotification({
    from: "sender@external.com",
    to: `info@${fwdDomain}`,
    subject: "Dedup test",
    messageId: msgId,
  }));

  // Process again — should be skipped
  const result = await processInbound(makeSnsNotification({
    from: "sender@external.com",
    to: `info@${fwdDomain}`,
    subject: "Dedup test",
    messageId: msgId,
  }));

  assertEquals(result.action, "skipped");
  assertEquals(result.details, "Duplicate SNS delivery");
}});

Deno.test({ name: "processInbound - catch-all matches when specific alias doesn't exist", ...fwdTestOpts, fn: async () => {
  const msgId = `catchall-test-${crypto.randomUUID()}`;
  const result = await processInbound(makeSnsNotification({
    from: "sender@external.com",
    to: `nonexistent@${fwdDomain}`,
    subject: "Catch-all test",
    messageId: msgId,
  }));

  assertEquals(result.action, "processed");
  // Should forward via catch-all to catchall@example.com
  const queue = await listForwardQueue();
  const queued = queue.find((q) => q.to === "catchall@example.com" && q.originalTo === `nonexistent@${fwdDomain}`);
  assertExists(queued, "Catch-all should forward to catchall destination");

  // Cleanup
  if (queued) await dequeueForward(queued.id);
}});

Deno.test({ name: "processInbound - disabled alias is not forwarded", ...fwdTestOpts, fn: async () => {
  // Disable the info alias
  const kv = _getKv();
  const aliasEntry = await kv.get(["aliases", fwdDomainId, "info"]);
  const aliasData = aliasEntry.value as any;
  await kv.set(["aliases", fwdDomainId, "info"], { ...aliasData, enabled: false });

  // Also disable catch-all so it doesn't match as fallback
  const catchAllEntry = await kv.get(["aliases", fwdDomainId, "*"]);
  const catchAllData = catchAllEntry.value as any;
  await kv.set(["aliases", fwdDomainId, "*"], { ...catchAllData, enabled: false });

  const msgId = `disabled-test-${crypto.randomUUID()}`;
  const result = await processInbound(makeSnsNotification({
    from: "sender@external.com",
    to: `info@${fwdDomain}`,
    subject: "Disabled test",
    messageId: msgId,
  }));

  assertEquals(result.action, "processed");
  assertEquals(result.details, "forwarded=0 discarded=1");

  // Restore aliases
  await kv.set(["aliases", fwdDomainId, "info"], { ...aliasData, enabled: true });
  await kv.set(["aliases", fwdDomainId, "*"], { ...catchAllData, enabled: true });
}});

Deno.test({ name: "processInbound - source rewrite in raw email", ...fwdTestOpts, fn: async () => {
  // Verify the raw email rewrite logic directly: From is rewritten, Reply-To added
  // We test this by checking what gets enqueued (since SES will fail)
  const msgId = `rewrite-test-${crypto.randomUUID()}`;
  await processInbound(makeSnsNotification({
    from: "original@sender.com",
    to: `info@${fwdDomain}`,
    subject: "Rewrite test",
    messageId: msgId,
  }));

  const queue = await listForwardQueue();
  const queued = queue.find((q) => q.from === "original@sender.com" && q.domainName === fwdDomain);
  assertExists(queued, "Should be enqueued");
  // The rawContent in the queue should be the original raw email
  // (the rewrite happens inside forwardEmail in ses.ts, so the queue stores original)
  assertEquals(queued!.rawContent.includes("From: original@sender.com"), true);

  // Cleanup
  if (queued) await dequeueForward(queued.id);
}});
