import { describe, it, before } from "node:test";
import assert from "node:assert/strict";

import { evaluateRules, processInbound, extractPlainBody, extractHtmlBody, extractAttachments } from "./forwarding.ts";
import {
  enqueueForward, dequeueForward, listForwardQueue, moveToDeadLetter,
  getQueueDepth, getDeadLetterCount,
  createUser, createDomain, createAlias, listAliases, getAlias,
  updateDomain, updateAlias,
  isMessageProcessed, markMessageProcessed,
  listLogs, updateUserSubscription, createRule,
  findConversationByThread, listConversations,
  deleteUser, deleteDomain,
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

describe("evaluateRules", () => {
  it("contains match", async () => {
    const rules = [makeRule({ field: "from", match: "contains", value: "spam" })];
    const result = await evaluateRules(rules, { to: "a@b.com", from: "spammer@evil.com", subject: "hi" });
    assert.ok(result);
    assert.equal(result!.id, "r1");
  });

  it("contains no match", async () => {
    const rules = [makeRule({ field: "from", match: "contains", value: "spam" })];
    const result = await evaluateRules(rules, { to: "a@b.com", from: "friend@good.com", subject: "hi" });
    assert.equal(result, null);
  });

  it("equals match (case insensitive)", async () => {
    const rules = [makeRule({ field: "subject", match: "equals", value: "HELLO" })];
    const result = await evaluateRules(rules, { to: "a@b.com", from: "x@y.com", subject: "hello" });
    assert.ok(result);
  });

  it("equals no match (partial)", async () => {
    const rules = [makeRule({ field: "subject", match: "equals", value: "hello" })];
    const result = await evaluateRules(rules, { to: "a@b.com", from: "x@y.com", subject: "hello world" });
    assert.equal(result, null);
  });

  it("regex match", async () => {
    const rules = [makeRule({ field: "from", match: "regex", value: "^admin@" })];
    const result = await evaluateRules(rules, { to: "a@b.com", from: "admin@example.com", subject: "hi" });
    assert.ok(result);
  });

  it("regex no match", async () => {
    const rules = [makeRule({ field: "from", match: "regex", value: "^admin@" })];
    const result = await evaluateRules(rules, { to: "a@b.com", from: "user@example.com", subject: "hi" });
    assert.equal(result, null);
  });

  it("invalid regex doesn't crash", async () => {
    const rules = [makeRule({ field: "from", match: "regex", value: "[invalid" })];
    const result = await evaluateRules(rules, { to: "a@b.com", from: "admin@example.com", subject: "hi" });
    assert.equal(result, null);
  });

  it("disabled rule skipped", async () => {
    const rules = [makeRule({ field: "from", match: "contains", value: "spam", enabled: false })];
    const result = await evaluateRules(rules, { to: "a@b.com", from: "spammer@evil.com", subject: "hi" });
    assert.equal(result, null);
  });

  it("priority order (first match wins)", async () => {
    const rules = [
      makeRule({ id: "r1", field: "from", match: "contains", value: "user", priority: 0, action: "discard" }),
      makeRule({ id: "r2", field: "from", match: "contains", value: "user", priority: 1, action: "forward" }),
    ];
    const result = await evaluateRules(rules, { to: "a@b.com", from: "user@x.com", subject: "hi" });
    assert.equal(result!.id, "r1");
    assert.equal(result!.action, "discard");
  });
});

// --- Queue tests ---

describe("Forward queue", () => {
  it("enqueue and dequeue forward", () => {
    const item = enqueueForward({
      rawContent: "raw email content",
      from: "sender@test.com",
      to: "dest@test.com",
      domainId: "test-domain",
      domainName: "test.com",
      originalTo: "alias@test.com",
      subject: "Test subject",
      logDays: 15,
    }, "SES throttle");

    assert.ok(item.id);
    assert.equal(item.attemptCount, 0);
    assert.equal(item.lastError, "SES throttle");

    const queue = listForwardQueue();
    assert.ok(queue.find((q) => q.id === item.id));

    dequeueForward(item.id);
    const afterDequeue = listForwardQueue();
    assert.equal(afterDequeue.find((q) => q.id === item.id), undefined);
  });

  it("moveToDeadLetter removes from active queue", () => {
    const item = enqueueForward({
      rawContent: "raw",
      from: "a@b.com",
      to: "c@d.com",
      domainId: "d1",
      domainName: "b.com",
      originalTo: "x@b.com",
      subject: "test",
      logDays: 15,
    }, "error");

    moveToDeadLetter({ ...item, attemptCount: 3 });

    const queue = listForwardQueue();
    assert.equal(queue.find((q) => q.id === item.id), undefined);
  });
});

// --- processInbound tests ---

function makeSnsNotification(opts: {
  from: string;
  to: string;
  subject: string;
  messageId: string;
  rawContent?: string;
  spamVerdict?: string;
  virusVerdict?: string;
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
        spamVerdict: { status: opts.spamVerdict ?? "PASS" },
        virusVerdict: { status: opts.virusVerdict ?? "PASS" },
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

// Setup test data
const fwdSuffix = `fwd-${Date.now()}`;
const fwdDomain = `${fwdSuffix}.test`;
const fwdEmail = `owner-${fwdSuffix}@example.com`;
let fwdDomainId: string;

describe("processInbound", () => {
  before(async () => {
    const hash = await hashPassword("testpass123");
    createUser(fwdEmail, hash);
    updateUserSubscription(fwdEmail, {
      plan: "developer",
      status: "active",
      currentPeriodEnd: new Date(Date.now() + 365 * 86400000).toISOString(),
    });
    const domain = createDomain(fwdEmail, fwdDomain, ["dkim1"], "verify1");
    fwdDomainId = domain.id;
    updateDomain(domain.id, { verified: true });
    createAlias(domain.id, "info", ["dest@example.com"]);
    createAlias(domain.id, "*", ["catchall@example.com"]);
  });

  it("forwards to matching alias and enqueues on SES failure", async () => {
    const msgId = `fwd-test-${crypto.randomUUID()}`;
    const result = await processInbound(makeSnsNotification({
      from: "sender@external.com",
      to: `info@${fwdDomain}`,
      subject: "Hello",
      messageId: msgId,
    }));

    assert.equal(result.action, "processed");
    const queue = listForwardQueue();
    const queued = queue.find((q) => q.from === "sender@external.com" && q.to === "dest@example.com");
    assert.ok(queued, "Email should be enqueued for retry after SES failure");

    await new Promise((r) => setTimeout(r, 100));
    const al = getAlias(fwdDomainId, "info");
    assert.ok(al);

    const processed = isMessageProcessed(msgId);
    assert.equal(processed, true);

    if (queued) dequeueForward(queued.id);
  });

  it("dedup prevents reprocessing", async () => {
    const msgId = `dedup-test-${crypto.randomUUID()}`;
    await processInbound(makeSnsNotification({
      from: "sender@external.com",
      to: `info@${fwdDomain}`,
      subject: "Dedup test",
      messageId: msgId,
    }));

    const result = await processInbound(makeSnsNotification({
      from: "sender@external.com",
      to: `info@${fwdDomain}`,
      subject: "Dedup test",
      messageId: msgId,
    }));

    assert.equal(result.action, "skipped");
    assert.equal(result.details, "Duplicate SNS delivery");
  });

  it("catch-all matches when specific alias doesn't exist", async () => {
    const msgId = `catchall-test-${crypto.randomUUID()}`;
    const result = await processInbound(makeSnsNotification({
      from: "sender@external.com",
      to: `nonexistent@${fwdDomain}`,
      subject: "Catch-all test",
      messageId: msgId,
    }));

    assert.equal(result.action, "processed");
    const queue = listForwardQueue();
    const queued = queue.find((q) => q.to === "catchall@example.com" && q.originalTo === `nonexistent@${fwdDomain}`);
    assert.ok(queued, "Catch-all should forward to catchall destination");

    if (queued) dequeueForward(queued.id);
  });

  it("disabled alias is not forwarded", async () => {
    updateAlias(fwdDomainId, "info", { enabled: false });
    updateAlias(fwdDomainId, "*", { enabled: false });

    const msgId = `disabled-test-${crypto.randomUUID()}`;
    const result = await processInbound(makeSnsNotification({
      from: "sender@external.com",
      to: `info@${fwdDomain}`,
      subject: "Disabled test",
      messageId: msgId,
    }));

    assert.equal(result.action, "processed");
    assert.equal(result.details, "forwarded=0 discarded=1");

    // Restore
    updateAlias(fwdDomainId, "info", { enabled: true });
    updateAlias(fwdDomainId, "*", { enabled: true });
  });

  it("source rewrite in raw email", async () => {
    const msgId = `rewrite-test-${crypto.randomUUID()}`;
    await processInbound(makeSnsNotification({
      from: "original@sender.com",
      to: `info@${fwdDomain}`,
      subject: "Rewrite test",
      messageId: msgId,
    }));

    const queue = listForwardQueue();
    const queued = queue.find((q) => q.from === "original@sender.com" && q.domainName === fwdDomain);
    assert.ok(queued, "Should be enqueued");
    assert.equal(queued!.rawContent.includes("From: original@sender.com"), true);

    if (queued) dequeueForward(queued.id);
  });

  // --- New tests ---

  it("spam verdict FAIL → rejected", async () => {
    const msgId = `spam-test-${crypto.randomUUID()}`;
    const result = await processInbound(makeSnsNotification({
      from: "spammer@evil.com",
      to: `info@${fwdDomain}`,
      subject: "Buy cheap stuff",
      messageId: msgId,
      spamVerdict: "FAIL",
    }));

    assert.equal(result.action, "rejected");
    assert.match(result.details, /spam|virus/i);
  });

  it("virus verdict FAIL → rejected", async () => {
    const msgId = `virus-test-${crypto.randomUUID()}`;
    const result = await processInbound(makeSnsNotification({
      from: "attacker@evil.com",
      to: `info@${fwdDomain}`,
      subject: "Open this",
      messageId: msgId,
      virusVerdict: "FAIL",
    }));

    assert.equal(result.action, "rejected");
    assert.match(result.details, /spam|virus/i);
  });

  it("rules: discard action prevents forwarding", async () => {
    const rule = createRule(fwdDomainId, {
      field: "from", match: "contains", value: "discard-me",
      action: "discard", target: "", priority: 0, enabled: true,
    });

    const msgId = `discard-rule-${crypto.randomUUID()}`;
    const result = await processInbound(makeSnsNotification({
      from: "discard-me@test.com",
      to: `info@${fwdDomain}`,
      subject: "Should be discarded",
      messageId: msgId,
    }));

    assert.equal(result.action, "processed");
    assert.match(result.details, /discarded=1/);

    // Should NOT be in forward queue
    const queue = listForwardQueue();
    const queued = queue.find((q) => q.from === "discard-me@test.com");
    assert.equal(queued, undefined);

    // Cleanup rule
    const { deleteRule } = await import("./db.ts");
    deleteRule(fwdDomainId, rule.id);
  });

  it("rules: forward action with custom target", async () => {
    const rule = createRule(fwdDomainId, {
      field: "subject", match: "contains", value: "vip-forward",
      action: "forward", target: "vip@custom.com", priority: 0, enabled: true,
    });

    const msgId = `rule-fwd-${crypto.randomUUID()}`;
    const result = await processInbound(makeSnsNotification({
      from: "sender@test.com",
      to: `info@${fwdDomain}`,
      subject: "vip-forward request",
      messageId: msgId,
    }));

    assert.equal(result.action, "processed");
    assert.match(result.details, /forwarded=1/);

    const queue = listForwardQueue();
    const queued = queue.find((q) => q.to === "vip@custom.com");
    assert.ok(queued, "Should forward to rule's custom target");

    if (queued) dequeueForward(queued.id);
    const { deleteRule } = await import("./db.ts");
    deleteRule(fwdDomainId, rule.id);
  });

  it("expired subscription → skip forwarding", async () => {
    // Create a separate domain with expired owner
    const expSuffix = `exp-${Date.now()}`;
    const expEmail = `expired-${expSuffix}@example.com`;
    const hash = await hashPassword("testpass123");
    createUser(expEmail, hash);
    updateUserSubscription(expEmail, {
      plan: "basico",
      status: "cancelled",
      currentPeriodEnd: new Date(Date.now() - 86400000).toISOString(), // expired yesterday
    });
    const expDomain = createDomain(expEmail, `${expSuffix}.test`, ["dkim1"], "v1");
    updateDomain(expDomain.id, { verified: true });
    createAlias(expDomain.id, "info", ["dest@example.com"]);

    const msgId = `expired-test-${crypto.randomUUID()}`;
    const result = await processInbound(makeSnsNotification({
      from: "sender@test.com",
      to: `info@${expSuffix}.test`,
      subject: "Should not forward",
      messageId: msgId,
    }));

    assert.equal(result.action, "processed");
    assert.equal(result.details, "forwarded=0 discarded=0");
  });

  it("saveToMesa threading: 2 emails same thread → single conversation", async () => {
    const threadId = `thread-${crypto.randomUUID()}`;
    const msgId1 = `mesa-thread1-${crypto.randomUUID()}`;
    const msgId2 = `mesa-thread2-${crypto.randomUUID()}`;

    const raw1 = [
      `From: sender@external.com`,
      `To: info@${fwdDomain}`,
      `Subject: Thread test`,
      `Message-ID: <${threadId}@test.com>`,
      `Content-Type: text/plain; charset=UTF-8`,
      ``,
      `First message`,
    ].join("\r\n");

    await processInbound(makeSnsNotification({
      from: "sender@external.com",
      to: `info@${fwdDomain}`,
      subject: "Thread test",
      messageId: msgId1,
      rawContent: raw1,
    }));

    const raw2 = [
      `From: sender@external.com`,
      `To: info@${fwdDomain}`,
      `Subject: Re: Thread test`,
      `Message-ID: <${msgId2}@test.com>`,
      `In-Reply-To: <${threadId}@test.com>`,
      `References: <${threadId}@test.com>`,
      `Content-Type: text/plain; charset=UTF-8`,
      ``,
      `Reply message`,
    ].join("\r\n");

    await processInbound(makeSnsNotification({
      from: "sender@external.com",
      to: `info@${fwdDomain}`,
      subject: "Re: Thread test",
      messageId: msgId2,
      rawContent: raw2,
    }));

    // Should have one conversation with messageCount >= 2
    const convs = listConversations(fwdDomainId, {});
    const threadConv = convs.find(c => c.subject === "Thread test" && c.from === "sender@external.com");
    assert.ok(threadConv, "Should find threaded conversation");
    assert.ok(threadConv!.messageCount >= 2, `Expected messageCount >= 2, got ${threadConv!.messageCount}`);
  });

  it("saveToMesa: unrelated email creates new conversation", async () => {
    const convsBefore = listConversations(fwdDomainId, {});
    const countBefore = convsBefore.length;

    const msgId = `new-conv-${crypto.randomUUID()}`;
    await processInbound(makeSnsNotification({
      from: "unique-sender@newdomain.com",
      to: `info@${fwdDomain}`,
      subject: `Unique subject ${msgId}`,
      messageId: msgId,
    }));

    const convsAfter = listConversations(fwdDomainId, {});
    assert.ok(convsAfter.length > countBefore, "Should create a new conversation");
  });
});

// --- MIME parsing tests ---

const NESTED_MULTIPART = [
  "From: sender@example.com",
  "To: alias@domain.com",
  "Subject: Test with attachment",
  'Content-Type: multipart/mixed; boundary="outer"',
  "",
  "--outer",
  'Content-Type: multipart/alternative; boundary="inner"',
  "",
  "--inner",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "Hello plain text",
  "--inner--",
  "--outer",
  'Content-Type: multipart/alternative; boundary="inner2"',
  "",
  "--inner2",
  "Content-Type: text/html; charset=utf-8",
  "",
  "<p>Hello HTML</p>",
  "--inner2--",
  "--outer",
  "Content-Type: image/png; name=\"photo.png\"",
  "Content-Disposition: attachment; filename=\"photo.png\"",
  "Content-Transfer-Encoding: base64",
  "",
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ",
  "--outer",
  "Content-Type: application/pdf; name=\"doc.pdf\"",
  "Content-Disposition: attachment; filename=\"doc.pdf\"",
  "Content-Transfer-Encoding: base64",
  "",
  "JVBERi0xLjQK",
  "--outer--",
].join("\r\n");

describe("MIME parsing", () => {
  it("extractPlainBody handles nested multipart", () => {
    assert.equal(extractPlainBody(NESTED_MULTIPART), "Hello plain text");
  });

  it("extractHtmlBody handles nested multipart", () => {
    assert.equal(extractHtmlBody(NESTED_MULTIPART), "<p>Hello HTML</p>");
  });

  it("extractAttachments returns metadata from nested multipart", () => {
    const attachments = extractAttachments(NESTED_MULTIPART);
    assert.equal(attachments.length, 2);
    assert.equal(attachments[0].filename, "photo.png");
    assert.equal(attachments[0].contentType, "image/png");
    assert.equal(attachments[1].filename, "doc.pdf");
    assert.equal(attachments[1].contentType, "application/pdf");
  });

  it("extractPlainBody handles simple non-multipart email", () => {
    const simple = ["From: a@b.com", "Content-Type: text/plain", "", "Simple body"].join("\r\n");
    assert.equal(extractPlainBody(simple), "Simple body");
  });

  it("extractPlainBody decodes quoted-printable", () => {
    const qp = [
      "From: sender@example.com",
      'Content-Type: multipart/alternative; boundary="qp"',
      "",
      "--qp",
      "Content-Type: text/plain; charset=utf-8",
      "Content-Transfer-Encoding: quoted-printable",
      "",
      "Hello =C3=A1cento y l=C3=ADnea",
      "--qp--",
    ].join("\r\n");
    assert.equal(extractPlainBody(qp), "Hello ácento y línea");
  });
});
