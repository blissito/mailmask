import { getDomainByName, getAlias, listAliases, listRules, addLog, bumpAliasStats, getUser, getUserPlanLimits, isMessageProcessed, markMessageProcessed, enqueueForward, listForwardQueue, dequeueForward, updateForwardQueueItem, moveToDeadLetter, RETRY_DELAYS, MAX_ATTEMPTS, findConversationByThread, createConversation, updateConversation, addMessage, type Rule, type ForwardQueueItem } from "./db.js";
import { forwardEmail, fetchEmailFromS3, sendAlert, listInboundEmailKeys, fetchEmailHeadersFromS3, sendFromDomain } from "./ses.js";
import { checkRateLimit } from "./rate-limit.js";
import { log } from "./logger.js";
import cron from "node-cron";

// --- SNS notification types ---

interface SnsNotification {
  Type: string;
  Message: string;
  MessageId: string;
  TopicArn: string;
  SubscribeURL?: string;
}

interface SesMailNotification {
  notificationType: string;
  receipt: {
    action: { type: string; bucketName: string; objectKey: string };
    recipients: string[];
    spamVerdict: { status: string };
    virusVerdict: { status: string };
    spfVerdict: { status: string };
    dkimVerdict: { status: string };
  };
  mail: {
    source: string;
    destination: string[];
    commonHeaders: {
      from: string[];
      to: string[];
      subject: string;
    };
    messageId: string;
  };
  content?: string; // raw email if included via SNS
}

// --- Email header parsing helpers ---

function extractHeader(raw: string, name: string): string {
  const re = new RegExp(`^${name}:\\s*(.+)$`, "mi");
  const match = raw.match(re);
  return match?.[1]?.trim() ?? "";
}

function extractReferences(raw: string): string[] {
  const refs: string[] = [];
  const inReplyTo = extractHeader(raw, "In-Reply-To");
  if (inReplyTo) refs.push(inReplyTo);
  const references = extractHeader(raw, "References");
  if (references) {
    // References header can contain multiple message-ids separated by whitespace
    refs.push(...references.split(/\s+/).filter(r => r.startsWith("<")));
  }
  const msgId = extractHeader(raw, "Message-ID");
  if (msgId) refs.push(msgId);
  return [...new Set(refs)];
}

// --- Recursive MIME parser ---

interface MimePart {
  headers: string;
  contentType: string;
  body: string;
  filename?: string;
  encoding?: string;
}

function parseMimeParts(body: string, boundary: string): MimePart[] {
  const parts: MimePart[] = [];
  const segments = body.split(`--${boundary}`);

  for (const segment of segments) {
    const trimmed = segment.trim();
    if (!trimmed || trimmed === "--") continue;

    const splitIdx = segment.indexOf("\r\n\r\n");
    if (splitIdx === -1) continue;

    const headers = segment.slice(0, splitIdx);
    let partBody = segment.slice(splitIdx + 4);
    // Remove trailing boundary marker
    if (partBody.endsWith("\r\n")) partBody = partBody.slice(0, -2);

    const ctMatch = headers.match(/Content-Type:\s*([^\r\n]+(?:\r\n\s+[^\r\n]+)*)/i);
    const contentType = ctMatch ? ctMatch[1].replace(/\r\n\s+/g, " ").trim() : "";

    // If this part is itself multipart, recurse
    if (contentType.toLowerCase().includes("multipart")) {
      const innerBoundary = contentType.match(/boundary="?([^";\s]+)"?/i);
      if (innerBoundary) {
        const innerParts = parseMimeParts(partBody, innerBoundary[1]);
        parts.push(...innerParts);
        continue;
      }
    }

    const encMatch = headers.match(/Content-Transfer-Encoding:\s*(\S+)/i);
    const encoding = encMatch ? encMatch[1].trim().toLowerCase() : undefined;

    // Extract filename from Content-Disposition or Content-Type
    let filename: string | undefined;
    const dispMatch = headers.match(/Content-Disposition:\s*([^\r\n]+(?:\r\n\s+[^\r\n]+)*)/i);
    if (dispMatch) {
      const disp = dispMatch[1].replace(/\r\n\s+/g, " ");
      const fnMatch = disp.match(/filename="?([^";\r\n]+)"?/i);
      if (fnMatch) filename = fnMatch[1].trim();
    }
    if (!filename) {
      const nameMatch = contentType.match(/name="?([^";\r\n]+)"?/i);
      if (nameMatch) filename = nameMatch[1].trim();
    }

    parts.push({ headers, contentType, body: partBody, filename, encoding });
  }
  return parts;
}

function flattenMimeParts(raw: string): MimePart[] {
  const headerBodySplit = raw.indexOf("\r\n\r\n");
  if (headerBodySplit === -1) return [];
  const body = raw.slice(headerBodySplit + 4);
  const contentType = extractHeader(raw, "Content-Type");

  if (contentType.includes("multipart")) {
    const boundaryMatch = contentType.match(/boundary="?([^";\s]+)"?/);
    if (boundaryMatch) {
      return parseMimeParts(body, boundaryMatch[1]);
    }
  }

  // Not multipart — single part
  const encMatch = raw.slice(0, headerBodySplit).match(/Content-Transfer-Encoding:\s*(\S+)/i);
  return [{ headers: raw.slice(0, headerBodySplit), contentType, body, encoding: encMatch?.[1]?.trim().toLowerCase() }];
}

function decodePartBody(part: MimePart): string {
  if (part.encoding === "quoted-printable") {
    const decoded = part.body.replace(/=\r?\n/g, "");
    // Convert hex-encoded bytes to a Uint8Array, then decode as UTF-8
    const bytes: number[] = [];
    for (let i = 0; i < decoded.length; i++) {
      if (decoded[i] === "=" && /^[0-9A-Fa-f]{2}$/.test(decoded.slice(i + 1, i + 3))) {
        bytes.push(parseInt(decoded.slice(i + 1, i + 3), 16));
        i += 2;
      } else {
        bytes.push(decoded.charCodeAt(i));
      }
    }
    return new TextDecoder("utf-8").decode(new Uint8Array(bytes));
  }
  if (part.encoding === "base64") {
    try { return atob(part.body.replace(/\s/g, "")); } catch { return part.body; }
  }
  return part.body;
}

export function extractPlainBody(raw: string): string {
  const parts = flattenMimeParts(raw);
  for (const part of parts) {
    if (part.contentType.toLowerCase().includes("text/plain")) {
      return decodePartBody(part).trim();
    }
  }
  // Fallback: return raw body after headers
  const idx = raw.indexOf("\r\n\r\n");
  return idx === -1 ? raw : raw.slice(idx + 4).trim();
}

export function extractHtmlBody(raw: string): string {
  const parts = flattenMimeParts(raw);
  for (const part of parts) {
    if (part.contentType.toLowerCase().includes("text/html")) {
      return decodePartBody(part).trim();
    }
  }
  return "";
}

export interface AttachmentMeta {
  index: number;
  filename: string;
  contentType: string;
  size: number;
}

export function extractAttachments(raw: string): AttachmentMeta[] {
  const parts = flattenMimeParts(raw);
  const attachments: AttachmentMeta[] = [];
  let idx = 0;

  for (const part of parts) {
    const ct = part.contentType.toLowerCase();
    // Skip text body parts
    if (ct.includes("text/plain") || ct.includes("text/html")) continue;
    // Skip empty parts
    if (!part.body.trim()) continue;

    const baseType = ct.split(";")[0].trim();
    attachments.push({
      index: idx++,
      filename: part.filename ?? `attachment-${idx}`,
      contentType: baseType,
      size: part.body.length,
    });
  }
  return attachments;
}

export function extractAttachmentByIndex(raw: string, index: number): { data: Uint8Array; contentType: string; filename: string } | null {
  const parts = flattenMimeParts(raw);
  let idx = 0;

  for (const part of parts) {
    const ct = part.contentType.toLowerCase();
    if (ct.includes("text/plain") || ct.includes("text/html")) continue;
    if (!part.body.trim()) continue;

    if (idx === index) {
      const baseType = ct.split(";")[0].trim();
      const filename = part.filename ?? `attachment-${idx + 1}`;
      // Decode base64 content to binary
      let data: Uint8Array;
      if (part.encoding === "base64") {
        const binary = atob(part.body.replace(/\s/g, ""));
        data = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) data[i] = binary.charCodeAt(i);
      } else {
        data = new TextEncoder().encode(part.body);
      }
      return { data, contentType: baseType, filename };
    }
    idx++;
  }
  return null;
}

// --- Mesa integration ---

async function saveToMesa(rawContent: string, from: string, recipient: string, subject: string, domainId: string, s3Bucket?: string, s3Key?: string): Promise<void> {
  const references = rawContent ? extractReferences(rawContent) : [];
  const messageIdHeader = rawContent ? extractHeader(rawContent, "Message-ID") : "";

  // Try to find existing conversation by threading
  let conv = await findConversationByThread(domainId, from, references);

  if (conv) {
    // Add message to existing conversation
    await addMessage({
      conversationId: conv.id,
      from,
      s3Bucket,
      s3Key,
      direction: "inbound",
      createdAt: new Date().toISOString(),
      messageId: messageIdHeader,
    });
    const newRefs = [...new Set([...conv.threadReferences, ...references])];
    await updateConversation(domainId, conv.id, {
      lastMessageAt: new Date().toISOString(),
      messageCount: conv.messageCount + 1,
      status: "open", // Re-open on new inbound message
      threadReferences: newRefs,
    });
  } else {
    // Create new conversation — include messageIdHeader so replies can thread
    const initialRefs = messageIdHeader
      ? [...new Set([...references, messageIdHeader])]
      : references;
    conv = await createConversation({
      domainId,
      from,
      to: recipient,
      subject,
      status: "open",
      priority: "normal",
      lastMessageAt: new Date().toISOString(),
      messageCount: 1,
      tags: [],
      threadReferences: initialRefs,
    });
    await addMessage({
      conversationId: conv.id,
      from,
      s3Bucket,
      s3Key,
      direction: "inbound",
      createdAt: new Date().toISOString(),
      messageId: messageIdHeader,
    });
  }
}

// --- Rebuild conversations from S3 ---

export async function rebuildConversationsFromS3(domainId: string, domainName: string): Promise<number> {
  const s3Bucket = process.env.S3_BUCKET ?? "mailmask-inbound";
  const keys = await listInboundEmailKeys(domainName);
  if (keys.length === 0) return 0;

  log("info", "mesa", "Rebuilding conversations from S3", { domainId, domainName, emailCount: keys.length });

  let rebuilt = 0;
  for (const obj of keys) {
    try {
      // Fetch first 4KB to parse headers
      const partial = await fetchEmailHeadersFromS3(s3Bucket, obj.key);
      const from = extractHeader(partial, "From");
      const subject = extractHeader(partial, "Subject") || "(sin asunto)";
      const messageIdHeader = extractHeader(partial, "Message-ID");
      const date = extractHeader(partial, "Date");
      const references = extractReferences(partial);

      // Extract recipient from S3 key or To header
      const toHeader = extractHeader(partial, "To");
      const recipient = toHeader || `unknown@${domainName}`;

      // Thread into existing or create new conversation
      let conv = await findConversationByThread(domainId, from, references);

      const createdAt = date ? new Date(date).toISOString() : (obj.lastModified || new Date().toISOString());

      if (conv) {
        await addMessage({
          conversationId: conv.id,
          from,
          s3Bucket,
          s3Key: obj.key,
          direction: "inbound",
          createdAt,
          messageId: messageIdHeader,
        });
        const newRefs = [...new Set([...conv.threadReferences, ...references])];
        await updateConversation(domainId, conv.id, {
          lastMessageAt: createdAt,
          messageCount: conv.messageCount + 1,
          threadReferences: newRefs,
        });
      } else {
        const initialRefs = messageIdHeader
          ? [...new Set([...references, messageIdHeader])]
          : references;
        conv = await createConversation({
          domainId,
          from,
          to: recipient,
          subject,
          status: "open",
          priority: "normal",
          lastMessageAt: createdAt,
          messageCount: 1,
          tags: [],
          threadReferences: initialRefs,
        });
        await addMessage({
          conversationId: conv.id,
          from,
          s3Bucket,
          s3Key: obj.key,
          direction: "inbound",
          createdAt,
          messageId: messageIdHeader,
        });
        rebuilt++;
      }
    } catch (err) {
      log("error", "mesa", "Failed to rebuild conversation from S3 object", { key: obj.key, error: String(err) });
    }
  }

  log("info", "mesa", "Rebuild complete", { domainId, rebuilt, totalEmails: keys.length });
  return rebuilt;
}

// --- Process inbound email ---

export async function processInbound(body: SnsNotification): Promise<{ action: string; details: string }> {
  // Handle SNS subscription confirmation
  if (body.Type === "SubscriptionConfirmation" && body.SubscribeURL) {
    await fetch(body.SubscribeURL);
    return { action: "subscribed", details: "SNS subscription confirmed" };
  }

  if (body.Type !== "Notification") {
    return { action: "ignored", details: `Unknown SNS type: ${body.Type}` };
  }

  const notification: SesMailNotification = JSON.parse(body.Message);

  // SNS dedup: skip already-processed messages
  const messageId = notification.mail.messageId;
  if (messageId && await isMessageProcessed(messageId)) {
    return { action: "skipped", details: "Duplicate SNS delivery" };
  }

  if (notification.notificationType !== "Received") {
    return { action: "ignored", details: `Not a received email: ${notification.notificationType}` };
  }

  const recipients = notification.receipt.recipients;
  const from = notification.mail.source;
  const subject = notification.mail.commonHeaders.subject ?? "(sin asunto)";

  // Fetch raw email from S3 (SNS notification only has metadata)
  let rawContent = notification.content ?? "";
  const s3Bucket = notification.receipt.action.bucketName;
  const s3Key = notification.receipt.action.objectKey;
  let s3FetchFailed = false;
  if (!rawContent && s3Bucket && s3Key) {
    try {
      rawContent = await fetchEmailFromS3(s3Bucket, s3Key);
    } catch (err) {
      log("error", "forwarding", "Failed to fetch email from S3", { error: String(err) });
      s3FetchFailed = true;
    }
  }

  let forwarded = 0;
  let discarded = 0;

  for (const recipient of recipients) {
    const [localPart, domainName] = recipient.split("@");
    if (!domainName) continue;

    const domain = await getDomainByName(domainName);
    if (!domain || !domain.verified) continue;

    // Check owner's plan — block forwarding if expired/no plan
    let logDays = 15; // default
    let forwardPerHour = 100; // default
    const owner = await getUser(domain.ownerEmail);
    if (owner) {
      const planLimits = getUserPlanLimits(owner);
      if (planLimits.domains === 0) {
        log("info", "forwarding", "Forwarding blocked: no active plan", { ownerEmail: domain.ownerEmail });
        continue;
      }
      if (planLimits.logDays > 0) logDays = planLimits.logDays;
      forwardPerHour = planLimits.forwardPerHour;
    }

    // Rate limit: per-domain forwarding
    const rlResult = checkRateLimit(`fwd:${domain.id}`, forwardPerHour, 3600_000);
    if (!rlResult.allowed) {
      log("warn", "forwarding", "Forwarding rate limit exceeded", { domainId: domain.id, domainName, forwardPerHour });
      await sendAlert("fwd-rate-limit", `Forwarding rate limit exceeded for domain ${domainName} (${forwardPerHour}/hr). Email from ${from} discarded.`);
      await addLog({
        domainId: domain.id,
        timestamp: new Date().toISOString(),
        from, to: recipient, subject,
        status: "discarded",
        forwardedTo: "",
        sizeBytes: rawContent.length,
        error: "Rate limit exceeded",
      }, logDays);
      discarded++;
      continue;
    }

    // Mesa: save to conversation
    if (rawContent) {
      try {
        await saveToMesa(rawContent, from, recipient, subject, domain.id, s3Bucket, s3Key);
      } catch (err) {
        log("error", "forwarding", "Failed to save to Mesa", { error: String(err), domainId: domain.id });
      }
    }

    // Step 1: Check rules first (higher priority)
    const rules = await listRules(domain.id);
    const matchedRule = await evaluateRules(rules, { to: recipient, from, subject });

    if (matchedRule) {
      if (matchedRule.action === "discard") {
        await addLog({
          domainId: domain.id,
          timestamp: new Date().toISOString(),
          from, to: recipient, subject,
          status: "discarded",
          forwardedTo: "",
          sizeBytes: rawContent.length,
        }, logDays);
        discarded++;
        continue;
      }

      if (matchedRule.action === "forward" && matchedRule.target) {
        await doForward(rawContent, from, matchedRule.target, domain.id, domainName, recipient, subject, logDays, s3Bucket, s3Key);
        forwarded++;
        continue;
      }

      if (matchedRule.action === "webhook" && matchedRule.target) {
        try {
          await fetch(matchedRule.target, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ from, to: recipient, subject, timestamp: new Date().toISOString() }),
          });
        } catch { /* fire and forget */ }
        await addLog({
          domainId: domain.id,
          timestamp: new Date().toISOString(),
          from, to: recipient, subject,
          status: "rule_matched",
          forwardedTo: matchedRule.target,
          sizeBytes: rawContent.length,
        }, logDays);
        continue;
      }
    }

    // Step 2: Check alias
    const alias = await getAlias(domain.id, localPart);
    const catchAll = await getAlias(domain.id, "*");
    const matched = alias?.enabled ? alias : (catchAll?.enabled ? catchAll : null);

    if (matched) {
      for (const dest of matched.destinations) {
        await doForward(rawContent, from, dest, domain.id, domainName, recipient, subject, logDays, s3Bucket, s3Key);
        forwarded++;
      }
      bumpAliasStats(domain.id, matched.alias, from); // fire-and-forget

      // Notify owner on first email to this alias
      if (!matched.forwardCount && owner) {
        const aliasAddr = `${matched.alias}@${domainName}`;
        sendFromDomain(
          `noreply@${domainName}`,
          owner.email,
          `Primer email recibido en ${aliasAddr}`,
          `¡Tu alias ${aliasAddr} acaba de recibir su primer email!\n\nDe: ${from}\nAsunto: ${subject}\n\nPuedes ver la actividad de tus alias en tu panel de control.`,
          { html: `<p>¡Tu alias <strong>${aliasAddr}</strong> acaba de recibir su primer email!</p><p><strong>De:</strong> ${from}<br><strong>Asunto:</strong> ${subject}</p><p>Puedes ver la actividad de tus alias en tu <a href="https://mailmask.studio/app">panel de control</a>.</p>` },
        ).catch(() => {}); // fire-and-forget
      }
    } else {
      await addLog({
        domainId: domain.id,
        timestamp: new Date().toISOString(),
        from, to: recipient, subject,
        status: "discarded",
        forwardedTo: "",
        sizeBytes: rawContent.length,
        error: "No matching alias",
      }, logDays);
      discarded++;
    }
  }

  if (messageId) await markMessageProcessed(messageId);
  return { action: "processed", details: `forwarded=${forwarded} discarded=${discarded}` };
}

// --- Rule evaluation ---

export async function evaluateRules(rules: Rule[], email: { to: string; from: string; subject: string }): Promise<Rule | null> {
  for (const rule of rules) {
    if (!rule.enabled) continue;

    const fieldValue = email[rule.field] ?? "";
    let matches = false;

    switch (rule.match) {
      case "contains":
        matches = fieldValue.toLowerCase().includes(rule.value.toLowerCase());
        break;
      case "equals":
        matches = fieldValue.toLowerCase() === rule.value.toLowerCase();
        break;
      case "regex":
        try {
          const re = new RegExp(rule.value, "i");
          // Guard against ReDoS: race regex against a timeout
          const regexResult = await new Promise<boolean>((resolve) => {
            const timer = setTimeout(() => resolve(false), 50);
            const result = re.test(fieldValue);
            clearTimeout(timer);
            resolve(result);
          });
          matches = regexResult;
        } catch {
          matches = false;
        }
        break;
    }

    if (matches) return rule;
  }
  return null;
}

// --- Forward helper ---

async function doForward(rawContent: string, from: string, to: string, domainId: string, domainName: string, originalTo: string, subject: string, logDays = 15, s3Bucket?: string, s3Key?: string): Promise<void> {
  if (!rawContent) {
    // S3 fetch failed — enqueue with S3 coords for later retry
    if (s3Bucket && s3Key) {
      try {
        await enqueueForward({ rawContent: "", from, to, domainId, domainName, originalTo, subject, logDays, s3Bucket, s3Key }, "S3 fetch failed");
        log("info", "forwarding", "Enqueued S3 retry", { from, to, s3Key });
      } catch (enqErr) {
        log("error", "forwarding", "Failed to enqueue S3 retry", { error: String(enqErr) });
      }
    }
    await addLog({
      domainId,
      timestamp: new Date().toISOString(),
      from, to: originalTo, subject,
      status: "failed",
      forwardedTo: to,
      sizeBytes: 0,
      error: "Email content unavailable (S3 fetch failed)",
    }, logDays);
    return;
  }
  try {
    await forwardEmail(rawContent, from, to, domainName);
    await addLog({
      domainId,
      timestamp: new Date().toISOString(),
      from, to: originalTo, subject,
      status: "forwarded",
      forwardedTo: to,
      sizeBytes: rawContent.length,
    }, logDays);
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    await addLog({
      domainId,
      timestamp: new Date().toISOString(),
      from, to: originalTo, subject,
      status: "failed",
      forwardedTo: to,
      sizeBytes: rawContent.length,
      error: errorMsg,
    }, logDays);

    // Enqueue for retry
    try {
      await enqueueForward({ rawContent, from, to, domainId, domainName, originalTo, subject, logDays, s3Bucket, s3Key }, errorMsg);
      log("info", "forwarding", "Enqueued forward retry", { from, to, error: errorMsg });
    } catch (enqErr) {
      log("error", "forwarding", "Failed to enqueue forward retry", { error: String(enqErr) });
    }
  }
}

// --- Retry cron (every 5 minutes) ---

cron.schedule("*/5 * * * *", async () => {
  const now = Date.now();
  const items = await listForwardQueue();
  let processed = 0;
  let deadLettered = 0;

  for (const item of items) {
    if (new Date(item.nextRetryAt).getTime() > now) continue;

    const attempt = item.attemptCount + 1;

    // Re-fetch from S3 if content is missing but coords exist
    let content = item.rawContent;
    if (!content && item.s3Bucket && item.s3Key) {
      try {
        content = await fetchEmailFromS3(item.s3Bucket, item.s3Key);
      } catch (err) {
        log("warn", "forwarding", "S3 re-fetch failed during retry", { error: String(err), s3Key: item.s3Key });
      }
    }

    if (!content) {
      // Still no content — increment attempt and skip
      if (attempt >= MAX_ATTEMPTS) {
        await moveToDeadLetter({ ...item, attemptCount: attempt, lastError: "S3 content unavailable after retries" });
        deadLettered++;
      } else {
        const delay = RETRY_DELAYS[Math.min(attempt, RETRY_DELAYS.length - 1)];
        await updateForwardQueueItem({ ...item, attemptCount: attempt, nextRetryAt: new Date(now + delay).toISOString(), lastError: "S3 content unavailable" });
      }
      continue;
    }

    try {
      await forwardEmail(content, item.from, item.to, item.domainName);
      await addLog({
        domainId: item.domainId,
        timestamp: new Date().toISOString(),
        from: item.from, to: item.originalTo, subject: item.subject,
        status: "forwarded",
        forwardedTo: item.to,
        sizeBytes: content.length,
      }, item.logDays);
      await dequeueForward(item.id);
      processed++;
      log("info", "forwarding", "Retry forwarded successfully", { attempt, from: item.from, to: item.to });
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);

      if (attempt >= MAX_ATTEMPTS) {
        await moveToDeadLetter({ ...item, attemptCount: attempt, lastError: errorMsg });
        deadLettered++;
        log("error", "forwarding", "Dead-lettered after max attempts", { attempt, from: item.from, to: item.to, error: errorMsg });
        await sendAlert("dead-letter", `Email dead-lettered after ${attempt} attempts.\nFrom: ${item.from}\nTo: ${item.to}\nSubject: ${item.subject}\nError: ${errorMsg}`);
      } else {
        const delay = RETRY_DELAYS[Math.min(attempt, RETRY_DELAYS.length - 1)];
        await updateForwardQueueItem({
          ...item,
          attemptCount: attempt,
          nextRetryAt: new Date(now + delay).toISOString(),
          lastError: errorMsg,
        });
        log("warn", "forwarding", "Retry attempt failed", { attempt, from: item.from, to: item.to, nextRetryMin: delay / 60_000 });
      }
    }
  }

  if (processed > 0 || deadLettered > 0) {
    log("info", "forwarding", "Retry cron completed", { processed, deadLettered });
  }
});
