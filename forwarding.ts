import { getDomainByName, getAlias, listAliases, listRules, addLog, bumpAliasStats, getUser, getUserPlanLimits, isMessageProcessed, markMessageProcessed, enqueueForward, listForwardQueue, dequeueForward, updateForwardQueueItem, moveToDeadLetter, RETRY_DELAYS, MAX_ATTEMPTS, type Rule, type ForwardQueueItem } from "./db.ts";
import { forwardEmail, fetchEmailFromS3, sendAlert } from "./ses.ts";
import { checkRateLimit } from "./rate-limit.ts";
import { log } from "./logger.ts";

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
  if (!rawContent && notification.receipt.action.bucketName && notification.receipt.action.objectKey) {
    try {
      rawContent = await fetchEmailFromS3(
        notification.receipt.action.bucketName,
        notification.receipt.action.objectKey,
      );
    } catch (err) {
      log("error", "forwarding", "Failed to fetch email from S3", { error: String(err) });
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
    const rlResult = await checkRateLimit(`fwd:${domain.id}`, forwardPerHour, 3600_000);
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

    // Step 1: Check rules first (higher priority)
    const rules = await listRules(domain.id);
    const matchedRule = evaluateRules(rules, { to: recipient, from, subject });

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
        await doForward(rawContent, from, matchedRule.target, domain.id, domainName, recipient, subject, logDays);
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
        await doForward(rawContent, from, dest, domain.id, domainName, recipient, subject, logDays);
        forwarded++;
      }
      bumpAliasStats(domain.id, matched.alias, from); // fire-and-forget
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

export function evaluateRules(rules: Rule[], email: { to: string; from: string; subject: string }): Rule | null {
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
          matches = new RegExp(rule.value, "i").test(fieldValue);
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

async function doForward(rawContent: string, from: string, to: string, domainId: string, domainName: string, originalTo: string, subject: string, logDays = 15): Promise<void> {
  if (!rawContent) {
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
      await enqueueForward({ rawContent, from, to, domainId, domainName, originalTo, subject, logDays }, errorMsg);
      log("info", "forwarding", "Enqueued forward retry", { from, to, error: errorMsg });
    } catch (enqErr) {
      log("error", "forwarding", "Failed to enqueue forward retry", { error: String(enqErr) });
    }
  }
}

// --- Retry cron (every 5 minutes) ---

Deno.cron("forward-retry", "*/5 * * * *", async () => {
  const now = Date.now();
  const items = await listForwardQueue();
  let processed = 0;
  let deadLettered = 0;

  for (const item of items) {
    if (new Date(item.nextRetryAt).getTime() > now) continue;

    const attempt = item.attemptCount + 1;

    try {
      await forwardEmail(item.rawContent, item.from, item.to, item.domainName);
      await addLog({
        domainId: item.domainId,
        timestamp: new Date().toISOString(),
        from: item.from, to: item.originalTo, subject: item.subject,
        status: "forwarded",
        forwardedTo: item.to,
        sizeBytes: item.rawContent.length,
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
