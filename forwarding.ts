import { getDomainByName, getAlias, listAliases, listRules, addLog, type Rule } from "./db.ts";
import { forwardEmail } from "./ses.ts";

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

  if (notification.notificationType !== "Received") {
    return { action: "ignored", details: `Not a received email: ${notification.notificationType}` };
  }

  const recipients = notification.receipt.recipients;
  const from = notification.mail.source;
  const subject = notification.mail.commonHeaders.subject ?? "(sin asunto)";
  const rawContent = notification.content ?? "";

  let forwarded = 0;
  let discarded = 0;

  for (const recipient of recipients) {
    const [localPart, domainName] = recipient.split("@");
    if (!domainName) continue;

    const domain = await getDomainByName(domainName);
    if (!domain || !domain.verified) continue;

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
        });
        discarded++;
        continue;
      }

      if (matchedRule.action === "forward" && matchedRule.target) {
        await doForward(rawContent, from, matchedRule.target, domain.id, recipient, subject);
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
        });
        continue;
      }
    }

    // Step 2: Check alias
    const alias = await getAlias(domain.id, localPart);
    const catchAll = await getAlias(domain.id, "*");
    const matched = alias?.enabled ? alias : (catchAll?.enabled ? catchAll : null);

    if (matched) {
      for (const dest of matched.destinations) {
        await doForward(rawContent, from, dest, domain.id, recipient, subject);
        forwarded++;
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
      });
      discarded++;
    }
  }

  return { action: "processed", details: `forwarded=${forwarded} discarded=${discarded}` };
}

// --- Rule evaluation ---

function evaluateRules(rules: Rule[], email: { to: string; from: string; subject: string }): Rule | null {
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

async function doForward(rawContent: string, from: string, to: string, domainId: string, originalTo: string, subject: string): Promise<void> {
  try {
    if (rawContent) {
      await forwardEmail(rawContent, from, to);
    }
    await addLog({
      domainId,
      timestamp: new Date().toISOString(),
      from, to: originalTo, subject,
      status: "forwarded",
      forwardedTo: to,
      sizeBytes: rawContent.length,
    });
  } catch (err) {
    await addLog({
      domainId,
      timestamp: new Date().toISOString(),
      from, to: originalTo, subject,
      status: "failed",
      forwardedTo: to,
      sizeBytes: rawContent.length,
      error: err instanceof Error ? err.message : String(err),
    });
  }
}
