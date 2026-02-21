import { log } from "./logger.ts";

const alertKv = await Deno.openKv(Deno.env.get("KV_URL"));

// Lazy-loaded AWS SDK clients to reduce cold start on Deno Deploy
let _sesOutbound: any;
let _sesInbound: any;
let _s3: any;

async function getSesOutbound() {
  if (!_sesOutbound) {
    const { SESClient } = await import("@aws-sdk/client-ses");
    _sesOutbound = new SESClient({ region: Deno.env.get("AWS_REGION") ?? "us-east-2" });
  }
  return _sesOutbound;
}

async function getSesInbound() {
  if (!_sesInbound) {
    const { SESClient } = await import("@aws-sdk/client-ses");
    _sesInbound = new SESClient({ region: Deno.env.get("AWS_SES_INBOUND_REGION") ?? "us-east-1" });
  }
  return _sesInbound;
}

async function getS3() {
  if (!_s3) {
    const { S3Client } = await import("@aws-sdk/client-s3");
    _s3 = new S3Client({ region: Deno.env.get("AWS_SES_INBOUND_REGION") ?? "us-east-1" });
  }
  return _s3;
}

const SNS_TOPIC_ARN = Deno.env.get("SNS_TOPIC_ARN") ?? "";
const RECEIPT_RULE_SET = Deno.env.get("SES_RULE_SET") ?? "formmy-email-forwarding";
const S3_BUCKET = Deno.env.get("S3_BUCKET") ?? "mailmask-inbound";

// --- Health check ---

export async function checkSesHealth(): Promise<boolean> {
  try {
    const ses = await getSesOutbound();
    const { GetSendQuotaCommand } = await import("@aws-sdk/client-ses");
    await ses.send(new GetSendQuotaCommand({}));
    return true;
  } catch {
    return false;
  }
}

// --- Domain verification ---

export interface DnsRecords {
  verificationToken: string; // TXT record value for _amazonses.domain
  dkimTokens: string[]; // CNAME records for DKIM
}

export async function verifyDomain(domain: string): Promise<DnsRecords> {
  const ses = await getSesInbound();
  const { VerifyDomainIdentityCommand, VerifyDomainDkimCommand } = await import("@aws-sdk/client-ses");

  const verifyRes = await ses.send(new VerifyDomainIdentityCommand({ Domain: domain }));
  const verificationToken = verifyRes.VerificationToken ?? "";

  const dkimRes = await ses.send(new VerifyDomainDkimCommand({ Domain: domain }));
  const dkimTokens = dkimRes.DkimTokens ?? [];

  // Create configuration set for outbound tracking (bounces/complaints)
  try {
    await createConfigurationSet(domain);
  } catch (err) {
    log("warn", "ses", "Could not create configuration set (may already exist)", { domain, error: String(err) });
  }

  return { verificationToken, dkimTokens };
}

// --- Configuration sets (outbound tracking) ---

function configSetName(domain: string): string {
  return `mailmask-${domain.replace(/\./g, "-")}`;
}

async function createConfigurationSet(domain: string): Promise<void> {
  const ses = await getSesOutbound();
  const { CreateConfigurationSetCommand, CreateConfigurationSetEventDestinationCommand } = await import("@aws-sdk/client-ses");
  const name = configSetName(domain);

  try {
    await ses.send(new CreateConfigurationSetCommand({
      ConfigurationSet: { Name: name },
    }));
  } catch (err: any) {
    // AlreadyExists is fine
    if (!String(err).includes("AlreadyExists")) throw err;
  }

  const snsTopicArn = Deno.env.get("SNS_OUTBOUND_TOPIC_ARN");
  if (snsTopicArn) {
    try {
      await ses.send(new CreateConfigurationSetEventDestinationCommand({
        ConfigurationSetName: name,
        EventDestination: {
          Name: `${name}-events`,
          Enabled: true,
          MatchingEventTypes: ["bounce", "complaint"],
          SNSDestination: { TopicARN: snsTopicArn },
        },
      }));
    } catch (err: any) {
      if (!String(err).includes("AlreadyExists")) {
        log("warn", "ses", "Could not create event destination", { domain, error: String(err) });
      }
    }
  }
}

export function getConfigSetName(domain: string): string {
  return configSetName(domain);
}

export async function checkDomainStatus(domain: string): Promise<{ verified: boolean; dkimVerified: boolean }> {
  try {
    const ses = await getSesInbound();
    const { GetIdentityVerificationAttributesCommand } = await import("@aws-sdk/client-ses");
    const res = await ses.send(new GetIdentityVerificationAttributesCommand({ Identities: [domain] }));
    const attrs = res.VerificationAttributes?.[domain];
    if (!attrs) return { verified: false, dkimVerified: false };

    return {
      verified: attrs.VerificationStatus === "Success",
      dkimVerified: false,
    };
  } catch {
    return { verified: false, dkimVerified: false };
  }
}

// --- Receipt rule (SES inbound) ---

export async function createReceiptRule(domain: string): Promise<void> {
  if (!SNS_TOPIC_ARN) throw new Error("SNS_TOPIC_ARN is required to create receipt rules");

  const ses = await getSesInbound();
  const { CreateReceiptRuleCommand } = await import("@aws-sdk/client-ses");
  const ruleName = `mailmask-${domain.replace(/\./g, "-")}`;

  await ses.send(new CreateReceiptRuleCommand({
    RuleSetName: RECEIPT_RULE_SET,
    Rule: {
      Name: ruleName,
      Enabled: true,
      Recipients: [domain],
      Actions: [
        {
          S3Action: {
            BucketName: S3_BUCKET,
            ObjectKeyPrefix: `inbound/${domain}/`,
            TopicArn: SNS_TOPIC_ARN,
          },
        },
      ],
      ScanEnabled: true,
    },
  }));
}

export async function repairReceiptRules(): Promise<number> {
  if (!SNS_TOPIC_ARN) {
    log("warn", "ses", "SNS_TOPIC_ARN not set, skipping receipt rule repair");
    return 0;
  }

  const ses = await getSesInbound();
  const { DescribeReceiptRuleSetCommand, UpdateReceiptRuleCommand } = await import("@aws-sdk/client-ses");

  const res = await ses.send(new DescribeReceiptRuleSetCommand({ RuleSetName: RECEIPT_RULE_SET }));
  const rules = res.Rules ?? [];
  let repaired = 0;

  for (const rule of rules) {
    const actions = rule.Actions ?? [];
    let needsUpdate = false;

    for (const action of actions) {
      if (action.S3Action && !action.S3Action.TopicArn) {
        action.S3Action.TopicArn = SNS_TOPIC_ARN;
        needsUpdate = true;
      }
    }

    if (needsUpdate) {
      await ses.send(new UpdateReceiptRuleCommand({
        RuleSetName: RECEIPT_RULE_SET,
        Rule: rule,
      }));
      log("info", "ses", `Repaired receipt rule: ${rule.Name}`, { ruleName: rule.Name });
      repaired++;
    }
  }

  return repaired;
}

export async function deleteReceiptRule(domain: string): Promise<void> {
  const ses = await getSesInbound();
  const { DeleteReceiptRuleCommand } = await import("@aws-sdk/client-ses");
  const ruleName = `mailmask-${domain.replace(/\./g, "-")}`;
  try {
    await ses.send(new DeleteReceiptRuleCommand({
      RuleSetName: RECEIPT_RULE_SET,
      RuleName: ruleName,
    }));
  } catch {
    // Rule may not exist, ignore
  }
}

export async function deleteDomainIdentity(domain: string): Promise<void> {
  try {
    const ses = await getSesInbound();
    const { DeleteIdentityCommand } = await import("@aws-sdk/client-ses");
    await ses.send(new DeleteIdentityCommand({ Identity: domain }));
  } catch (err) {
    log("warn", "ses", "Could not delete domain identity", { domain, error: String(err) });
  }
}

export async function deleteConfigurationSet(domain: string): Promise<void> {
  try {
    const ses = await getSesOutbound();
    const { DeleteConfigurationSetCommand } = await import("@aws-sdk/client-ses");
    await ses.send(new DeleteConfigurationSetCommand({
      ConfigurationSetName: configSetName(domain),
    }));
  } catch (err) {
    log("warn", "ses", "Could not delete configuration set", { domain, error: String(err) });
  }
}

// --- Fetch raw email from S3 ---

export async function fetchEmailFromS3(bucketName: string, objectKey: string): Promise<string> {
  const s3 = await getS3();
  const { GetObjectCommand } = await import("@aws-sdk/client-s3");
  const res = await s3.send(new GetObjectCommand({ Bucket: bucketName, Key: objectKey }));
  return await res.Body!.transformToString("utf-8");
}

// --- Email forwarding ---

export async function forwardEmail(originalRaw: string, from: string, to: string, aliasDomain: string): Promise<void> {
  const ses = await getSesOutbound();
  const { SendRawEmailCommand } = await import("@aws-sdk/client-ses");

  const forwardingAddress = Deno.env.get("FORWARDING_FROM") ?? "mailmask@easybits.cloud";

  // Rewrite From header and add Reply-To so replies go to original sender
  let rewrittenRaw = originalRaw.replace(
    /^From:\s*.+$/mi,
    `From: "${from}" <${forwardingAddress}>\r\nReply-To: ${from}`,
  );

  // Remove/rewrite headers that SES validates against verified identities
  rewrittenRaw = rewrittenRaw.replace(/^Return-Path:\s*.+$/mi, `Return-Path: <${forwardingAddress}>`);
  rewrittenRaw = rewrittenRaw.replace(/^Sender:\s*.+$/mi, "");

  const extraHeaders = [
    `X-MailMask-Forwarded: true`,
    `X-Original-To: ${to}`,
  ].join("\r\n");

  const firstNewline = rewrittenRaw.indexOf("\r\n");
  rewrittenRaw = firstNewline >= 0
    ? rewrittenRaw.slice(0, firstNewline) + "\r\n" + extraHeaders + rewrittenRaw.slice(firstNewline)
    : extraHeaders + "\r\n" + rewrittenRaw;

  await ses.send(new SendRawEmailCommand({
    RawMessage: { Data: new TextEncoder().encode(rewrittenRaw) },
    Source: forwardingAddress,
    Destinations: [to],
  }));
}

// --- Send from domain (SMTP outbound) ---

export async function sendFromDomain(from: string, to: string, subject: string, body: string, opts?: { html?: string; replyTo?: string; configSet?: string; inReplyTo?: string; references?: string }): Promise<string> {
  const ses = await getSesOutbound();
  const { SendRawEmailCommand } = await import("@aws-sdk/client-ses");

  const messageId = `<${crypto.randomUUID()}@${from.split("@")[1] ?? "mailmask.app"}>`;
  const boundary = `----=_Part_${Date.now()}`;
  const headers = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    `Message-ID: ${messageId}`,
    `MIME-Version: 1.0`,
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
  ];
  if (opts?.replyTo) headers.push(`Reply-To: ${opts.replyTo}`);
  if (opts?.inReplyTo) headers.push(`In-Reply-To: ${opts.inReplyTo}`);
  if (opts?.references) headers.push(`References: ${opts.references}`);

  const parts = [
    `--${boundary}`,
    `Content-Type: text/plain; charset=UTF-8`,
    `Content-Transfer-Encoding: 7bit`,
    ``,
    body,
  ];
  if (opts?.html) {
    parts.push(
      ``,
      `--${boundary}`,
      `Content-Type: text/html; charset=UTF-8`,
      `Content-Transfer-Encoding: 7bit`,
      ``,
      opts.html,
    );
  }
  parts.push(``, `--${boundary}--`);

  const rawEmail = [...headers, ``, ...parts].join("\r\n");

  // deno-lint-ignore no-explicit-any
  const cmd: any = {
    RawMessage: { Data: new TextEncoder().encode(rawEmail) },
    Source: from,
    Destinations: [to],
  };
  if (opts?.configSet) cmd.ConfigurationSetName = opts.configSet;

  await ses.send(new SendRawEmailCommand(cmd));
  return messageId;
}

// --- S3 backup helpers ---

const BACKUP_BUCKET = Deno.env.get("S3_BACKUP_BUCKET") ?? "mailmask-inbound";
const BACKUP_PREFIX = "backups/";
const BACKUP_RETENTION = 7;

export async function putBackupToS3(key: string, data: string): Promise<void> {
  const s3 = await getS3();
  const { PutObjectCommand } = await import("@aws-sdk/client-s3");
  await s3.send(new PutObjectCommand({
    Bucket: BACKUP_BUCKET,
    Key: `${BACKUP_PREFIX}${key}`,
    Body: new TextEncoder().encode(data),
    ContentType: "application/json",
  }));
}

export async function deleteOldBackups(): Promise<void> {
  const s3 = await getS3();
  const { ListObjectsV2Command, DeleteObjectCommand } = await import("@aws-sdk/client-s3");
  const res = await s3.send(new ListObjectsV2Command({
    Bucket: BACKUP_BUCKET,
    Prefix: BACKUP_PREFIX,
  }));
  const objects = res.Contents ?? [];
  // Sort by key (date-based), oldest first
  objects.sort((a: any, b: any) => (a.Key ?? "").localeCompare(b.Key ?? ""));
  const toDelete = objects.slice(0, Math.max(0, objects.length - BACKUP_RETENTION));
  for (const obj of toDelete) {
    if (obj.Key) {
      await s3.send(new DeleteObjectCommand({ Bucket: BACKUP_BUCKET, Key: obj.Key }));
    }
  }
}

// --- Admin backup listing/download ---

export async function listBackups(): Promise<{ key: string; date: string; sizeBytes: number }[]> {
  const s3 = await getS3();
  const { ListObjectsV2Command } = await import("@aws-sdk/client-s3");
  const res = await s3.send(new ListObjectsV2Command({
    Bucket: BACKUP_BUCKET,
    Prefix: BACKUP_PREFIX,
  }));
  const objects = res.Contents ?? [];
  return objects
    .map((obj: any) => ({
      key: (obj.Key ?? "").replace(BACKUP_PREFIX, ""),
      date: obj.LastModified?.toISOString() ?? "",
      sizeBytes: obj.Size ?? 0,
    }))
    .sort((a: any, b: any) => b.date.localeCompare(a.date));
}

export async function getBackupFromS3(key: string): Promise<string> {
  const s3 = await getS3();
  const { GetObjectCommand } = await import("@aws-sdk/client-s3");
  const res = await s3.send(new GetObjectCommand({
    Bucket: BACKUP_BUCKET,
    Key: `${BACKUP_PREFIX}${key}`,
  }));
  return await res.Body!.transformToString("utf-8");
}

export async function deleteBackupFromS3(key: string): Promise<void> {
  const s3 = await getS3();
  const { DeleteObjectCommand } = await import("@aws-sdk/client-s3");
  await s3.send(new DeleteObjectCommand({
    Bucket: BACKUP_BUCKET,
    Key: `${BACKUP_PREFIX}${key}`,
  }));
}

// --- SNS subscription verification ---

let _sns: any;
async function getSns() {
  if (!_sns) {
    const { SNSClient } = await import("@aws-sdk/client-sns");
    _sns = new SNSClient({ region: Deno.env.get("AWS_SES_INBOUND_REGION") ?? "us-east-1" });
  }
  return _sns;
}

export async function ensureSnsSubscription(appUrl: string): Promise<string> {
  if (!SNS_TOPIC_ARN) {
    log("warn", "ses", "SNS_TOPIC_ARN not set, skipping SNS subscription check");
    return "skipped";
  }

  const endpoint = `${appUrl.replace(/\/+$/, "")}/api/webhooks/ses-inbound`;
  const sns = await getSns();
  const { ListSubscriptionsByTopicCommand, SubscribeCommand } = await import("@aws-sdk/client-sns");

  const res = await sns.send(new ListSubscriptionsByTopicCommand({ TopicArn: SNS_TOPIC_ARN }));
  const subscriptions = res.Subscriptions ?? [];

  const existing = subscriptions.find(
    (s: any) => s.Protocol === "https" && s.Endpoint === endpoint,
  );

  if (existing) {
    log("info", "ses", "SNS subscription already exists", { endpoint, arn: existing.SubscriptionArn });
    return "exists";
  }

  await sns.send(new SubscribeCommand({
    TopicArn: SNS_TOPIC_ARN,
    Protocol: "https",
    Endpoint: endpoint,
  }));

  log("info", "ses", "Created SNS subscription", { endpoint });
  return "created";
}

// --- Admin alerts with throttle ---

export async function sendAlert(alertType: string, message: string): Promise<boolean> {
  const alertEmail = Deno.env.get("ALERT_EMAIL") ?? "brenda@fixter.org,contacto@fixter.org";
  if (!alertEmail) return false;

  // Throttle: max 1 alert of same type per hour
  const throttleKey = ["alert-throttle", alertType];
  const existing = await alertKv.get(throttleKey);
  if (existing.value) return false;

  const alertFrom = Deno.env.get("ALERT_FROM_EMAIL") ?? "noreply@mailmask.app";
  const recipients = alertEmail.split(",").map((e) => e.trim()).filter(Boolean);
  try {
    const ses = await getSesOutbound();
    const { SendRawEmailCommand } = await import("@aws-sdk/client-ses");
    const boundary = `----=_Part_${Date.now()}`;
    const rawEmail = [
      `From: ${alertFrom}`,
      `To: ${recipients.join(", ")}`,
      `Subject: [MailMask Alert] ${alertType}`,
      `MIME-Version: 1.0`,
      `Content-Type: multipart/alternative; boundary="${boundary}"`,
      ``,
      `--${boundary}`,
      `Content-Type: text/plain; charset=UTF-8`,
      `Content-Transfer-Encoding: 7bit`,
      ``,
      message,
      ``,
      `--${boundary}--`,
    ].join("\r\n");
    await ses.send(new SendRawEmailCommand({
      RawMessage: { Data: new TextEncoder().encode(rawEmail) },
      Source: alertFrom,
      Destinations: recipients,
    }));
    await alertKv.set(throttleKey, true, { expireIn: 60 * 60 * 1000 }); // 1h
    return true;
  } catch (err) {
    log("error", "ses", "Failed to send alert", { alertType, error: String(err) });
    return false;
  }
}
