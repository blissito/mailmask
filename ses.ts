import { log } from "./logger.js";
import { db } from "./pg.js";
import { tokens } from "./schema.js";
import { eq, and, gt } from "drizzle-orm";

// Lazy-loaded AWS SDK clients to reduce cold start on Deno Deploy
let _sesOutbound: any;
let _sesInbound: any;
let _s3: any;

async function getSesOutbound() {
  if (!_sesOutbound) {
    const { SESClient } = await import("@aws-sdk/client-ses");
    _sesOutbound = new SESClient({ region: process.env.AWS_REGION ?? "us-east-2" });
  }
  return _sesOutbound;
}

async function getSesInbound() {
  if (!_sesInbound) {
    const { SESClient } = await import("@aws-sdk/client-ses");
    _sesInbound = new SESClient({ region: process.env.AWS_SES_INBOUND_REGION ?? "us-east-1" });
  }
  return _sesInbound;
}

async function getS3() {
  if (!_s3) {
    const { S3Client } = await import("@aws-sdk/client-s3");
    _s3 = new S3Client({ region: process.env.AWS_SES_INBOUND_REGION ?? "us-east-1" });
  }
  return _s3;
}

const SNS_TOPIC_ARN = process.env.SNS_TOPIC_ARN ?? "";
const RECEIPT_RULE_SET = process.env.SES_RULE_SET ?? "formmy-email-forwarding";
const S3_BUCKET = process.env.S3_BUCKET ?? "mailmask-inbound";

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

  const snsTopicArn = process.env.SNS_OUTBOUND_TOPIC_ARN;
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

// --- List inbound email keys from S3 ---

export async function listInboundEmailKeys(domain: string): Promise<{ key: string; lastModified: string; size: number }[]> {
  const s3 = await getS3();
  const { ListObjectsV2Command } = await import("@aws-sdk/client-s3");
  const prefix = `inbound/${domain}/`;
  const results: { key: string; lastModified: string; size: number }[] = [];
  let continuationToken: string | undefined;

  do {
    const res = await s3.send(new ListObjectsV2Command({
      Bucket: S3_BUCKET,
      Prefix: prefix,
      ContinuationToken: continuationToken,
    }));
    for (const obj of res.Contents ?? []) {
      if (obj.Key) {
        results.push({
          key: obj.Key,
          lastModified: obj.LastModified?.toISOString() ?? "",
          size: obj.Size ?? 0,
        });
      }
    }
    continuationToken = res.IsTruncated ? res.NextContinuationToken : undefined;
  } while (continuationToken);

  return results;
}

// --- Fetch partial email from S3 (headers only) ---

export async function fetchEmailHeadersFromS3(bucketName: string, objectKey: string, bytes = 4096): Promise<string> {
  const s3 = await getS3();
  const { GetObjectCommand } = await import("@aws-sdk/client-s3");
  const res = await s3.send(new GetObjectCommand({
    Bucket: bucketName,
    Key: objectKey,
    Range: `bytes=0-${bytes - 1}`,
  }));
  return await res.Body!.transformToString("utf-8");
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

  const forwardingAddress = process.env.FORWARDING_FROM ?? "reenvio@mailmask.studio";

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

  const messageId = `<${crypto.randomUUID()}@${from.split("@")[1] ?? "mailmask.studio"}>`;
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

// --- Delete S3 object (for purge) ---

export async function deleteEmailFromS3(bucket: string, key: string): Promise<void> {
  const s3 = await getS3();
  const { DeleteObjectCommand } = await import("@aws-sdk/client-s3");
  await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
}

// --- S3 backup helpers ---

const BACKUP_BUCKET = process.env.S3_BACKUP_BUCKET ?? "mailmask-inbound";
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

// --- SMTP Relay: IAM credential management ---

let _iam: any;
async function getIam() {
  if (!_iam) {
    const { IAMClient } = await import("@aws-sdk/client-iam");
    _iam = new IAMClient({ region: process.env.AWS_REGION ?? "us-east-2" });
  }
  return _iam;
}

const SES_SMTP_REGION = process.env.AWS_REGION ?? "us-east-2";

export async function deriveSesSmtpPassword(secretAccessKey: string, region: string): Promise<string> {
  const enc = new TextEncoder();
  const VERSION = 0x04;

  async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    const cryptoKey = await crypto.subtle.importKey("raw", (key as unknown as ArrayBuffer), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = await crypto.subtle.sign("HMAC", cryptoKey, (data as unknown as ArrayBuffer));
    return new Uint8Array(sig);
  }

  // AWS SES SMTP password derivation algorithm
  const DATE = "11111111";
  const SERVICE = "ses";

  let signature = await hmacSha256(enc.encode("AWS4" + secretAccessKey), enc.encode(DATE));
  signature = await hmacSha256(signature, enc.encode(region));
  signature = await hmacSha256(signature, enc.encode(SERVICE));
  signature = await hmacSha256(signature, new Uint8Array([VERSION]));

  // Prepend version byte and base64 encode
  const result = new Uint8Array(1 + signature.length);
  result[0] = VERSION;
  result.set(signature, 1);

  // Base64 encode
  let binary = "";
  for (const byte of result) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export async function createSmtpIamCredential(domain: string): Promise<{ iamUsername: string; accessKeyId: string; smtpPassword: string }> {
  const iam = await getIam();
  const {
    CreateUserCommand,
    PutUserPolicyCommand,
    CreateAccessKeyCommand,
  } = await import("@aws-sdk/client-iam");

  const iamUsername = `mailmask-smtp-${domain.replace(/\./g, "-")}-${Date.now()}`;

  // 1. Create IAM user
  await iam.send(new CreateUserCommand({ UserName: iamUsername }));

  // 2. Attach inline policy restricting to SendRawEmail for this domain only
  const policy = JSON.stringify({
    Version: "2012-10-17",
    Statement: [{
      Effect: "Allow",
      Action: ["ses:SendRawEmail", "ses:SendEmail"],
      Resource: "*",
      Condition: {
        StringLike: {
          "ses:FromAddress": `*@${domain}`,
        },
      },
    }],
  });

  await iam.send(new PutUserPolicyCommand({
    UserName: iamUsername,
    PolicyName: "ses-send",
    PolicyDocument: policy,
  }));

  // 3. Create access key
  const keyRes = await iam.send(new CreateAccessKeyCommand({ UserName: iamUsername }));
  const accessKeyId = keyRes.AccessKey!.AccessKeyId!;
  const secretAccessKey = keyRes.AccessKey!.SecretAccessKey!;

  // 4. Derive SMTP password from secret access key
  const smtpPassword = await deriveSesSmtpPassword(secretAccessKey, SES_SMTP_REGION);

  return { iamUsername, accessKeyId, smtpPassword };
}

export async function revokeSmtpIamCredential(iamUsername: string, accessKeyId: string): Promise<void> {
  const iam = await getIam();
  const {
    DeleteAccessKeyCommand,
    DeleteUserPolicyCommand,
    DeleteUserCommand,
  } = await import("@aws-sdk/client-iam");

  try {
    await iam.send(new DeleteAccessKeyCommand({ UserName: iamUsername, AccessKeyId: accessKeyId }));
  } catch (err) {
    log("warn", "iam", "Could not delete access key", { iamUsername, error: String(err) });
  }

  try {
    await iam.send(new DeleteUserPolicyCommand({ UserName: iamUsername, PolicyName: "ses-send" }));
  } catch (err) {
    log("warn", "iam", "Could not delete user policy", { iamUsername, error: String(err) });
  }

  try {
    await iam.send(new DeleteUserCommand({ UserName: iamUsername }));
  } catch (err) {
    log("warn", "iam", "Could not delete IAM user", { iamUsername, error: String(err) });
  }
}

// --- SNS subscription verification ---

let _sns: any;
async function getSns() {
  if (!_sns) {
    const { SNSClient } = await import("@aws-sdk/client-sns");
    _sns = new SNSClient({ region: process.env.AWS_SES_INBOUND_REGION ?? "us-east-1" });
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
    // If pending confirmation, delete and re-subscribe to trigger a new confirmation
    if (existing.SubscriptionArn === "PendingConfirmation") {
      log("info", "ses", "SNS subscription pending, will re-subscribe", { endpoint });
      // Can't delete PendingConfirmation subs, just re-subscribe to trigger new confirmation
      await sns.send(new SubscribeCommand({
        TopicArn: SNS_TOPIC_ARN,
        Protocol: "https",
        Endpoint: endpoint,
      }));
      log("info", "ses", "Re-subscribed SNS to trigger confirmation", { endpoint });
      return "re-subscribed";
    }
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
  const alertEmail = process.env.ALERT_EMAIL ?? "brenda@fixter.org,contacto@fixter.org";
  if (!alertEmail) return false;

  // Throttle: max 1 alert of same type per hour
  const throttleToken = `alert-throttle:${alertType}`;
  const existing = await db.select().from(tokens).where(
    and(eq(tokens.token, throttleToken), gt(tokens.expiresAt, new Date().toISOString()))
  );
  if (existing.length > 0) return false;

  const alertFrom = process.env.ALERT_FROM_EMAIL ?? "noreply@mailmask.studio";
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
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    await db.insert(tokens).values({
      token: throttleToken,
      kind: "alert-throttle",
      value: {},
      expiresAt,
    }).onConflictDoUpdate({ target: tokens.token, set: { expiresAt } });
    return true;
  } catch (err) {
    log("error", "ses", "Failed to send alert", { alertType, error: String(err) });
    return false;
  }
}
