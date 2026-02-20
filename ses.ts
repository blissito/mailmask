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
const RECEIPT_RULE_SET = Deno.env.get("SES_RULE_SET") ?? "mailmask-email-forwarding";
const S3_BUCKET = Deno.env.get("S3_BUCKET") ?? "mailmask-inbound";

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

  return { verificationToken, dkimTokens };
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

// --- Fetch raw email from S3 ---

export async function fetchEmailFromS3(bucketName: string, objectKey: string): Promise<string> {
  const s3 = await getS3();
  const { GetObjectCommand } = await import("@aws-sdk/client-s3");
  const res = await s3.send(new GetObjectCommand({ Bucket: bucketName, Key: objectKey }));
  return await res.Body!.transformToString("utf-8");
}

// --- Email forwarding ---

export async function forwardEmail(originalRaw: string, from: string, to: string): Promise<void> {
  const ses = await getSesOutbound();
  const { SendRawEmailCommand } = await import("@aws-sdk/client-ses");

  const headers = [
    `X-MailMask-Forwarded: true`,
    `X-Original-To: ${to}`,
  ].join("\r\n");

  const firstNewline = originalRaw.indexOf("\r\n");
  const rewrittenRaw = firstNewline >= 0
    ? originalRaw.slice(0, firstNewline) + "\r\n" + headers + originalRaw.slice(firstNewline)
    : headers + "\r\n" + originalRaw;

  await ses.send(new SendRawEmailCommand({
    RawMessage: { Data: new TextEncoder().encode(rewrittenRaw) },
    Source: from,
    Destinations: [to],
  }));
}

// --- Send from domain (SMTP outbound) ---

export async function sendFromDomain(from: string, to: string, subject: string, body: string): Promise<void> {
  const ses = await getSesOutbound();
  const { SendRawEmailCommand } = await import("@aws-sdk/client-ses");

  const boundary = `----=_Part_${Date.now()}`;
  const rawEmail = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    `MIME-Version: 1.0`,
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    ``,
    `--${boundary}`,
    `Content-Type: text/plain; charset=UTF-8`,
    `Content-Transfer-Encoding: 7bit`,
    ``,
    body,
    ``,
    `--${boundary}--`,
  ].join("\r\n");

  await ses.send(new SendRawEmailCommand({
    RawMessage: { Data: new TextEncoder().encode(rawEmail) },
    Source: from,
    Destinations: [to],
  }));
}
