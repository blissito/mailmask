import { SESClient, VerifyDomainIdentityCommand, VerifyDomainDkimCommand, GetIdentityVerificationAttributesCommand, SendRawEmailCommand, CreateReceiptRuleCommand, DeleteReceiptRuleCommand, DescribeReceiptRuleSetCommand } from "@aws-sdk/client-ses";
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";

const ses = new SESClient({ region: Deno.env.get("AWS_REGION") ?? "us-east-1" });
const s3 = new S3Client({ region: Deno.env.get("AWS_REGION") ?? "us-east-1" });

const SNS_TOPIC_ARN = Deno.env.get("SNS_TOPIC_ARN") ?? "";
const RECEIPT_RULE_SET = Deno.env.get("SES_RULE_SET") ?? "formmy-email-forwarding";
const S3_BUCKET = Deno.env.get("S3_BUCKET") ?? "mailmask-inbound";

// --- Domain verification ---

export interface DnsRecords {
  verificationToken: string; // TXT record value for _amazonses.domain
  dkimTokens: string[]; // CNAME records for DKIM
}

export async function verifyDomain(domain: string): Promise<DnsRecords> {
  // Step 1: Verify domain identity (TXT record)
  const verifyRes = await ses.send(new VerifyDomainIdentityCommand({ Domain: domain }));
  const verificationToken = verifyRes.VerificationToken ?? "";

  // Step 2: Enable DKIM (CNAME records)
  const dkimRes = await ses.send(new VerifyDomainDkimCommand({ Domain: domain }));
  const dkimTokens = dkimRes.DkimTokens ?? [];

  return { verificationToken, dkimTokens };
}

export async function checkDomainStatus(domain: string): Promise<{ verified: boolean; dkimVerified: boolean }> {
  try {
    const res = await ses.send(new GetIdentityVerificationAttributesCommand({ Identities: [domain] }));
    const attrs = res.VerificationAttributes?.[domain];
    if (!attrs) return { verified: false, dkimVerified: false };

    return {
      verified: attrs.VerificationStatus === "Success",
      dkimVerified: false, // DKIM status needs separate check via SESv2 if needed
    };
  } catch {
    return { verified: false, dkimVerified: false };
  }
}

// --- Receipt rule (SES inbound) ---

export async function createReceiptRule(domain: string): Promise<void> {
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
  const res = await s3.send(new GetObjectCommand({ Bucket: bucketName, Key: objectKey }));
  return await res.Body!.transformToString("utf-8");
}

// --- Email forwarding ---

export async function forwardEmail(originalRaw: string, from: string, to: string): Promise<void> {
  // Rewrite envelope: keep original headers but change envelope recipient
  // Add X-Forwarded-For and X-Forwarded-To headers
  const headers = [
    `X-MailMask-Forwarded: true`,
    `X-Original-To: ${to}`,
  ].join("\r\n");

  // Insert our headers after the first line of the raw email
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

// --- Test helpers ---

let _sesClient = ses;
export function _injectSesClient(client: any) {
  _sesClient = client;
}
