import { log } from "./logger.js";
import { db } from "./pg.js";
import { tokens } from "./schema.js";
import { eq, and, gt } from "drizzle-orm";

// MailMask is pinned to us-east-1. SES inbound only exists in us-east-1,
// us-west-2 and eu-west-1, and all receipt rules, the inbound S3 bucket and
// every verified customer domain live there. Sending from another region would
// split sender reputation and separate inbound from outbound, so this is not
// configurable via env — a stray AWS_REGION secret must not be able to move it.
export const AWS_REGION = "us-east-1";

// Lazy-loaded AWS SDK clients to reduce cold start on Deno Deploy
let _sesOutbound: any;
let _sesInbound: any;
let _s3: any;

async function getSesOutbound() {
  if (!_sesOutbound) {
    const { SESClient } = await import("@aws-sdk/client-ses");
    _sesOutbound = new SESClient({ region: AWS_REGION });
  }
  return _sesOutbound;
}

async function getSesInbound() {
  if (!_sesInbound) {
    const { SESClient } = await import("@aws-sdk/client-ses");
    _sesInbound = new SESClient({ region: AWS_REGION });
  }
  return _sesInbound;
}

async function getS3() {
  if (!_s3) {
    const { S3Client } = await import("@aws-sdk/client-s3");
    _s3 = new S3Client({ region: AWS_REGION });
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

/**
 * Estado real del dominio en SES.
 *
 * `respondio` separa "SES dice que no está verificado" de "no pudimos
 * preguntarle". Antes todo error caía en `verified: false`, así que un parpadeo
 * de red se veía igual que un dominio caído; por miedo a eso, la ruta de verify
 * dejó de preguntar del todo y empezó a responder `true` de memoria. Resultado:
 * un dominio podía desaparecer de SES —como pasó con brendago.design— y MailMask
 * seguía jurando que estaba verificado, sin poder enviar ni recibir.
 */
export async function checkDomainStatus(
  domain: string
): Promise<{ verified: boolean; dkimVerified: boolean; respondio: boolean }> {
  try {
    const ses = await getSesInbound();
    const { GetIdentityVerificationAttributesCommand, GetIdentityDkimAttributesCommand } =
      await import("@aws-sdk/client-ses");
    const res = await ses.send(new GetIdentityVerificationAttributesCommand({ Identities: [domain] }));
    const attrs = res.VerificationAttributes?.[domain];

    // Sin atributos, SES respondió y no conoce el dominio: eso es un "no"
    // legítimo, no una falla de consulta.
    if (!attrs) return { verified: false, dkimVerified: false, respondio: true };

    // El DKIM se consultaba nunca y se reportaba siempre como false.
    let dkimVerified = false;
    try {
      const dkim = await ses.send(new GetIdentityDkimAttributesCommand({ Identities: [domain] }));
      dkimVerified = dkim.DkimAttributes?.[domain]?.DkimVerificationStatus === "Success";
    } catch {
      // El DKIM es accesorio para decidir si el dominio existe.
    }

    return {
      verified: attrs.VerificationStatus === "Success",
      dkimVerified,
      respondio: true,
    };
  } catch (err) {
    log("warn", "ses", "No se pudo consultar el estado del dominio", { domain, error: String(err) });
    return { verified: false, dkimVerified: false, respondio: false };
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

// Remove headers (and their folded continuation lines) from the header block only,
// never from the body. Used to drop signatures that no longer apply after we rewrite From.
function stripHeaders(raw: string, names: string[]): string {
  const sepMatch = raw.match(/\r?\n\r?\n/);
  const sepIdx = sepMatch?.index ?? -1;
  const headerBlock = sepIdx >= 0 ? raw.slice(0, sepIdx) : raw;
  const rest = sepIdx >= 0 ? raw.slice(sepIdx) : "";
  const prefixes = names.map((n) => n.toLowerCase() + ":");

  const kept: string[] = [];
  let skipping = false;
  for (const line of headerBlock.split(/\r?\n/)) {
    if (/^[ \t]/.test(line)) {
      // Folded continuation: belongs to whatever header we last decided on
      if (!skipping) kept.push(line);
      continue;
    }
    skipping = prefixes.some((p) => line.toLowerCase().startsWith(p));
    if (!skipping) kept.push(line);
  }
  return kept.join("\r\n") + rest;
}

export async function forwardEmail(originalRaw: string, from: string, to: string, aliasDomain: string): Promise<void> {
  const ses = await getSesOutbound();
  const { SendRawEmailCommand } = await import("@aws-sdk/client-ses");

  // The sender's DKIM signature covers the original From, which we rewrite below, so it
  // is already invalid. Worse, SES signs outbound mail itself and rejects the message
  // with "Duplicate header 'DKIM-Signature'" if the original signature is still present.
  // ARC/DomainKey signatures and Sender are dropped for the same reason.
  originalRaw = stripHeaders(originalRaw, [
    "DKIM-Signature",
    "DomainKey-Signature",
    "ARC-Seal",
    "ARC-Message-Signature",
    "ARC-Authentication-Results",
    "Sender",
  ]);

  // Use the alias domain for From so emails show the user's domain, not mailmask.studio
  const forwardingAddress = `reenvio@${aliasDomain}`;

  // Rewrite From header and add Reply-To so replies go to original sender
  let rewrittenRaw = originalRaw.replace(
    /^From:\s*.+$/mi,
    `From: "${from}" <${forwardingAddress}>\r\nReply-To: ${from}`,
  );

  // Remove/rewrite headers that SES validates against verified identities
  rewrittenRaw = rewrittenRaw.replace(/^Return-Path:\s*.+$/mi, `Return-Path: <${forwardingAddress}>`);

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

// Un CR o LF en un valor de header permite inyectar headers arbitrarios (un Bcc:, por
// ejemplo). Los valores vienen de input del usuario — asunto, destinatario, reply-to —
// así que se limpian antes de armar el mensaje.
function stripHeaderInjection(value: string): string {
  return value.replace(/[\r\n]+/g, " ").trim();
}

// RFC 2047. Un header solo admite ASCII: un asunto como "Cotización" metería bytes UTF-8
// crudos. Se deja pasar lo que ya viene encoded (típico del correo entrante, que se
// reenvía tal cual en las respuestas).
export function encodeHeader(value: string): string {
  const clean = stripHeaderInjection(value);
  if (!clean) return "";
  // Solo se deja pasar si TODO el valor son encoded-words. Con un prefijo bastaba para
  // colar bytes crudos en la cola ("=?UTF-8?Q?Pedido?= confirmado señor").
  if (/^(=\?[^?]+\?[BQbq]\?[^?]*\?=)(\s+=\?[^?]+\?[BQbq]\?[^?]*\?=)*$/.test(clean)) return clean;
  // deno-lint-ignore no-control-regex
  if (!/[^\x00-\x7F]/.test(clean)) return clean;

  // RFC 2047 topa cada encoded-word en 75 caracteres, así que se parte en varios
  // plegados con CRLF+espacio. Un solo encoded-word largo podía superar el límite de
  // 998 caracteres por línea y hacer que SES rechazara el mensaje entero.
  const words: string[] = [];
  let chunk = "";
  for (const ch of clean) {
    const candidate = chunk + ch;
    // 45 bytes → 60 chars de base64, más el envoltorio =?UTF-8?B?...?= cabe en 75.
    if (Buffer.byteLength(candidate, "utf8") > 45) {
      words.push(`=?UTF-8?B?${Buffer.from(chunk, "utf8").toString("base64")}?=`);
      chunk = ch;
    } else {
      chunk = candidate;
    }
  }
  if (chunk) words.push(`=?UTF-8?B?${Buffer.from(chunk, "utf8").toString("base64")}?=`);
  return words.join("\r\n ");
}

// "Nombre <a@b.com>" → "a@b.com". Las conversaciones reconstruidas desde S3 guardan el
// From con display name, y eso no sirve ni como destinatario de SES ni para buscar en la
// lista de supresión.
export function normalizeAddress(value: string): string {
  // Se toma el grupo MÁS INTERNO: un valor anidado ("A <B <x@y>>") con `<([^>]+)>`
  // devolvía "B <x@y", sin cerrar, y SES respondía "Missing '>'".
  const m = value.match(/<([^<>]+)>/);
  return stripHeaderInjection(m ? m[1] : value).toLowerCase();
}

/** Imagen incrustada en el cuerpo con `cid:`, como hace Gmail al insertar una foto. */
export interface InlineImage {
  /** Identificador referenciado desde el HTML como `src="cid:..."`. */
  cid: string;
  contentType: string;
  data: Uint8Array;
  filename?: string;
}

/** Archivo adjunto: se descarga aparte, no se muestra dentro del cuerpo. */
export interface Attachment {
  filename: string;
  contentType: string;
  data: Uint8Array;
}

// SendRawEmail (SES v1) topa el mensaje en 10 MB y base64 infla ~33%, así que el
// contenido útil real es menor. Se corta antes de llegar a SES para poder dar un
// error entendible en vez de un rechazo del proveedor.
export const MAX_RAW_MESSAGE_BYTES = 9 * 1024 * 1024;

export async function sendFromDomain(from: string, to: string, subject: string, body: string, opts?: { html?: string; replyTo?: string; configSet?: string; inReplyTo?: string; references?: string; inlineImages?: InlineImage[]; attachments?: Attachment[]; cc?: string[]; bcc?: string[] }): Promise<string> {
  const ses = await getSesOutbound();
  const { SendRawEmailCommand } = await import("@aws-sdk/client-ses");

  // El header From conserva el display name si viene ("MailMask <alertas@...>"); el
  // sobre de SES necesita la dirección pelada.
  const fromAddr = normalizeAddress(from);
  const toAddr = normalizeAddress(to);
  const fromHeader = /<[^>]+>/.test(from) ? stripHeaderInjection(from) : fromAddr;
  const messageId = `<${crypto.randomUUID()}@${fromAddr.split("@")[1] ?? "mailmask.studio"}>`;
  const stamp = Date.now();
  const altBoundary = `----=_Alt_${stamp}`;
  const relBoundary = `----=_Rel_${stamp}`;
  const mixBoundary = `----=_Mix_${stamp}`;

  // El correo se arma en capas, de dentro hacia fuera, y sólo se añade la capa que
  // hace falta. Es la misma estructura que produce Gmail:
  //
  //   multipart/mixed        ← si hay adjuntos
  //     multipart/related    ← si hay imágenes incrustadas (cid:)
  //       multipart/alternative   ← siempre: texto plano + HTML
  //
  // Envolver de más no es inocuo: algunos clientes muestran un clip de "adjunto"
  // por el simple hecho de ver un multipart/mixed, aunque venga vacío.
  const inline = opts?.inlineImages?.length ? opts.inlineImages : null;
  const attachments = opts?.attachments?.length ? opts.attachments : null;

  const outerType = attachments
    ? `multipart/mixed; boundary="${mixBoundary}"`
    : inline
    ? `multipart/related; type="multipart/alternative"; boundary="${relBoundary}"`
    : `multipart/alternative; boundary="${altBoundary}"`;

  // Cc va en los headers y Bcc NO: ése es justo el punto de la copia oculta. Ambos
  // sí entran en Destinations, que es a quien SES entrega de verdad.
  const ccList = (opts?.cc ?? []).map(normalizeAddress).filter(Boolean);
  const bccList = (opts?.bcc ?? []).map(normalizeAddress).filter(Boolean);

  const headers = [
    `From: ${fromHeader}`,
    `To: ${toAddr}`,
    ...(ccList.length ? [`Cc: ${ccList.join(", ")}`] : []),
    `Subject: ${encodeHeader(subject)}`,
    `Message-ID: ${messageId}`,
    `MIME-Version: 1.0`,
    `Content-Type: ${outerType}`,
  ];
  if (opts?.replyTo) headers.push(`Reply-To: ${normalizeAddress(opts.replyTo)}`);
  if (opts?.inReplyTo) headers.push(`In-Reply-To: ${stripHeaderInjection(opts.inReplyTo)}`);
  if (opts?.references) headers.push(`References: ${stripHeaderInjection(opts.references)}`);

  // base64: el cuerpo es UTF-8 y declararlo 7bit es mentira — se corrompe en tránsito.
  const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64").replace(/(.{76})/g, "$1\r\n");
  const b64bin = (d: Uint8Array) => Buffer.from(d).toString("base64").replace(/(.{76})/g, "$1\r\n");

  // --- capa 1: alternative (texto plano + HTML) ---
  let lines: string[] = [
    `--${altBoundary}`,
    `Content-Type: text/plain; charset=UTF-8`,
    `Content-Transfer-Encoding: base64`,
    ``,
    b64(body),
  ];
  if (opts?.html) {
    lines.push(
      ``,
      `--${altBoundary}`,
      `Content-Type: text/html; charset=UTF-8`,
      `Content-Transfer-Encoding: base64`,
      ``,
      b64(opts.html),
    );
  }
  lines.push(``, `--${altBoundary}--`);

  // --- capa 2: related (imágenes referenciadas por cid) ---
  if (inline) {
    lines = [
      `--${relBoundary}`,
      `Content-Type: multipart/alternative; boundary="${altBoundary}"`,
      ``,
      ...lines,
    ];
    for (const img of inline) {
      // El Content-ID va entre ángulos; el HTML lo referencia SIN ellos.
      lines.push(
        ``,
        `--${relBoundary}`,
        `Content-Type: ${stripHeaderInjection(img.contentType)}`,
        `Content-Transfer-Encoding: base64`,
        `Content-ID: <${stripHeaderInjection(img.cid)}>`,
        `Content-Disposition: inline; filename="${stripHeaderInjection(img.filename ?? img.cid)}"`,
        ``,
        b64bin(img.data),
      );
    }
    lines.push(``, `--${relBoundary}--`);
  }

  // --- capa 3: mixed (archivos adjuntos) ---
  if (attachments) {
    const innerType = inline
      ? `multipart/related; type="multipart/alternative"; boundary="${relBoundary}"`
      : `multipart/alternative; boundary="${altBoundary}"`;
    lines = [`--${mixBoundary}`, `Content-Type: ${innerType}`, ``, ...lines];
    for (const file of attachments) {
      // El nombre se codifica RFC 2047: un adjunto llamado "cotización.pdf" llegaba
      // con la tilde rota en varios clientes.
      lines.push(
        ``,
        `--${mixBoundary}`,
        `Content-Type: ${stripHeaderInjection(file.contentType)}`,
        `Content-Transfer-Encoding: base64`,
        `Content-Disposition: attachment; filename="${encodeHeader(stripHeaderInjection(file.filename))}"`,
        ``,
        b64bin(file.data),
      );
    }
    lines.push(``, `--${mixBoundary}--`);
  }

  const rawEmail = [...headers, ``, ...lines].join("\r\n");
  if (Buffer.byteLength(rawEmail, "utf8") > MAX_RAW_MESSAGE_BYTES) {
    throw new Error("El correo excede el tamaño máximo. Usa archivos más ligeros.");
  }

  // deno-lint-ignore no-explicit-any
  const cmd: any = {
    RawMessage: { Data: new TextEncoder().encode(rawEmail) },
    Source: fromAddr,
    // Bcc entra aquí y no en los headers: así recibe la copia sin que los demás
    // destinatarios lo vean.
    Destinations: [toAddr, ...ccList, ...bccList],
  };
  if (opts?.configSet) cmd.ConfigurationSetName = opts.configSet;

  try {
    await ses.send(new SendRawEmailCommand(cmd));
  } catch (err: any) {
    // Auto-create configuration set if it doesn't exist in this region
    if (opts?.configSet && String(err).includes("ConfigurationSetDoesNotExist")) {
      const domain = from.split("@")[1] ?? "";
      try { await createConfigurationSet(domain); } catch { /* best effort */ }
      delete cmd.ConfigurationSetName;
      await ses.send(new SendRawEmailCommand(cmd));
    } else {
      throw err;
    }
  }
  return messageId;
}

// --- Delete S3 object (for purge) ---

export async function deleteEmailFromS3(bucket: string, key: string): Promise<void> {
  const s3 = await getS3();
  const { DeleteObjectCommand } = await import("@aws-sdk/client-s3");
  await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
}

// --- S3 backup helpers ---

const BACKUP_BUCKET = process.env.S3_BACKUP_BUCKET ?? "mailmask-backups";
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

// Full-database backups are gzipped SQLite files, so they must be uploaded as bytes.
// putBackupToS3 above encodes a string and hardcodes application/json, which would
// corrupt a binary body.
export async function putBackupBinaryToS3(
  key: string,
  body: Uint8Array,
  contentType = "application/gzip",
): Promise<void> {
  const s3 = await getS3();
  const { PutObjectCommand } = await import("@aws-sdk/client-s3");
  await s3.send(new PutObjectCommand({
    Bucket: BACKUP_BUCKET,
    Key: `${BACKUP_PREFIX}${key}`,
    Body: body,
    ContentType: contentType,
  }));
}

// Binary-safe counterpart of getBackupFromS3, which decodes as UTF-8 and mangles bytes.
export async function getBackupBytesFromS3(key: string): Promise<Uint8Array> {
  const s3 = await getS3();
  const { GetObjectCommand } = await import("@aws-sdk/client-s3");
  const res = await s3.send(new GetObjectCommand({
    Bucket: BACKUP_BUCKET,
    Key: `${BACKUP_PREFIX}${key}`,
  }));
  return await res.Body!.transformToByteArray();
}

export async function deleteOldBackups(): Promise<void> {
  const s3 = await getS3();
  const { ListObjectsV2Command, DeleteObjectCommand } = await import("@aws-sdk/client-s3");
  const res = await s3.send(new ListObjectsV2Command({
    Bucket: BACKUP_BUCKET,
    Prefix: BACKUP_PREFIX,
  }));
  const objects = res.Contents ?? [];

  // Retention is per backup family. A single pool would let the legacy
  // mailmask-backup-*.json files count against the retention window and evict real
  // mailmask-db-*.sqlite.gz snapshots — losing the only restorable copies.
  const families = new Map<string, typeof objects>();
  for (const obj of objects) {
    const key = obj.Key ?? "";
    const family = key.includes(".sqlite.gz") ? "db" : "legacy-json";
    const list = families.get(family) ?? [];
    list.push(obj);
    families.set(family, list);
  }

  for (const [, list] of families) {
    // Sort by key (timestamp-based), oldest first
    list.sort((a: any, b: any) => (a.Key ?? "").localeCompare(b.Key ?? ""));

    // Retention counts *days*, not files. Keys carry a full timestamp, so pressing
    // "Crear backup ahora" a few times would otherwise fill the whole window with
    // near-identical snapshots taken seconds apart and evict last week's history.
    // Keep only the newest backup per calendar day, then the newest N days.
    const newestPerDay = new Map<string, any>();
    for (const obj of list) {
      const day = (obj.Key ?? "").match(/(\d{4}-\d{2}-\d{2})/)?.[1];
      if (!day) continue;
      newestPerDay.set(day, obj); // list is oldest-first, so the last write wins
    }
    const keepDays = [...newestPerDay.keys()].sort().slice(-BACKUP_RETENTION);
    const keep = new Set(keepDays.map((d) => newestPerDay.get(d)?.Key));

    for (const obj of list) {
      if (obj.Key && !keep.has(obj.Key)) {
        await s3.send(new DeleteObjectCommand({ Bucket: BACKUP_BUCKET, Key: obj.Key }));
      }
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
    _iam = new IAMClient({ region: AWS_REGION });
  }
  return _iam;
}

const SES_SMTP_REGION = AWS_REGION;

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
    _sns = new SNSClient({ region: AWS_REGION });
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

// --- Imágenes incrustadas en correos salientes ---
//
// Van al bucket de entrada bajo un prefijo propio. El bucket es PRIVADO y así debe
// seguir, pero un cliente de correo trae las imágenes de forma anónima: no lleva
// nuestra cookie ni puede firmar una petición. Por eso no se expone una URL de S3
// sino una ruta nuestra (`GET /api/img/:key`) que lee de aquí y la sirve.
//
// El tipo se guarda junto al objeto y se vuelve a validar contra la lista blanca
// al servir: nunca se confía en el Content-Type almacenado.
export const EMAIL_IMAGE_PREFIX = "email-images/";
/** Archivos adjuntos en tránsito: viven aquí sólo hasta que el correo sale. */
export const EMAIL_FILE_PREFIX = "email-files/";

export const ALLOWED_IMAGE_TYPES: Record<string, string> = {
  "image/png": "png",
  "image/jpeg": "jpg",
  "image/gif": "gif",
  "image/webp": "webp",
};

export async function putEmailImageToS3(key: string, body: Uint8Array, contentType: string): Promise<void> {
  const s3 = await getS3();
  const { PutObjectCommand } = await import("@aws-sdk/client-s3");
  await s3.send(new PutObjectCommand({
    Bucket: S3_BUCKET,
    Key: `${EMAIL_IMAGE_PREFIX}${key}`,
    Body: body,
    ContentType: contentType,
    // Sin ACL: el objeto sigue siendo privado. Se sirve por nuestra ruta.
    CacheControl: "public, max-age=31536000, immutable",
  }));
}

/**
 * Borra una imagen ya incrustada en un correo enviado. Puede fallar sin
 * consecuencias: el correo ya salió con los bytes dentro, así que el objeto en S3
 * es desecho. Lo que quede sin borrar lo recoge el barrido diario.
 */
export async function deleteEmailImageFromS3(key: string): Promise<void> {
  const s3 = await getS3();
  const { DeleteObjectCommand } = await import("@aws-sdk/client-s3");
  await s3.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: `${EMAIL_IMAGE_PREFIX}${key}` }));
}

/**
 * Borra las imágenes subidas hace más de `maxAgeHours` que nadie llegó a enviar.
 * Devuelve cuántas quitó.
 *
 * Existe porque el compositor sube la imagen para poder previsualizarla, mucho
 * antes de que se decida mandar el correo — y a veces no se manda. Sin esto el
 * bucket sólo crece.
 */
export async function sweepOrphanEmailImages(maxAgeHours = 24): Promise<number> {
  return (await sweepPrefix(EMAIL_IMAGE_PREFIX, maxAgeHours)) +
    (await sweepPrefix(EMAIL_FILE_PREFIX, maxAgeHours));
}

async function sweepPrefix(prefix: string, maxAgeHours: number): Promise<number> {
  const s3 = await getS3();
  const { ListObjectsV2Command, DeleteObjectCommand } = await import("@aws-sdk/client-s3");
  const cutoff = Date.now() - maxAgeHours * 3600_000;
  let removed = 0;
  let token: string | undefined;

  do {
    const res: any = await s3.send(new ListObjectsV2Command({
      Bucket: S3_BUCKET,
      Prefix: prefix,
      ContinuationToken: token,
    }));
    for (const obj of res.Contents ?? []) {
      if (!obj.Key || !obj.LastModified) continue;
      if (new Date(obj.LastModified).getTime() >= cutoff) continue;
      try {
        await s3.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: obj.Key }));
        removed++;
      } catch { /* mejor esfuerzo: el barrido de mañana lo reintenta */ }
    }
    token = res.IsTruncated ? res.NextContinuationToken : undefined;
  } while (token);

  return removed;
}

export async function putEmailFileToS3(key: string, body: Uint8Array, contentType: string): Promise<void> {
  const s3 = await getS3();
  const { PutObjectCommand } = await import("@aws-sdk/client-s3");
  await s3.send(new PutObjectCommand({
    Bucket: S3_BUCKET,
    Key: `${EMAIL_FILE_PREFIX}${key}`,
    Body: body,
    ContentType: contentType,
  }));
}

export async function getEmailFileFromS3(key: string): Promise<{ body: Uint8Array; contentType: string } | null> {
  const s3 = await getS3();
  const { GetObjectCommand } = await import("@aws-sdk/client-s3");
  try {
    const res = await s3.send(new GetObjectCommand({ Bucket: S3_BUCKET, Key: `${EMAIL_FILE_PREFIX}${key}` }));
    return { body: await res.Body!.transformToByteArray(), contentType: res.ContentType ?? "application/octet-stream" };
  } catch {
    return null;
  }
}

export async function deleteEmailFileFromS3(key: string): Promise<void> {
  const s3 = await getS3();
  const { DeleteObjectCommand } = await import("@aws-sdk/client-s3");
  await s3.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: `${EMAIL_FILE_PREFIX}${key}` }));
}

export async function getEmailImageFromS3(key: string): Promise<{ body: Uint8Array; contentType: string } | null> {
  const s3 = await getS3();
  const { GetObjectCommand } = await import("@aws-sdk/client-s3");
  try {
    const res = await s3.send(new GetObjectCommand({ Bucket: S3_BUCKET, Key: `${EMAIL_IMAGE_PREFIX}${key}` }));
    const body = await res.Body!.transformToByteArray();
    return { body, contentType: res.ContentType ?? "application/octet-stream" };
  } catch {
    return null;
  }
}
