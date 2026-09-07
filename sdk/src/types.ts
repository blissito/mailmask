export interface MailMaskConfig {
  apiKey: string;
  baseUrl?: string;
  /**
   * `fetch` alterno. Sirve para poner un timeout por llamada
   * (`AbortSignal.timeout`), reintentos o un proxy, y para probar el SDK
   * contra el servidor en proceso sin levantar un puerto.
   */
  fetch?: typeof fetch;
}

export interface Domain {
  id: string;
  domain: string;
  verified: boolean;
  mxConfigured: boolean;
  registeredViaMailmask: boolean;
  createdAt: string;
  /** Sólo en `domains.list`: reenvíos del mes en curso. */
  monthlyForwards?: number;
  /** Sólo en `domains.list`: tope de reenvíos por hora del plan. */
  forwardPerHour?: number;
}

export interface DnsRecord {
  type: "MX" | "TXT" | "CNAME";
  name: string;
  value: string;
  priority?: number;
}

/** Respuesta de `domains.create`: el dominio y los registros DNS que hay que poner. */
export interface DomainCreated {
  domain: Domain;
  /** true si es el 2.º dominio sin activar: se guarda pero no reenvía hasta activarlo ($99/mes). */
  requiereActivacion: boolean;
  dnsRecords: {
    mx: DnsRecord;
    verification: DnsRecord;
    dkim: DnsRecord[];
    spf: DnsRecord;
  };
}

/** Respuesta de `domains.verify`. */
export interface DomainVerification {
  domain: string;
  verified: boolean;
  dkimVerified: boolean;
  /** true cuando no se pudo consultar a SES: los campos son el último estado conocido. */
  stale?: boolean;
  error?: string;
}

export interface Alias {
  alias: string;
  domainId: string;
  destinations: string[];
  enabled: boolean;
  forwardCount: number;
  lastFrom?: string | null;
  lastAt?: string | null;
  createdAt: string;
  /** true si la máscara guarda el correo en un buzón IMAP. */
  mailboxEnabled?: boolean;
}

/** Credenciales de un buzón IMAP recién creado. La contraseña se muestra una sola vez. */
export interface MailboxCreated {
  email: string;
  password: string;
  quotaBytes: number;
  imap: { host: string; port: number; security: string };
  smtp: { host: string; port: number; security: string };
}

/** `aliases.create`: el alias, y si pediste buzón, sus credenciales o por qué no se creó. */
export interface AliasCreated extends Alias {
  buzon?: MailboxCreated | null;
  errorBuzon?: string | null;
}

export interface CreateAliasInput {
  /** Parte local, sin el dominio: "hola" para hola@tudominio.com. `*` para catch-all. */
  alias: string;
  /** Adónde reenviar. Puede ir vacío sólo si `mailbox` es true. */
  destinations?: string[];
  /** Crear también un buzón IMAP (requiere dominio activado). */
  mailbox?: boolean;
}

export interface UpdateAliasInput {
  enabled?: boolean;
  destinations?: string[];
}

export type RuleField = "to" | "from" | "subject";
export type RuleMatch = "contains" | "equals" | "regex";
/** `forward` y `webhook` requieren `target`; `discard` no. */
export type RuleAction = "forward" | "webhook" | "discard";

export interface Rule {
  id: string;
  domainId: string;
  field: RuleField;
  match: RuleMatch;
  value: string;
  action: RuleAction;
  target: string;
  priority: number;
  enabled: boolean;
  createdAt: string;
}

export interface CreateRuleInput {
  field: RuleField;
  /** Los patrones `regex` se validan al guardar: uno peligroso responde 400. */
  match: RuleMatch;
  value: string;
  action: RuleAction;
  /** Destino del `forward` o URL del `webhook`. Se ignora con `discard`. */
  target?: string;
  priority?: number;
  enabled?: boolean;
}

export interface UpdateRuleInput {
  field?: RuleField;
  match?: RuleMatch;
  value?: string;
  action?: RuleAction;
  target?: string;
  priority?: number;
  enabled?: boolean;
}

export interface EmailLog {
  id: string;
  domainId: string;
  timestamp: string;
  from: string;
  to: string;
  subject: string;
  /** Entrantes: forwarded, discarded, failed, rule_matched. Salientes: sent → delivered | bounced | complained. */
  status: "forwarded" | "discarded" | "failed" | "rule_matched" | "sent" | "delivered" | "bounced" | "complained";
  forwardedTo: string;
  sizeBytes: number;
  error?: string;
  /** Id interno de SES; cruza el log con los eventos de entrega. Sólo en salientes. */
  sesMessageId?: string;
}

export interface SendEmailInput {
  to: string;
  subject: string;
  /** Al menos uno de `html`, `body` o `markdown`. Con html y body se manda multipart. HTML máx. 100 KB. */
  html?: string;
  body?: string;
  markdown?: string;
  replyTo?: string;
  /**
   * Parte local de un alias **activo** del dominio. Sin esto el correo sale
   * desde `noreply@tudominio.com`.
   */
  from?: string;
  /** Nombre visible del remitente: `Libretas <hola@tudominio.com>`. */
  fromName?: string;
  /** Copias visibles. Máx. 20; también pasan por la lista de supresión. */
  cc?: string[];
  /** Copias ocultas. Máx. 20. */
  bcc?: string[];
  /** `Message-ID` del correo al que se responde, para que el cliente lo enhebre. */
  inReplyTo?: string;
  /** Cadena `References` del hilo. */
  references?: string;
  /** Archivos subidos antes con `attachments.upload`. Se borran de S3 al enviarse. */
  attachments?: AttachmentRef[];
}

/** Lo que devuelve `attachments.upload`; se pasa tal cual en `SendEmailInput.attachments`. */
export interface AttachmentRef {
  key: string;
  filename: string;
  contentType?: string;
}

export interface UploadAttachmentInput {
  filename: string;
  contentType: string;
  data: Uint8Array | Blob;
}

export interface UploadedAttachment {
  ok: boolean;
  key: string;
  filename: string;
  size: number;
}

export interface SendOptions {
  /**
   * Reintentar con la misma clave (máx. 128 caracteres) devuelve la respuesta
   * original sin volver a enviar ni consumir cuota, durante 24 h.
   */
  idempotencyKey?: string;
}

export interface Suppression {
  email: string;
  /** `bounce:Permanent`, `complaint` o `manual`. */
  reason: string;
  createdAt: string;
}

export type WebhookEvent = "email.received" | "email.sent" | "email.delivered" | "email.bounced" | "email.complained";

export interface Webhook {
  id: string;
  domainId: string;
  url: string;
  events: WebhookEvent[];
  enabled: boolean;
  createdAt: string;
}

/** Lo que devuelve `webhooks.create`. El `secret` se muestra una sola vez. */
export interface WebhookCreated extends Webhook {
  secret: string;
}

export interface CreateWebhookInput {
  /** Debe ser https y pública. */
  url: string;
  events: WebhookEvent[];
}

export interface UpdateWebhookInput {
  url?: string;
  events?: WebhookEvent[];
  enabled?: boolean;
}

export interface WebhookDelivery {
  id: string;
  webhookId: string;
  event: WebhookEvent | "ping";
  attempts: number;
  status: "pending" | "delivered" | "failed";
  nextAt: string;
  lastError: string | null;
  lastStatusCode: number | null;
  createdAt: string;
}

/** Cuerpo que recibe tu endpoint. `data` depende del evento. */
export interface WebhookPayload<T = Record<string, unknown>> {
  event: WebhookEvent | "ping";
  domainId: string;
  timestamp: string;
  data: T;
}

export interface BulkSendInput {
  recipients: string[];
  subject: string;
  html: string;
  /** Alias activo del dominio; por omisión `noreply`. */
  from?: string;
}

/** Lo que devuelve `bulkSend`: el job se encola, todavía no hay estado que leer. */
export interface BulkJobCreated {
  ok: boolean;
  jobId: string;
}

export interface BulkJob {
  id: string;
  domainId: string;
  recipients: string[];
  subject: string;
  html: string;
  from: string;
  status: string;
  totalRecipients: number;
  sent: number;
  failed: number;
  /** Destinatarios saltados por bounce o queja previa: total = sent + failed + skippedSuppressed. */
  skippedSuppressed: number;
  lastError?: string | null;
  createdAt: string;
  completedAt?: string | null;
  expiresAt: string;
}

export interface SmtpCredential {
  id: string;
  domainId: string;
  label: string;
  iamUsername: string;
  createdAt: string;
}

/**
 * Lo que devuelve `smtp.create`. La contraseña se muestra **una sola vez**: no
 * se puede volver a consultar, sólo revocar la credencial y crear otra.
 */
export interface SmtpCredentialCreated {
  id: string;
  label: string;
  server: string;
  port: number;
  encryption: string;
  username: string;
  password: string;
  createdAt: string;
}

export interface ApiKey {
  id: string;
  name: string;
  /** Primeros caracteres de la llave, para identificarla en listados. */
  keyPrefix: string;
  lastUsedAt?: string;
  createdAt: string;
}

// --- DNS ---

export type DnsRecordType = "A" | "AAAA" | "CNAME" | "TXT" | "MX" | "NS" | "CAA" | "SRV";

/**
 * Un conjunto de registros con el mismo nombre y tipo. El DNS trabaja así, no con registros
 * sueltos: `values` es la lista completa y al escribirla reemplaza lo que hubiera.
 */
export interface DnsRRSet {
  name: string;
  type: DnsRecordType;
  ttl: number;
  values: string[];
}

export interface DnsRRSetAnotado extends DnsRRSet {
  /** Lo pone MailMask para que el correo funcione. */
  managed: boolean;
  editable: boolean;
  managedReason?: string;
  /** Valores que hay que conservar aunque el registro sea editable (el SPF). */
  protectedValues?: string[];
}

export interface DnsZoneState {
  status: "none" | "pending_delegation" | "active";
  hostedZoneId?: string;
  nameservers?: string[];
  delegated?: boolean;
}

export interface DnsListResponse {
  zone: DnsZoneState;
  records: DnsRRSetAnotado[];
  /** Presente cuando todavía no hay zona: dice qué hacer. */
  hint?: string;
}

export interface DnsZoneCreated {
  hostedZoneId: string;
  nameservers: string[];
  /** Lo que copiamos de tu proveedor anterior. Revísalo: puede faltar algo. */
  imported: DnsRRSet[];
  importWarning: string;
}

export interface DnsDelegation {
  delegated: boolean;
  observed: string[];
  expected: string[];
}

export interface DnsImportResult {
  found: DnsRRSet[];
  nameservers: string[];
  warning: string;
}

export interface DnsChangeResult {
  record?: DnsRRSet;
  records?: DnsRRSet[];
  changeId: string;
  propagacion: string;
}

export type DnsPreset =
  | "vercel" | "netlify" | "github-pages" | "cloudflare-pages" | "render" | "fly"
  | "redirect-a-www" | "dmarc";
