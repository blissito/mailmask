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
  /** Último valor medido. Si `verifiedStatus` es "unknown", no lo afirmes: confírmalo con `domains.health`. */
  verified: boolean;
  /** Último valor medido. Si `mxStatus` es "unknown", no lo afirmes: confírmalo con `domains.health`. */
  mxConfigured: boolean;
  registeredViaMailmask: boolean;
  createdAt: string;
  /** Cuándo se midieron `verified` y `mxConfigured` en vivo (health, verify o el servidor). null = nunca. */
  checkedAt?: string | null;
  /** "unknown" si la revisión tiene más de 24 h o nunca se hizo. */
  mxStatus?: "ok" | "missing" | "unknown";
  /** "unknown" si la revisión tiene más de 24 h o nunca se hizo. */
  verifiedStatus?: "ok" | "missing" | "unknown";
  /** Presente cuando algún estado es "unknown": qué hacer para confirmarlo. */
  statusNote?: string;
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
  /** Si el MX apunta al inbound de SES, medido en la misma llamada; null si el DNS no respondió. */
  mxConfigured?: boolean | null;
  /** true cuando no se pudo consultar a SES: los campos son el último estado conocido. */
  stale?: boolean;
  error?: string;
}

/** Nombre público de `Alias` desde la 0.4.5. */
export type Address = Alias;
/** Nombre público de `AliasCreated` desde la 0.4.5. */
export type AddressCreated = AliasCreated;
/** Nombre público de `CreateAliasInput` desde la 0.4.5. */
export type CreateAddressInput = CreateAliasInput;
/** Nombre público de `UpdateAliasInput` desde la 0.4.5. */
export type UpdateAddressInput = UpdateAliasInput;

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

// --- Registros a pegar en el registrador ---

export interface DnsSetupRecord {
  id: string;
  type: "MX" | "TXT" | "CNAME";
  /** Relativo al dominio, como lo piden casi todos los paneles ('@', '_amazonses'). */
  name: string;
  fqdn: string;
  value: string;
  /** Sólo MX, para paneles con campo de prioridad aparte (entonces el valor es `host`). */
  priority?: number;
  host?: string;
  level: "requerido" | "recomendado" | "opcional";
  purpose: string;
  benefit?: string;
  /** Ayuda en texto con **negritas** estilo markdown. */
  hints: string[];
  /** Sólo con `live`: si el DNS público ya lo tiene; null = no se pudo consultar. */
  ok?: boolean | null;
  observed?: string[];
  /** SPF: valor fusionado cuando ya existe otro SPF (se edita ése, no se crea otro). */
  suggestedValue?: string;
}

export interface DnsSetup {
  domain: string;
  records: DnsSetupRecord[];
  live: boolean;
  nameservers?: string[];
  /** Panel donde se pegan, deducido de los nameservers. */
  registrarHint?: { provider: string; label: string; note: string } | null;
  summary?: string;
}

// --- Cobro ---

export interface BillingStatus {
  subscription: { plan: string; status: string; currentPeriodEnd?: string; [k: string]: unknown };
}

export interface Addon {
  id: string;
  kind: string;
  /** Dominio al que aplica; sin él es un add-on legado de toda la cuenta. */
  domainId?: string;
  status: "pending" | "active" | "cancelled" | "expired";
  priceCents: number;
  currentPeriodEnd?: string;
  createdAt: string;
  cancelledAt?: string;
  source: "purchase" | "courtesy" | "migration";
}

export interface AddonsResponse {
  catalog: Record<string, { price: number; label: string }>;
  forSale: string[];
  mine: Addon[];
}

/** Liga de pago de MercadoPago. Nada cambia hasta que el usuario la abre y paga. */
export interface CheckoutLink {
  init_point: string;
  addonId: string;
}

// --- Registro y transferencia de dominios ---

export interface DomainSearchResult {
  available: boolean;
  domain: string;
  tld: string;
  /** Centavos MXN por año. */
  price: number;
  currency: "MXN";
}

export interface TldPrice {
  tld: string;
  /** Centavos MXN. */
  price: number;
  renewPrice: number;
  transferPrice: number;
  popular: boolean;
}

export interface DomainRegistrationCreated {
  /** Liga de pago de MercadoPago; el registro arranca al pagar. */
  initPoint: string;
  registrationId: string;
}

export interface DomainRegistration {
  id: string;
  domainId: string | null;
  domainName: string;
  kind: "register" | "transfer";
  status: string;
  expiresAt: string | null;
  priceCents: number;
  renewalStatus: string;
  renewalPriceCents: number | null;
  nextChargeAt: string | null;
  dnsImportStatus: string;
  transferAuthCodeHint: string | null;
  /** Candado de transferencia (`clientTransferProhibited`); null si aún no se ha leído de AWS. */
  transferLock: boolean | null;
  /** Mientras está quitado: cuándo se vuelve a poner solo. */
  transferUnlockedUntil: string | null;
  /** Desde cuándo puede cambiar de registrador (regla de 60 días de ICANN). */
  transferEligibleAt: string;
  lastError: string | null;
  createdAt: string;
  [k: string]: unknown;
}

export interface TransferRequirement {
  texto: string;
  ok: boolean | null;
  ayuda?: string;
}

export interface TransferCheck {
  domain: string;
  /** Centavos MXN; incluye un año de renovación. */
  price: number;
  currency: "MXN";
  requisitos: TransferRequirement[];
  dns: { found: unknown[]; nameservers?: string[]; warning?: string; truncado?: boolean };
  [k: string]: unknown;
}

export interface TransferDnsInventory {
  records: unknown[];
  status: string;
  takenAt: string | null;
}

export interface RenewalLink {
  init_point: string;
  nextChargeAt: string;
}

// --- Equipo y Bandeja ---

export interface DomainMember {
  id: string;
  domainId: string;
  email: string;
  name: string;
  role: "admin" | "agent";
  createdAt: string;
  /** Del perfil de su cuenta de MailMask, si lo llenó. */
  displayName?: string | null;
  avatarUrl?: string | null;
}

export interface DomainInvite {
  token: string;
  email: string;
  name: string;
  role: "admin" | "agent";
  expiresAt: string;
  inviteUrl: string;
}

export interface CannedReply {
  id: string;
  domainId: string;
  title: string;
  /** Markdown. */
  body: string;
  createdAt: string;
}

/** Perfil de la cuenta de MailMask (el usuario, no una máscara). */
export interface AccountProfile {
  email: string;
  displayName: string | null;
  /** Ruta relativa al host de MailMask (`/api/avatar/...`), o null sin foto. */
  avatarUrl: string | null;
}

/** Derechos y uso de UN dominio, dentro de `AccountMe.porDominio`. */
export interface AccountMeDomainUsage {
  id: string;
  domain: string;
  /** Límites del dominio (sends, aliases, dominios, etc.), por plan y add-ons. */
  derechos: Record<string, unknown>;
  addons: Addon[];
  uso: {
    aliases: { current: number; limit: number };
    rules: { current: number; limit: number };
    sends: { current: number; limit: number };
    forwards: { current: number; limit: number };
    mailboxBytes: { current: number; limit: number };
  };
}

/** Respuesta de `account.me()`: identidad de la cuenta y su uso, por dominio y total. */
export interface AccountMe extends AccountProfile {
  isAdmin: boolean;
  assistant: boolean;
  domainsCount: number;
  emailVerified: boolean;
  forwards: { current: number; limit: number };
  subscription: { plan: string; status: string; currentPeriodEnd: string | null; planLabel: string; [k: string]: unknown };
  porDominio: AccountMeDomainUsage[];
  addons: Addon[];
  planPriceCents: number | null;
  addonCatalog: Record<string, { price: number; label: string }>;
  addonsForSale: string[];
  lastOrder: Order | null;
  usage: {
    domains: { current: number; limit: number | null };
    aliasesPerDomain: unknown[];
    rulesPerDomain: unknown[];
    sendsPerDomain: unknown[];
  };
  referralSlug?: string | null;
  referralStats: ReferralStats;
}

/** Respuesta de `account.export()`: todo el dato del usuario, listo para descargar. */
export interface AccountExport {
  email: string;
  exportedAt: string;
  domains: {
    domain: string;
    domainId: string;
    verified: boolean;
    aliases: Alias[];
    rules: Rule[];
    logs: EmailLog[];
  }[];
}

/** Respuesta de `domains.uploadImage()`. */
export interface UploadedEmailImage {
  ok: boolean;
  /** Efímera: se borra tras enviarse (o la barre el aseo diario si nunca se usó). */
  url: string;
}

// --- Bandeja (inbox) ---

export type InboxStatus = "open" | "snoozed" | "closed";

export interface InboxConversation {
  id: string;
  domainId: string;
  /** El contacto externo (en un hilo que inició el dominio, el destinatario). */
  from: string;
  /** La máscara del dominio por la que va el hilo (`ventas@tudominio.com`). */
  to: string;
  subject: string;
  status: InboxStatus;
  assignedTo?: string;
  priority: "normal" | "urgent";
  lastMessageAt: string;
  messageCount: number;
  tags: string[];
  deletedAt?: string;
  snoozedUntil?: string;
  /** Para quien pregunta: hay mensajes que no ha visto. */
  unread?: boolean;
  /** Sólo en búsqueda: fragmento con la coincidencia. */
  snippet?: string;
  [k: string]: unknown;
}

export interface InboxListOptions {
  /** `open`, `snoozed`, `closed`, `unread` (de quien pregunta) o `deleted` (papelera). */
  status?: InboxStatus | "unread" | "deleted";
  /** Dirección completa de la máscara (`ventas@tudominio.com`). */
  to?: string;
  assignedTo?: string;
  /** Búsqueda en asunto, remitente y cuerpo. Con `q` no hay paginación (tope 50). */
  q?: string;
  /** Máx. 100. */
  limit?: number;
  cursor?: string;
}

export interface InboxPage {
  items: InboxConversation[];
  nextCursor: string | null;
  /** Máscaras con conversaciones (sólo en la primera página). */
  aliases?: string[];
  mode: "list" | "search" | "search-degraded";
  unreadCount?: number;
  [k: string]: unknown;
}

export interface InboxAttachment {
  index: number;
  filename: string;
  contentType: string;
  size: number;
}

export interface InboxMessage {
  id: string;
  conversationId: string;
  from: string;
  /** Texto plano. */
  body?: string;
  html?: string;
  direction: "inbound" | "outbound";
  createdAt: string;
  messageId?: string;
  deliveryStatus?: "sent" | "delivered" | "bounced" | "complained";
  attachments?: InboxAttachment[];
  /** El original ya no está (retención de 90 días o pérdida): `body` puede venir del índice. */
  bodyDegraded?: string;
}

export interface InboxNote {
  id: string;
  conversationId: string;
  author: string;
  body: string;
  createdAt: string;
}

export interface InboxConversationDetail extends InboxConversation {
  messages: InboxMessage[];
  notes: InboxNote[];
  totalMessages: number;
  hasMore: boolean;
}

export interface InboxComposeInput {
  /** Parte local (o dirección completa) de una máscara activa del dominio. */
  fromAlias: string;
  to: string;
  subject: string;
  markdown?: string;
  html?: string;
  body?: string;
  cc?: string[];
  bcc?: string[];
  attachments?: AttachmentRef[];
}

export interface InboxReplyInput {
  markdown?: string;
  html?: string;
  body?: string;
  cc?: string[];
  bcc?: string[];
  /** Cita el último mensaje recibido (por omisión true; sólo con markdown). */
  quote?: boolean;
  attachments?: AttachmentRef[];
}

export interface InboxUpdateInput {
  status?: InboxStatus;
  /** ISO, futura y a menos de 90 días. Obligatoria con `status: "snoozed"`. */
  snoozedUntil?: string;
  tags?: string[];
  priority?: "normal" | "urgent";
}

// --- Cuenta: pedidos y referidos ---

export interface Order {
  id: string;
  number: string;
  date: string;
  kind: string;
  concept: string;
  subject: string | null;
  amountCents: number;
  listPriceCents: number | null;
  currency: string;
  periodStart: string | null;
  periodEnd: string | null;
  failureReason: string | null;
  note: string | null;
  reference: string | null;
}

export interface OrdersPage {
  orders: Order[];
  nextCursor: string | null;
  invoiceNote: string;
}

export interface ReferralStats {
  slug?: string | null;
  referrals: unknown[];
  [k: string]: unknown;
}
