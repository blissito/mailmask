import type {
  MailMaskConfig, Domain, DomainCreated, DomainVerification, Alias, AliasCreated, MailboxCreated, CreateAliasInput, UpdateAliasInput,
  Rule, CreateRuleInput, UpdateRuleInput, EmailLog, SendEmailInput,
  BulkSendInput, BulkJob, BulkJobCreated, SmtpCredential, SmtpCredentialCreated,
  ApiKey, SendOptions, UploadAttachmentInput, UploadedAttachment, Suppression,
  Webhook, WebhookCreated, CreateWebhookInput, UpdateWebhookInput, WebhookDelivery,
  DnsRecordType, DnsRRSet, DnsListResponse, DnsZoneCreated, DnsDelegation, DnsImportResult,
  DnsChangeResult, DnsPreset, DnsSetup,
  BillingStatus, AddonsResponse, CheckoutLink, DomainSearchResult, TldPrice, DomainRegistrationCreated,
  DomainRegistration, TransferCheck, TransferDnsInventory, RenewalLink, DomainMember, DomainInvite, CannedReply,
  AccountProfile, InboxPage, InboxListOptions, InboxConversation, InboxConversationDetail, InboxComposeInput,
  InboxReplyInput, InboxUpdateInput, InboxNote, OrdersPage, ReferralStats,
} from "./types.js";

class MailMaskError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "MailMaskError";
  }
}

async function request<T>(baseUrl: string, apiKey: string, path: string, opts?: RequestInit, doFetch: typeof fetch = fetch): Promise<T> {
  // Con FormData el runtime pone el boundary; forzar el Content-Type lo rompe.
  const headers: Record<string, string> = { "Authorization": `Bearer ${apiKey}`, ...(opts?.headers as Record<string, string> | undefined) };
  if (!(opts?.body instanceof FormData) && !("Content-Type" in headers)) headers["Content-Type"] = "application/json";
  const res = await doFetch(`${baseUrl}${path}`, { ...opts, headers });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new MailMaskError(res.status, body.error || res.statusText);
  }
  return res.json() as Promise<T>;
}

// Para lo que no es JSON (el perfil de Apple, el .mbox): mismo auth y mismo manejo de error.
async function requestRaw(baseUrl: string, apiKey: string, path: string, doFetch: typeof fetch = fetch): Promise<Response> {
  const res = await doFetch(`${baseUrl}${path}`, { headers: { "Authorization": `Bearer ${apiKey}` } });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new MailMaskError(res.status, body.error || res.statusText);
  }
  return res;
}

export class MailMask {
  private baseUrl: string;
  private apiKey: string;

  domains: DomainsResource;
  aliases: AliasesResource;
  rules: RulesResource;
  logs: LogsResource;
  send: SendResource;
  attachments: AttachmentsResource;
  suppressions: SuppressionsResource;
  webhooks: WebhooksResource;
  smtp: SmtpResource;
  apiKeys: ApiKeysResource;
  dns: DnsResource;
  billing: BillingResource;
  registrations: RegistrationsResource;
  transfers: TransfersResource;
  members: MembersResource;
  signature: SignatureResource;
  canned: CannedResource;
  account: AccountResource;
  inbox: InboxResource;
  referrals: ReferralsResource;

  constructor(config: MailMaskConfig) {
    this.apiKey = config.apiKey;
    this.baseUrl = (config.baseUrl || "https://www.mailmask.studio").replace(/\/$/, "");
    // Sin bind, un `fetch` de config que sea el global de node truena con
    // "Illegal invocation" al perder su receptor.
    const doFetch = config.fetch ? config.fetch : fetch;
    const req = <T>(path: string, opts?: RequestInit) => request<T>(this.baseUrl, this.apiKey, path, opts, doFetch);

    this.domains = new DomainsResource(req);
    this.aliases = new AliasesResource(req, (path) => requestRaw(this.baseUrl, this.apiKey, path, doFetch));
    this.rules = new RulesResource(req);
    this.logs = new LogsResource(req);
    this.send = new SendResource(req);
    this.attachments = new AttachmentsResource(req);
    this.suppressions = new SuppressionsResource(req);
    this.webhooks = new WebhooksResource(req);
    this.smtp = new SmtpResource(req);
    this.apiKeys = new ApiKeysResource(req);
    this.dns = new DnsResource(req);
    this.billing = new BillingResource(req);
    this.registrations = new RegistrationsResource(req);
    this.transfers = new TransfersResource(req);
    this.members = new MembersResource(req);
    this.signature = new SignatureResource(req);
    this.canned = new CannedResource(req);
    this.account = new AccountResource(req);
    this.inbox = new InboxResource(req, (path) => requestRaw(this.baseUrl, this.apiKey, path, doFetch));
    this.referrals = new ReferralsResource(req);
  }
}

type Req = <T>(path: string, opts?: RequestInit) => Promise<T>;

class DomainsResource {
  constructor(private req: Req) {}
  list() { return this.req<Domain[]>("/api/domains"); }
  get(id: string) { return this.req<Domain>(`/api/domains/${id}`); }
  create(domain: string) { return this.req<DomainCreated>("/api/domains", { method: "POST", body: JSON.stringify({ domain }) }); }
  delete(id: string) { return this.req<{ ok: boolean }>(`/api/domains/${id}`, { method: "DELETE" }); }
  health(id: string) { return this.req<Record<string, unknown>>(`/api/domains/${id}/health`); }
  verify(id: string) { return this.req<DomainVerification>(`/api/domains/${id}/verify`, { method: "POST" }); }
  /** Registros a pegar en el registrador. Con `live` los compara con el DNS público y deduce el panel. */
  dnsSetup(id: string, opts?: { live?: boolean }) { return this.req<DnsSetup>(`/api/domains/${id}/dns-setup${opts?.live ? "?live=1" : ""}`); }
  /** Logo de la firma (PNG, JPG o WebP; máx. 500 KB). Se ve en todo correo en markdown. */
  setLogo(id: string, file: Blob, filename = "logo") {
    const form = new FormData();
    form.append("file", file, filename);
    return this.req<{ ok: boolean; logoUrl: string }>(`/api/domains/${id}/logo`, { method: "POST", body: form });
  }
  /** Logo desde un adjunto del chat del asistente (URL firmada de `/api/asistente/files/*`). */
  setLogoFromUrl(id: string, url: string) {
    return this.req<{ ok: boolean; logoUrl: string }>(`/api/domains/${id}/logo`, { method: "POST", body: JSON.stringify({ fromUrl: url }) });
  }
  removeLogo(id: string) { return this.req<{ ok: boolean }>(`/api/domains/${id}/logo`, { method: "DELETE" }); }
}

class DnsResource {
  constructor(private req: Req) {}
  list(domainId: string) { return this.req<DnsListResponse>(`/api/domains/${domainId}/dns`); }
  createZone(domainId: string) { return this.req<DnsZoneCreated>(`/api/domains/${domainId}/dns/zone`, { method: "POST" }); }
  delegation(domainId: string) { return this.req<DnsDelegation>(`/api/domains/${domainId}/dns/delegation`); }
  import(domainId: string) { return this.req<DnsImportResult>(`/api/domains/${domainId}/dns/import`, { method: "POST" }); }
  /** Reemplaza el conjunto: `values` sustituye por completo lo que hubiera en ese nombre y tipo. */
  upsert(domainId: string, record: { name: string; type: DnsRecordType; values: string[]; ttl?: number }) {
    return this.req<DnsChangeResult>(`/api/domains/${domainId}/dns/records`, { method: "PUT", body: JSON.stringify(record) });
  }
  delete(domainId: string, name: string, type: DnsRecordType) {
    return this.req<{ ok: boolean; changeId: string }>(`/api/domains/${domainId}/dns/records`, { method: "DELETE", body: JSON.stringify({ name, type }) });
  }
  preset(domainId: string, preset: DnsPreset, target?: string, subdomain?: string) {
    return this.req<DnsChangeResult>(`/api/domains/${domainId}/dns/preset`, { method: "POST", body: JSON.stringify({ preset, target, subdomain }) });
  }
}

class AliasesResource {
  constructor(private req: Req, private raw: (path: string) => Promise<Response>) {}
  /** Perfil de configuración de Apple Mail (plist) para el buzón de una máscara. */
  async appleProfile(domainId: string, alias: string) {
    return (await this.raw(`/api/domains/${domainId}/apple-profile?alias=${encodeURIComponent(alias)}`)).text();
  }
  /** Exporta el buzón en formato mbox. Devuelve la respuesta en streaming: un buzón puede pesar GB. */
  exportMbox(domainId: string, alias: string) { return this.raw(`/api/domains/${domainId}/alias/${alias}/mailbox/export`); }
  list(domainId: string) { return this.req<Alias[]>(`/api/domains/${domainId}/alias`); }
  create(domainId: string, input: CreateAliasInput) { return this.req<AliasCreated>(`/api/domains/${domainId}/alias`, { method: "POST", body: JSON.stringify({ ...input, destinations: input.destinations ?? [] }) }); }
  /** Crea un buzón IMAP para una máscara existente. La contraseña sólo se devuelve aquí. */
  createMailbox(domainId: string, alias: string) { return this.req<MailboxCreated>(`/api/domains/${domainId}/alias/${alias}/mailbox`, { method: "POST" }); }
  /** Borra el buzón Y SU CORREO. La máscara debe conservar al menos un destino. */
  deleteMailbox(domainId: string, alias: string) { return this.req<{ ok: boolean }>(`/api/domains/${domainId}/alias/${alias}/mailbox`, { method: "DELETE" }); }
  /** Genera una contraseña nueva para el buzón. Sólo se devuelve aquí; no se guarda. */
  resetMailboxPassword(domainId: string, alias: string) { return this.req<{ password: string }>(`/api/domains/${domainId}/alias/${alias}/mailbox/password`, { method: "POST" }); }
  update(domainId: string, alias: string, input: UpdateAliasInput) { return this.req<Alias>(`/api/domains/${domainId}/alias/${alias}`, { method: "PUT", body: JSON.stringify(input) }); }
  delete(domainId: string, alias: string) { return this.req<{ ok: boolean }>(`/api/domains/${domainId}/alias/${alias}`, { method: "DELETE" }); }
}

class RulesResource {
  constructor(private req: Req) {}
  list(domainId: string) { return this.req<Rule[]>(`/api/domains/${domainId}/rules`); }
  create(domainId: string, input: CreateRuleInput) { return this.req<Rule>(`/api/domains/${domainId}/rules`, { method: "POST", body: JSON.stringify(input) }); }
  update(domainId: string, ruleId: string, input: UpdateRuleInput) { return this.req<Rule>(`/api/domains/${domainId}/rules/${ruleId}`, { method: "PUT", body: JSON.stringify(input) }); }
  delete(domainId: string, ruleId: string) { return this.req<{ ok: boolean }>(`/api/domains/${domainId}/rules/${ruleId}`, { method: "DELETE" }); }
}

class LogsResource {
  constructor(private req: Req) {}
  /** `limit` por omisión 50, máximo 100. */
  list(domainId: string, opts?: { limit?: number }) {
    const qs = opts?.limit ? `?limit=${encodeURIComponent(opts.limit)}` : "";
    return this.req<EmailLog[]>(`/api/domains/${domainId}/logs${qs}`);
  }
}

class SendResource {
  constructor(private req: Req) {}
  send(domainId: string, input: SendEmailInput, opts?: SendOptions) {
    const headers: Record<string, string> = {};
    if (opts?.idempotencyKey) headers["Idempotency-Key"] = opts.idempotencyKey;
    return this.req<{ ok: boolean; messageId: string; sesMessageId: string }>(`/api/domains/${domainId}/send`, { method: "POST", body: JSON.stringify(input), headers });
  }
  bulkSend(domainId: string, input: BulkSendInput) { return this.req<BulkJobCreated>(`/api/domains/${domainId}/send-bulk`, { method: "POST", body: JSON.stringify(input) }); }
  bulkStatus(domainId: string, jobId: string) { return this.req<BulkJob>(`/api/domains/${domainId}/bulk/${jobId}`); }
}

class AttachmentsResource {
  constructor(private req: Req) {}
  /** Máx. 5 MB. Ejecutables bloqueados (415). La llave vale hasta que se envía. */
  upload(domainId: string, input: UploadAttachmentInput) {
    const form = new FormData();
    const blob = input.data instanceof Blob ? input.data : new Blob([input.data as BlobPart], { type: input.contentType });
    form.append("file", blob, input.filename);
    return this.req<UploadedAttachment>(`/api/domains/${domainId}/attachments`, { method: "POST", body: form });
  }
  /** Desde un adjunto del chat del asistente (URL firmada de `/api/asistente/files/*`). */
  uploadFromUrl(domainId: string, url: string, filename?: string) {
    return this.req<UploadedAttachment>(`/api/domains/${domainId}/attachments`, { method: "POST", body: JSON.stringify({ fromUrl: url, filename }) });
  }
}

class SuppressionsResource {
  constructor(private req: Req) {}
  list(domainId: string) { return this.req<Suppression[]>(`/api/domains/${domainId}/suppressions`); }
  add(domainId: string, email: string) { return this.req<Suppression>(`/api/domains/${domainId}/suppressions`, { method: "POST", body: JSON.stringify({ email }) }); }
  remove(domainId: string, email: string) { return this.req<{ ok: boolean }>(`/api/domains/${domainId}/suppressions/${encodeURIComponent(email)}`, { method: "DELETE" }); }
}

class WebhooksResource {
  constructor(private req: Req) {}
  list(domainId: string) { return this.req<Webhook[]>(`/api/domains/${domainId}/webhooks`); }
  create(domainId: string, input: CreateWebhookInput) { return this.req<WebhookCreated>(`/api/domains/${domainId}/webhooks`, { method: "POST", body: JSON.stringify(input) }); }
  update(domainId: string, webhookId: string, input: UpdateWebhookInput) { return this.req<Webhook>(`/api/domains/${domainId}/webhooks/${webhookId}`, { method: "PUT", body: JSON.stringify(input) }); }
  delete(domainId: string, webhookId: string) { return this.req<{ ok: boolean }>(`/api/domains/${domainId}/webhooks/${webhookId}`, { method: "DELETE" }); }
  /** Encola un `ping`; llega en el siguiente minuto. */
  test(domainId: string, webhookId: string) { return this.req<{ ok: boolean; deliveryId: string }>(`/api/domains/${domainId}/webhooks/${webhookId}/test`, { method: "POST" }); }
  deliveries(domainId: string, webhookId: string) { return this.req<WebhookDelivery[]>(`/api/domains/${domainId}/webhooks/${webhookId}/deliveries`); }
}

class SmtpResource {
  constructor(private req: Req) {}
  list(domainId: string) { return this.req<SmtpCredential[]>(`/api/domains/${domainId}/smtp-credentials`); }
  create(domainId: string, label: string) { return this.req<SmtpCredentialCreated>(`/api/domains/${domainId}/smtp-credentials`, { method: "POST", body: JSON.stringify({ label }) }); }
  revoke(domainId: string, credId: string) { return this.req<{ ok: boolean }>(`/api/domains/${domainId}/smtp-credentials/${credId}`, { method: "DELETE" }); }
}

class ApiKeysResource {
  constructor(private req: Req) {}
  list() { return this.req<ApiKey[]>("/api/api-keys"); }
  create(name: string) { return this.req<ApiKey & { key: string }>("/api/api-keys", { method: "POST", body: JSON.stringify({ name }) }); }
  revoke(id: string) { return this.req<{ ok: boolean }>(`/api/api-keys/${id}`, { method: "DELETE" }); }
}

class BillingResource {
  constructor(private req: Req) {}
  status() { return this.req<BillingStatus>("/api/billing/status"); }
  addons() { return this.req<AddonsResponse>("/api/addons"); }
  /**
   * Liga de MercadoPago para un add-on de un dominio (`domain` = activarlo, $99/mes).
   * El usuario la abre y paga; hasta entonces no cambia nada.
   */
  checkout(domainId: string, kind: "domain" | "storage50" | "sends100" = "domain", opts?: { payerEmail?: string; period?: "monthly" | "annual" }) {
    return this.req<CheckoutLink>("/api/addons/checkout", { method: "POST", body: JSON.stringify({ kind, domainId, payerEmail: opts?.payerEmail, period: opts?.period }) });
  }
  /** Cancela la suscripción de un add-on; el cupo sigue hasta el fin del periodo pagado. */
  cancelAddon(addonId: string) { return this.req<{ ok: boolean; activeUntil: string | null }>(`/api/addons/${addonId}/cancel`, { method: "POST" }); }
  /** Historial de cobros, cortesías y cancelaciones (más reciente primero). */
  orders(opts?: { limit?: number; before?: string }) {
    const qs = new URLSearchParams();
    if (opts?.limit) qs.set("limit", String(opts.limit));
    if (opts?.before) qs.set("before", opts.before);
    const q = qs.toString();
    return this.req<OrdersPage>(`/api/billing/orders${q ? `?${q}` : ""}`);
  }
}

class RegistrationsResource {
  constructor(private req: Req) {}
  search(domain: string) { return this.req<DomainSearchResult>(`/api/domains/search?q=${encodeURIComponent(domain)}`); }
  tlds() { return this.req<TldPrice[]>("/api/domains/tlds"); }
  /** Crea el registro pendiente y devuelve la liga de pago; el dominio se registra al pagar. */
  register(domain: string) { return this.req<DomainRegistrationCreated>("/api/domains/register", { method: "POST", body: JSON.stringify({ domain }) }); }
  list() { return this.req<DomainRegistration[]>("/api/domains/registrations"); }
  /** Pide el traslado a otro registrador. El código EPP llega por correo al dueño, nunca en la respuesta. */
  transferOut(regId: string) { return this.req<{ ok: boolean; aviso: string }>(`/api/domains/registrations/${regId}/transfer-out`, { method: "POST" }); }
  /** Liga de MercadoPago para la suscripción de renovación anual. */
  renewal(regId: string, opts?: { payerEmail?: string }) {
    return this.req<RenewalLink>(`/api/domains/registrations/${regId}/renewal`, { method: "POST", body: JSON.stringify({ payerEmail: opts?.payerEmail }) });
  }
  /** Deja de cobrar la renovación anual. El dominio sigue vigente hasta su vencimiento. */
  cancelRenewal(regId: string) { return this.req<{ ok: boolean; aviso: string }>(`/api/domains/registrations/${regId}/renewal/cancel`, { method: "POST" }); }
}

class TransfersResource {
  constructor(private req: Req) {}
  /** Requisitos, precio e inventario del DNS actual. No cobra ni crea nada. */
  check(domain: string) { return this.req<TransferCheck>("/api/domains/transfer/check", { method: "POST", body: JSON.stringify({ domain }) }); }
  dns(regId: string) { return this.req<TransferDnsInventory>(`/api/domains/transfer/${regId}/dns`); }
  /** Reemplaza el inventario completo (RRSets). Vuelve a quedar pendiente de aprobar. */
  setDns(regId: string, records: { name: string; type: string; ttl?: number; values: string[] }[]) {
    return this.req<{ records: unknown[] }>(`/api/domains/transfer/${regId}/dns`, { method: "PUT", body: JSON.stringify({ records }) });
  }
  approveDns(regId: string) { return this.req<{ ok: boolean }>(`/api/domains/transfer/${regId}/dns/approve`, { method: "POST" }); }
  resendEmail(regId: string) { return this.req<{ ok: boolean }>(`/api/domains/transfer/${regId}/resend-email`, { method: "POST" }); }
}

class MembersResource {
  constructor(private req: Req) {}
  list(domainId: string) { return this.req<{ members: DomainMember[]; invites: DomainInvite[] }>(`/api/domains/${domainId}/agents`); }
  invite(domainId: string, input: { email: string; name: string; role?: "admin" | "agent" }) {
    return this.req<{ ok: boolean; inviteUrl: string }>(`/api/domains/${domainId}/agents/invite`, { method: "POST", body: JSON.stringify(input) });
  }
  remove(domainId: string, memberId: string) { return this.req<{ ok: boolean }>(`/api/domains/${domainId}/agents/${memberId}`, { method: "DELETE" }); }
  cancelInvite(domainId: string, token: string) { return this.req<{ ok: boolean }>(`/api/domains/${domainId}/agents/invites/${token}`, { method: "DELETE" }); }
}

class SignatureResource {
  constructor(private req: Req) {}
  async get(domainId: string) {
    const d = await this.req<{ signature?: string | null }>(`/api/domains/${domainId}`);
    return { signature: d.signature ?? null };
  }
  /** Markdown, máx. 2000 caracteres. Cadena vacía la borra. */
  set(domainId: string, signature: string) {
    return this.req<{ ok: boolean; signature: string | null }>(`/api/domains/${domainId}/signature`, { method: "PUT", body: JSON.stringify({ signature }) });
  }
}

class CannedResource {
  constructor(private req: Req) {}
  list(domainId: string) { return this.req<CannedReply[]>(`/api/domains/${domainId}/canned`); }
  create(domainId: string, input: { title: string; body: string }) {
    return this.req<CannedReply>(`/api/domains/${domainId}/canned`, { method: "POST", body: JSON.stringify(input) });
  }
  delete(domainId: string, cannedId: string) { return this.req<{ ok: boolean }>(`/api/domains/${domainId}/canned/${cannedId}`, { method: "DELETE" }); }
}

class AccountResource {
  constructor(private req: Req) {}
  getProfile() { return this.req<AccountProfile>("/api/profile"); }
  /** Nombre visible (máx. 60 caracteres). Cadena vacía lo borra. */
  updateProfile(input: { displayName: string | null }) {
    return this.req<AccountProfile>("/api/profile", { method: "PUT", body: JSON.stringify(input) });
  }
  /** Foto desde un adjunto que el usuario subió al asistente (URL firmada de `/api/asistente/files/*`). */
  setAvatarFromUrl(url: string) {
    return this.req<AccountProfile & { ok: boolean }>("/api/profile/avatar", { method: "POST", body: JSON.stringify({ fromUrl: url }) });
  }
  /** Foto desde bytes (PNG, JPG o WebP; máx. 2 MB). */
  setAvatar(file: Blob, filename = "avatar") {
    const form = new FormData();
    form.append("file", file, filename);
    return this.req<AccountProfile & { ok: boolean }>("/api/profile/avatar", { method: "POST", body: form });
  }
  removeAvatar() { return this.req<AccountProfile & { ok: boolean }>("/api/profile/avatar", { method: "DELETE" }); }
}

/**
 * La Bandeja: conversaciones del dominio. Todo pasa por los mismos permisos que la app
 * (dueño, admin o agente invitado) y los mismos topes de envío.
 */
class InboxResource {
  constructor(private req: Req, private raw: (path: string) => Promise<Response>) {}
  list(domainId: string, opts?: InboxListOptions) {
    const qs = new URLSearchParams({ domainId });
    for (const [k, v] of Object.entries(opts ?? {})) if (v !== undefined && v !== "") qs.set(k, String(v));
    return this.req<InboxPage>(`/api/bandeja/conversations?${qs}`);
  }
  /** Conversación con sus mensajes (los 30 más recientes, o anteriores a `before`). Abrirla la marca leída. */
  get(domainId: string, conversationId: string, opts?: { before?: string }) {
    const qs = new URLSearchParams({ domainId });
    if (opts?.before) qs.set("before", opts.before);
    return this.req<InboxConversationDetail>(`/api/bandeja/conversations/${conversationId}?${qs}`);
  }
  /** Un correo nuevo desde una máscara: abre un hilo. Gasta cuota de envío (dominio activado). */
  compose(domainId: string, input: InboxComposeInput) {
    return this.req<{ ok: boolean; conversationId: string; messageId: string }>("/api/bandeja/conversations", { method: "POST", body: JSON.stringify({ ...input, domainId }) });
  }
  /** Responde en el hilo desde la máscara del hilo. No gasta cuota de envío. */
  reply(domainId: string, conversationId: string, input: InboxReplyInput) {
    return this.req<{ ok: boolean; messageId: string }>(`/api/bandeja/conversations/${conversationId}/reply`, { method: "POST", body: JSON.stringify({ ...input, domainId }) });
  }
  update(domainId: string, conversationId: string, input: InboxUpdateInput) {
    return this.req<InboxConversation>(`/api/bandeja/conversations/${conversationId}`, { method: "PATCH", body: JSON.stringify({ ...input, domainId }) });
  }
  markRead(domainId: string, conversationId: string) {
    return this.req<{ ok: boolean; unreadCount: number }>(`/api/bandeja/conversations/${conversationId}/read`, { method: "POST", body: JSON.stringify({ domainId }) });
  }
  /** Sin `assignedTo` la deja sin asignar. */
  assign(domainId: string, conversationId: string, assignedTo?: string) {
    return this.req<InboxConversation>(`/api/bandeja/conversations/${conversationId}/assign`, { method: "POST", body: JSON.stringify({ domainId, assignedTo }) });
  }
  /** Nota interna: la ve el equipo, nunca el contacto. */
  addNote(domainId: string, conversationId: string, body: string) {
    return this.req<InboxNote>(`/api/bandeja/conversations/${conversationId}/note`, { method: "POST", body: JSON.stringify({ domainId, body }) });
  }
  /** A la papelera (se puede restaurar). Máx. 200 por llamada. */
  delete(domainId: string, conversationIds: string[]) {
    return this.req<{ ok: boolean; deleted: number }>("/api/bandeja/conversations/bulk-delete", { method: "POST", body: JSON.stringify({ domainId, ids: conversationIds }) });
  }
  restore(domainId: string, conversationId: string) {
    return this.req<{ ok: boolean }>(`/api/bandeja/conversations/${conversationId}/restore`, { method: "POST", body: JSON.stringify({ domainId }) });
  }
  metrics(domainId: string, opts?: { days?: number }) {
    const qs = new URLSearchParams({ domainId });
    if (opts?.days) qs.set("days", String(opts.days));
    return this.req<Record<string, unknown>>(`/api/bandeja/metrics?${qs}`);
  }
  /** Bytes de un adjunto de un mensaje (id del mensaje e índice de `attachments`). */
  attachment(domainId: string, conversationId: string, messageId: string, index: number) {
    return this.raw(`/api/bandeja/conversations/${conversationId}/attachments/${messageId}/${index}?domainId=${encodeURIComponent(domainId)}`);
  }
}

class ReferralsResource {
  constructor(private req: Req) {}
  get() { return this.req<ReferralStats>("/api/referrals"); }
  /** 3-30 caracteres: minúsculas, números y guiones. */
  setSlug(slug: string) { return this.req<{ ok: boolean; slug: string }>("/api/referrals/slug", { method: "PUT", body: JSON.stringify({ slug }) }); }
  /** Nombre que ven los invitados (2-40 caracteres). */
  setName(name: string) { return this.req<{ ok: boolean }>("/api/referrals/name", { method: "PUT", body: JSON.stringify({ name }) }); }
}

export { MailMaskError };
