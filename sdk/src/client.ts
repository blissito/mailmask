import type {
  MailMaskConfig, Domain, DomainCreated, DomainVerification, Alias, AliasCreated, MailboxCreated, CreateAliasInput, UpdateAliasInput,
  Rule, CreateRuleInput, UpdateRuleInput, EmailLog, SendEmailInput,
  BulkSendInput, BulkJob, BulkJobCreated, SmtpCredential, SmtpCredentialCreated,
  ApiKey, SendOptions, UploadAttachmentInput, UploadedAttachment, Suppression,
  Webhook, WebhookCreated, CreateWebhookInput, UpdateWebhookInput, WebhookDelivery,
  DnsRecordType, DnsRRSet, DnsListResponse, DnsZoneCreated, DnsDelegation, DnsImportResult,
  DnsChangeResult, DnsPreset,
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

  constructor(config: MailMaskConfig) {
    this.apiKey = config.apiKey;
    this.baseUrl = (config.baseUrl || "https://www.mailmask.studio").replace(/\/$/, "");
    // Sin bind, un `fetch` de config que sea el global de node truena con
    // "Illegal invocation" al perder su receptor.
    const doFetch = config.fetch ? config.fetch : fetch;
    const req = <T>(path: string, opts?: RequestInit) => request<T>(this.baseUrl, this.apiKey, path, opts, doFetch);

    this.domains = new DomainsResource(req);
    this.aliases = new AliasesResource(req);
    this.rules = new RulesResource(req);
    this.logs = new LogsResource(req);
    this.send = new SendResource(req);
    this.attachments = new AttachmentsResource(req);
    this.suppressions = new SuppressionsResource(req);
    this.webhooks = new WebhooksResource(req);
    this.smtp = new SmtpResource(req);
    this.apiKeys = new ApiKeysResource(req);
    this.dns = new DnsResource(req);
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
  constructor(private req: Req) {}
  list(domainId: string) { return this.req<Alias[]>(`/api/domains/${domainId}/alias`); }
  create(domainId: string, input: CreateAliasInput) { return this.req<AliasCreated>(`/api/domains/${domainId}/alias`, { method: "POST", body: JSON.stringify({ ...input, destinations: input.destinations ?? [] }) }); }
  /** Crea un buzón IMAP para una máscara existente. La contraseña sólo se devuelve aquí. */
  createMailbox(domainId: string, alias: string) { return this.req<MailboxCreated>(`/api/domains/${domainId}/alias/${alias}/mailbox`, { method: "POST" }); }
  /** Borra el buzón Y SU CORREO. La máscara debe conservar al menos un destino. */
  deleteMailbox(domainId: string, alias: string) { return this.req<{ ok: boolean }>(`/api/domains/${domainId}/alias/${alias}/mailbox`, { method: "DELETE" }); }
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

export { MailMaskError };
