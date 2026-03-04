import type {
  MailMaskConfig, Domain, Alias, CreateAliasInput, UpdateAliasInput,
  Rule, CreateRuleInput, UpdateRuleInput, EmailLog, SendEmailInput,
  BulkSendInput, BulkJob, SmtpCredential, ApiKey,
} from "./types.js";

class MailMaskError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "MailMaskError";
  }
}

async function request<T>(baseUrl: string, apiKey: string, path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${baseUrl}${path}`, {
    ...opts,
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json",
      ...opts?.headers,
    },
  });
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
  smtp: SmtpResource;
  apiKeys: ApiKeysResource;

  constructor(config: MailMaskConfig) {
    this.apiKey = config.apiKey;
    this.baseUrl = (config.baseUrl || "https://www.mailmask.studio").replace(/\/$/, "");
    const req = <T>(path: string, opts?: RequestInit) => request<T>(this.baseUrl, this.apiKey, path, opts);

    this.domains = new DomainsResource(req);
    this.aliases = new AliasesResource(req);
    this.rules = new RulesResource(req);
    this.logs = new LogsResource(req);
    this.send = new SendResource(req);
    this.smtp = new SmtpResource(req);
    this.apiKeys = new ApiKeysResource(req);
  }
}

type Req = <T>(path: string, opts?: RequestInit) => Promise<T>;

class DomainsResource {
  constructor(private req: Req) {}
  list() { return this.req<Domain[]>("/api/domains"); }
  get(id: string) { return this.req<Domain>(`/api/domains/${id}`); }
  create(domain: string) { return this.req<{ domain: Domain }>("/api/domains", { method: "POST", body: JSON.stringify({ domain }) }); }
  delete(id: string) { return this.req<{ ok: boolean }>(`/api/domains/${id}`, { method: "DELETE" }); }
  health(id: string) { return this.req<Record<string, unknown>>(`/api/domains/${id}/health`); }
  verify(id: string) { return this.req<Record<string, unknown>>(`/api/domains/${id}/verify`, { method: "POST" }); }
}

class AliasesResource {
  constructor(private req: Req) {}
  list(domainId: string) { return this.req<Alias[]>(`/api/domains/${domainId}/aliases`); }
  create(domainId: string, input: CreateAliasInput) { return this.req<Alias>(`/api/domains/${domainId}/aliases`, { method: "POST", body: JSON.stringify(input) }); }
  update(domainId: string, alias: string, input: UpdateAliasInput) { return this.req<Alias>(`/api/domains/${domainId}/aliases/${alias}`, { method: "PUT", body: JSON.stringify(input) }); }
  delete(domainId: string, alias: string) { return this.req<{ ok: boolean }>(`/api/domains/${domainId}/aliases/${alias}`, { method: "DELETE" }); }
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
  list(domainId: string) { return this.req<EmailLog[]>(`/api/domains/${domainId}/logs`); }
}

class SendResource {
  constructor(private req: Req) {}
  send(domainId: string, input: SendEmailInput) { return this.req<{ messageId: string }>(`/api/domains/${domainId}/send`, { method: "POST", body: JSON.stringify(input) }); }
  bulkSend(domainId: string, input: BulkSendInput) { return this.req<BulkJob>(`/api/domains/${domainId}/bulk-send`, { method: "POST", body: JSON.stringify(input) }); }
  bulkStatus(domainId: string, jobId: string) { return this.req<BulkJob>(`/api/domains/${domainId}/bulk-send/${jobId}`); }
}

class SmtpResource {
  constructor(private req: Req) {}
  list(domainId: string) { return this.req<SmtpCredential[]>(`/api/domains/${domainId}/smtp-credentials`); }
  create(domainId: string, label: string) { return this.req<SmtpCredential & { smtpPassword: string }>(`/api/domains/${domainId}/smtp-credentials`, { method: "POST", body: JSON.stringify({ label }) }); }
  revoke(domainId: string, credId: string) { return this.req<{ ok: boolean }>(`/api/domains/${domainId}/smtp-credentials/${credId}`, { method: "DELETE" }); }
}

class ApiKeysResource {
  constructor(private req: Req) {}
  list() { return this.req<ApiKey[]>("/api/api-keys"); }
  create(name: string) { return this.req<ApiKey & { key: string }>("/api/api-keys", { method: "POST", body: JSON.stringify({ name }) }); }
  revoke(id: string) { return this.req<{ ok: boolean }>(`/api/api-keys/${id}`, { method: "DELETE" }); }
}

export { MailMaskError };
