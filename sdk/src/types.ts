export interface MailMaskConfig {
  apiKey: string;
  baseUrl?: string;
}

export interface Domain {
  id: string;
  domain: string;
  verified: boolean;
  mxConfigured: boolean;
  createdAt: string;
}

export interface Alias {
  alias: string;
  domainId: string;
  destinations: string[];
  enabled: boolean;
  forwardCount: number;
  createdAt: string;
}

export interface CreateAliasInput {
  local: string;
  forwardTo: string | string[];
}

export interface UpdateAliasInput {
  enabled?: boolean;
  destinations?: string[];
}

export interface Rule {
  id: string;
  domainId: string;
  field: "to" | "from" | "subject";
  match: string;
  value: string;
  action: string;
  target: string;
  priority: number;
  enabled: boolean;
  createdAt: string;
}

export interface CreateRuleInput {
  field: "to" | "from" | "subject";
  match: string;
  value: string;
  action: string;
  target: string;
  priority?: number;
}

export interface UpdateRuleInput {
  field?: "to" | "from" | "subject";
  match?: string;
  value?: string;
  action?: string;
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
  status: string;
  forwardedTo: string;
  error?: string;
}

export interface SendEmailInput {
  fromLocal: string;
  to: string;
  subject: string;
  html: string;
}

export interface BulkSendInput {
  from: string;
  recipients: string[];
  subject: string;
  html: string;
}

export interface BulkJob {
  id: string;
  status: string;
  totalRecipients: number;
  sent: number;
  failed: number;
}

export interface SmtpCredential {
  id: string;
  domainId: string;
  label: string;
  iamUsername: string;
  createdAt: string;
}

export interface ApiKey {
  id: string;
  name: string;
  lastUsedAt?: string;
  createdAt: string;
}
