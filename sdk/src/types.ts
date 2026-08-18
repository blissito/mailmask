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
  /** Parte local, sin el dominio: "hola" para hola@tudominio.com. `*` para catch-all. */
  alias: string;
  destinations: string[];
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
  to: string;
  subject: string;
  /** Al menos uno de `html` o `body`. Con los dos se manda multipart. */
  html?: string;
  body?: string;
  replyTo?: string;
  /**
   * Parte local de un alias **activo** del dominio. Sin esto el correo sale
   * desde `noreply@tudominio.com`.
   */
  from?: string;
  /** Nombre visible del remitente: `Libretas <hola@tudominio.com>`. */
  fromName?: string;
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
  lastUsedAt?: string;
  createdAt: string;
}
