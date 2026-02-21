import { sql as _sql } from "./pg.ts";

let sql = _sql;

// --- Types ---

export interface Subscription {
  plan: "basico" | "freelancer" | "developer" | "pro" | "agencia";
  status: "active" | "past_due" | "cancelled" | "none";
  mpSubscriptionId?: string;
  currentPeriodEnd?: string; // ISO date
}

export interface User {
  email: string;
  passwordHash: string;
  createdAt: string;
  subscription?: Subscription;
  emailVerified?: boolean;
  verifyToken?: string;
  passwordChangedAt?: string; // ISO date
}

export interface Domain {
  id: string;
  ownerEmail: string;
  domain: string;
  verified: boolean;
  mxConfigured: boolean;
  dkimTokens: string[];
  verificationToken: string;
  createdAt: string;
}

export interface Alias {
  alias: string;
  domainId: string;
  destinations: string[];
  enabled: boolean;
  createdAt: string;
  forwardCount?: number;
  lastFrom?: string;
  lastAt?: string;
}

export interface Rule {
  id: string;
  domainId: string;
  field: "to" | "from" | "subject";
  match: "contains" | "equals" | "regex";
  value: string;
  action: "forward" | "webhook" | "discard";
  target: string;
  priority: number;
  enabled: boolean;
  createdAt: string;
}

export interface EmailLog {
  id: string;
  domainId: string;
  timestamp: string;
  from: string;
  to: string;
  subject: string;
  status: "forwarded" | "discarded" | "failed" | "rule_matched";
  forwardedTo: string;
  sizeBytes: number;
  error?: string;
}

// --- Plans ---

export const PLANS = {
  basico:     { price: 49_00,  yearlyPrice: 490_00,  domains: 1,  aliases: 5,   rules: 0,   logDays: 0,  sends: 0,     api: false, webhooks: false, forwardPerHour: 100 },
  freelancer: { price: 449_00, yearlyPrice: 4490_00, domains: 15, aliases: 50,  rules: 10,  logDays: 30, sends: 500,   api: false, webhooks: false, forwardPerHour: 500 },
  developer:  { price: 999_00, yearlyPrice: 9990_00, domains: 20, aliases: 100, rules: 50,  logDays: 90, sends: 2000,  api: true,  webhooks: true,  forwardPerHour: 2000 },
  pro:     { price: 299_00, yearlyPrice: 2990_00, domains: 15, aliases: 50,  rules: 10,  logDays: 30, sends: 500,   api: false, webhooks: false, forwardPerHour: 500 },
  agencia: { price: 999_00, yearlyPrice: 9990_00, domains: 20, aliases: 100, rules: 50,  logDays: 90, sends: 2000,  api: true,  webhooks: true,  forwardPerHour: 2000 },
} as const;

// --- Row → interface mappers ---

function rowToUser(r: any): User {
  const user: User = {
    email: r.email,
    passwordHash: r.password_hash,
    createdAt: r.created_at instanceof Date ? r.created_at.toISOString() : r.created_at,
    emailVerified: r.email_verified ?? false,
    passwordChangedAt: r.password_changed_at ? (r.password_changed_at instanceof Date ? r.password_changed_at.toISOString() : r.password_changed_at) : undefined,
  };
  if (r.sub_plan) {
    user.subscription = {
      plan: r.sub_plan,
      status: r.sub_status ?? "none",
      mpSubscriptionId: r.sub_mp_id ?? undefined,
      currentPeriodEnd: r.sub_period_end ? (r.sub_period_end instanceof Date ? r.sub_period_end.toISOString() : r.sub_period_end) : undefined,
    };
  }
  return user;
}

function rowToDomain(r: any): Domain {
  return {
    id: r.id,
    ownerEmail: r.owner_email,
    domain: r.domain,
    verified: r.verified,
    mxConfigured: r.mx_configured,
    dkimTokens: r.dkim_tokens ?? [],
    verificationToken: r.verification_token,
    createdAt: r.created_at instanceof Date ? r.created_at.toISOString() : r.created_at,
  };
}

function rowToAlias(r: any): Alias {
  return {
    alias: r.alias,
    domainId: r.domain_id,
    destinations: r.destinations ?? [],
    enabled: r.enabled,
    createdAt: r.created_at instanceof Date ? r.created_at.toISOString() : r.created_at,
    forwardCount: r.forward_count || undefined,
    lastFrom: r.last_from ?? undefined,
    lastAt: r.last_at ? (r.last_at instanceof Date ? r.last_at.toISOString() : r.last_at) : undefined,
  };
}

function rowToRule(r: any): Rule {
  return {
    id: r.id,
    domainId: r.domain_id,
    field: r.field,
    match: r.match,
    value: r.value,
    action: r.action,
    target: r.target,
    priority: r.priority,
    enabled: r.enabled,
    createdAt: r.created_at instanceof Date ? r.created_at.toISOString() : r.created_at,
  };
}

function rowToLog(r: any): EmailLog {
  return {
    id: r.id,
    domainId: r.domain_id,
    timestamp: r.timestamp instanceof Date ? r.timestamp.toISOString() : r.timestamp,
    from: r.from,
    to: r.to,
    subject: r.subject,
    status: r.status,
    forwardedTo: r.forwarded_to,
    sizeBytes: r.size_bytes,
    error: r.error ?? undefined,
  };
}

// --- Users ---

export async function getUser(email: string): Promise<User | null> {
  const rows = await sql`SELECT * FROM users WHERE email = ${email}`;
  return rows.length ? rowToUser(rows[0]) : null;
}

export async function createUser(email: string, passwordHash: string): Promise<User> {
  const rows = await sql`
    INSERT INTO users (email, password_hash) VALUES (${email}, ${passwordHash})
    RETURNING *`;
  return rowToUser(rows[0]);
}

export async function getUserByVerifyToken(token: string): Promise<User | null> {
  const rows = await sql`
    SELECT value FROM tokens WHERE token = ${token} AND kind = 'verify' AND expires_at > NOW()`;
  if (!rows.length) return null;
  const email = (rows[0].value as any)?.email;
  if (!email) return null;
  return getUser(email);
}

export async function setVerifyToken(email: string, token: string): Promise<void> {
  const user = await getUser(email);
  if (!user) return;
  await sql`UPDATE users SET email_verified = FALSE WHERE email = ${email}`;
  await sql`
    INSERT INTO tokens (token, kind, value, expires_at)
    VALUES (${token}, 'verify', ${JSON.stringify({ email })}, NOW() + INTERVAL '7 days')
    ON CONFLICT (token) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at`;
}

export async function verifyUserEmail(email: string): Promise<void> {
  await sql`UPDATE users SET email_verified = TRUE WHERE email = ${email}`;
  // Clean up verify tokens for this user
  await sql`DELETE FROM tokens WHERE kind = 'verify' AND value->>'email' = ${email}`;
}

// --- Domains ---

export async function createDomain(ownerEmail: string, domain: string, dkimTokens: string[], verificationToken: string): Promise<Domain> {
  const rows = await sql`
    INSERT INTO domains (owner_email, domain, dkim_tokens, verification_token)
    VALUES (${ownerEmail}, ${domain}, ${dkimTokens}, ${verificationToken})
    RETURNING *`;
  return rowToDomain(rows[0]);
}

export async function getDomain(id: string): Promise<Domain | null> {
  const rows = await sql`SELECT * FROM domains WHERE id = ${id}`;
  return rows.length ? rowToDomain(rows[0]) : null;
}

export async function getDomainByName(domain: string): Promise<Domain | null> {
  const rows = await sql`SELECT * FROM domains WHERE domain = ${domain}`;
  return rows.length ? rowToDomain(rows[0]) : null;
}

export async function listUserDomains(email: string): Promise<Domain[]> {
  const rows = await sql`SELECT * FROM domains WHERE owner_email = ${email} ORDER BY created_at`;
  return rows.map(rowToDomain);
}

export async function updateDomain(id: string, updates: Partial<Pick<Domain, "verified" | "mxConfigured">>): Promise<Domain | null> {
  const sets: string[] = [];
  if (updates.verified !== undefined) sets.push("verified");
  if (updates.mxConfigured !== undefined) sets.push("mx_configured");
  if (!sets.length) return getDomain(id);

  const rows = await sql`
    UPDATE domains SET
      verified = COALESCE(${updates.verified ?? null}, verified),
      mx_configured = COALESCE(${updates.mxConfigured ?? null}, mx_configured)
    WHERE id = ${id} RETURNING *`;
  return rows.length ? rowToDomain(rows[0]) : null;
}

export async function deleteDomain(id: string): Promise<boolean> {
  // CASCADE handles alias, rules, conversations, messages, notes, agents, suppressions, email_logs
  const res = await sql`DELETE FROM domains WHERE id = ${id}`;
  return res.count > 0;
}

export async function countUserDomains(email: string): Promise<number> {
  const rows = await sql`SELECT COUNT(*)::int AS c FROM domains WHERE owner_email = ${email}`;
  return rows[0].c;
}

// --- Aliases ---

export async function createAlias(domainId: string, alias: string, destinations: string[]): Promise<Alias> {
  const rows = await sql`
    INSERT INTO alias (domain_id, alias, destinations)
    VALUES (${domainId}, ${alias}, ${destinations})
    RETURNING *`;
  return rowToAlias(rows[0]);
}

export async function getAlias(domainId: string, alias: string): Promise<Alias | null> {
  const rows = await sql`SELECT * FROM alias WHERE domain_id = ${domainId} AND alias = ${alias}`;
  return rows.length ? rowToAlias(rows[0]) : null;
}

export async function listAliases(domainId: string): Promise<Alias[]> {
  const rows = await sql`SELECT * FROM alias WHERE domain_id = ${domainId} ORDER BY created_at`;
  return rows.map(rowToAlias);
}

export async function updateAlias(domainId: string, alias: string, updates: Partial<Pick<Alias, "destinations" | "enabled">>): Promise<Alias | null> {
  const rows = await sql`
    UPDATE alias SET
      destinations = COALESCE(${updates.destinations ?? null}, destinations),
      enabled = COALESCE(${updates.enabled ?? null}, enabled)
    WHERE domain_id = ${domainId} AND alias = ${alias}
    RETURNING *`;
  return rows.length ? rowToAlias(rows[0]) : null;
}

export async function bumpAliasStats(domainId: string, alias: string, from: string): Promise<void> {
  await sql`
    UPDATE alias SET
      forward_count = forward_count + 1,
      last_from = ${from},
      last_at = NOW()
    WHERE domain_id = ${domainId} AND alias = ${alias}`;
}

export async function deleteAlias(domainId: string, alias: string): Promise<boolean> {
  const res = await sql`DELETE FROM alias WHERE domain_id = ${domainId} AND alias = ${alias}`;
  return res.count > 0;
}

export async function countAliases(domainId: string): Promise<number> {
  const rows = await sql`SELECT COUNT(*)::int AS c FROM alias WHERE domain_id = ${domainId}`;
  return rows[0].c;
}

// --- Rules ---

export async function createRule(domainId: string, rule: Omit<Rule, "id" | "domainId" | "createdAt">): Promise<Rule> {
  const rows = await sql`
    INSERT INTO rules (domain_id, field, match, value, action, target, priority, enabled)
    VALUES (${domainId}, ${rule.field}, ${rule.match}, ${rule.value}, ${rule.action}, ${rule.target}, ${rule.priority}, ${rule.enabled})
    RETURNING *`;
  return rowToRule(rows[0]);
}

export async function listRules(domainId: string): Promise<Rule[]> {
  const rows = await sql`SELECT * FROM rules WHERE domain_id = ${domainId} ORDER BY priority`;
  return rows.map(rowToRule);
}

export async function deleteRule(domainId: string, ruleId: string): Promise<boolean> {
  const res = await sql`DELETE FROM rules WHERE domain_id = ${domainId} AND id = ${ruleId}`;
  return res.count > 0;
}

// --- Logs ---

export async function addLog(log: Omit<EmailLog, "id">, logDays = 30): Promise<EmailLog> {
  const rows = await sql`
    INSERT INTO email_logs (domain_id, timestamp, "from", "to", subject, status, forwarded_to, size_bytes, error, expires_at)
    VALUES (${log.domainId}, ${log.timestamp}, ${log.from}, ${log.to}, ${log.subject}, ${log.status}, ${log.forwardedTo}, ${log.sizeBytes}, ${log.error ?? null}, NOW() + ${logDays + ' days'}::interval)
    RETURNING *`;
  return rowToLog(rows[0]);
}

export async function listLogs(domainId: string, limit = 50): Promise<EmailLog[]> {
  const rows = await sql`
    SELECT * FROM email_logs
    WHERE domain_id = ${domainId} AND expires_at > NOW()
    ORDER BY timestamp DESC LIMIT ${limit}`;
  return rows.map(rowToLog);
}

// --- Subscription helpers ---

export async function getUserBySubscriptionId(mpSubId: string): Promise<User | null> {
  const rows = await sql`SELECT * FROM users WHERE sub_mp_id = ${mpSubId}`;
  return rows.length ? rowToUser(rows[0]) : null;
}

export async function extendSubscriptionPeriod(email: string, days: number): Promise<void> {
  const user = await getUser(email);
  if (!user?.subscription) return;
  const existing = user.subscription.currentPeriodEnd
    ? new Date(user.subscription.currentPeriodEnd)
    : new Date();
  const base = existing > new Date() ? existing : new Date();
  base.setDate(base.getDate() + days);
  await updateUserSubscription(email, {
    ...user.subscription,
    status: "active",
    currentPeriodEnd: base.toISOString(),
  });
}

export async function updateUserSubscription(email: string, sub: Subscription): Promise<User | null> {
  const rows = await sql`
    UPDATE users SET
      sub_plan = ${sub.plan},
      sub_status = ${sub.status},
      sub_mp_id = ${sub.mpSubscriptionId ?? null},
      sub_period_end = ${sub.currentPeriodEnd ?? null}
    WHERE email = ${email} RETURNING *`;
  return rows.length ? rowToUser(rows[0]) : null;
}

export function getUserPlanLimits(user: User): { domains: number; aliases: number; rules: number; logDays: number; sends: number; api: boolean; webhooks: boolean; forwardPerHour: number } {
  const sub = user.subscription;
  if (sub && (sub.status === "active" || sub.status === "cancelled")) {
    if (sub.currentPeriodEnd && new Date(sub.currentPeriodEnd) < new Date()) {
      return { domains: 0, aliases: 0, rules: 0, logDays: 0, sends: 0, api: false, webhooks: false, forwardPerHour: 0 };
    }
    const plan = PLANS[sub.plan];
    return { domains: plan.domains, aliases: plan.aliases, rules: plan.rules, logDays: plan.logDays, sends: plan.sends, api: plan.api, webhooks: plan.webhooks, forwardPerHour: plan.forwardPerHour };
  }
  return { domains: 0, aliases: 0, rules: 0, logDays: 0, sends: 0, api: false, webhooks: false, forwardPerHour: 0 };
}

// --- Pending checkout (guest flow) ---

export async function createPendingCheckout(token: string, plan: string): Promise<void> {
  await sql`
    INSERT INTO tokens (token, kind, value, expires_at)
    VALUES (${token}, 'pending-checkout', ${JSON.stringify({ plan })}, NOW() + INTERVAL '24 hours')
    ON CONFLICT (token) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at`;
}

export async function getPendingCheckout(token: string): Promise<string | null> {
  const rows = await sql`
    SELECT value FROM tokens WHERE token = ${token} AND kind = 'pending-checkout' AND expires_at > NOW()`;
  if (!rows.length) return null;
  return (rows[0].value as any)?.plan ?? null;
}

export async function deletePendingCheckout(token: string): Promise<void> {
  await sql`DELETE FROM tokens WHERE token = ${token} AND kind = 'pending-checkout'`;
}

// --- Password token (set-password flow) ---

export async function setPasswordToken(email: string, token: string): Promise<void> {
  await sql`
    INSERT INTO tokens (token, kind, value, expires_at)
    VALUES (${token}, 'password', ${JSON.stringify({ email })}, NOW() + INTERVAL '7 days')
    ON CONFLICT (token) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at`;
}

export async function getEmailByPasswordToken(token: string): Promise<string | null> {
  const rows = await sql`
    SELECT value FROM tokens WHERE token = ${token} AND kind = 'password' AND expires_at > NOW()`;
  if (!rows.length) return null;
  return (rows[0].value as any)?.email ?? null;
}

export async function deletePasswordToken(token: string): Promise<void> {
  await sql`DELETE FROM tokens WHERE token = ${token} AND kind = 'password'`;
}

// --- Update user password ---

export async function updateUserPassword(email: string, passwordHash: string): Promise<void> {
  await sql`UPDATE users SET password_hash = ${passwordHash}, password_changed_at = NOW() WHERE email = ${email}`;
}

// --- Webhook idempotency ---

export async function isWebhookProcessed(id: string): Promise<boolean> {
  const rows = await sql`
    SELECT 1 FROM tokens WHERE token = ${id} AND kind = 'webhook' AND expires_at > NOW()`;
  return rows.length > 0;
}

export async function markWebhookProcessed(id: string): Promise<void> {
  await sql`
    INSERT INTO tokens (token, kind, value, expires_at)
    VALUES (${id}, 'webhook', '{}', NOW() + INTERVAL '7 days')
    ON CONFLICT (token) DO NOTHING`;
}

// --- Atomic user creation (guest checkout) ---

export async function createUserIfNotExists(email: string, passwordHash: string): Promise<boolean> {
  const rows = await sql`
    INSERT INTO users (email, password_hash) VALUES (${email}, ${passwordHash})
    ON CONFLICT (email) DO NOTHING RETURNING email`;
  return rows.length > 0;
}

// --- SNS message dedup ---

export async function isMessageProcessed(messageId: string): Promise<boolean> {
  const rows = await sql`
    SELECT 1 FROM tokens WHERE token = ${messageId} AND kind = 'sns' AND expires_at > NOW()`;
  return rows.length > 0;
}

export async function markMessageProcessed(messageId: string): Promise<void> {
  await sql`
    INSERT INTO tokens (token, kind, value, expires_at)
    VALUES (${messageId}, 'sns', '{}', NOW() + INTERVAL '24 hours')
    ON CONFLICT (token) DO NOTHING`;
}

// --- Forward queue (retry on SES failure) ---

export interface ForwardQueueItem {
  id: string;
  rawContent: string;
  from: string;
  to: string;
  domainId: string;
  domainName: string;
  originalTo: string;
  subject: string;
  logDays: number;
  attemptCount: number;
  nextRetryAt: string;
  createdAt: string;
  lastError?: string;
  s3Bucket?: string;
  s3Key?: string;
}

const RETRY_DELAYS = [5 * 60_000, 30 * 60_000, 2 * 60 * 60_000];
const MAX_ATTEMPTS = 3;
const QUEUE_TTL = 48 * 60 * 60 * 1000;

export { RETRY_DELAYS, MAX_ATTEMPTS };

function rowToForwardQueue(r: any): ForwardQueueItem {
  return {
    id: r.id,
    rawContent: r.raw_content,
    from: r.from,
    to: r.to,
    domainId: r.domain_id,
    domainName: r.domain_name,
    originalTo: r.original_to,
    subject: r.subject,
    logDays: r.log_days,
    attemptCount: r.attempt_count,
    nextRetryAt: r.next_retry_at instanceof Date ? r.next_retry_at.toISOString() : r.next_retry_at,
    createdAt: r.created_at instanceof Date ? r.created_at.toISOString() : r.created_at,
    lastError: r.last_error ?? undefined,
    s3Bucket: r.s3_bucket ?? undefined,
    s3Key: r.s3_key ?? undefined,
  };
}

export async function enqueueForward(item: Omit<ForwardQueueItem, "id" | "createdAt" | "attemptCount" | "nextRetryAt">, error?: string): Promise<ForwardQueueItem> {
  const nextRetry = new Date(Date.now() + RETRY_DELAYS[0]);
  const expiresAt = new Date(Date.now() + QUEUE_TTL);
  const rows = await sql`
    INSERT INTO forward_queue (raw_content, "from", "to", domain_id, domain_name, original_to, subject, log_days, attempt_count, next_retry_at, last_error, s3_bucket, s3_key, expires_at)
    VALUES (${item.rawContent}, ${item.from}, ${item.to}, ${item.domainId}, ${item.domainName}, ${item.originalTo}, ${item.subject}, ${item.logDays}, 0, ${nextRetry}, ${error ?? null}, ${item.s3Bucket ?? null}, ${item.s3Key ?? null}, ${expiresAt})
    RETURNING *`;
  return rowToForwardQueue(rows[0]);
}

export async function getForwardQueueItem(id: string): Promise<ForwardQueueItem | null> {
  const rows = await sql`SELECT * FROM forward_queue WHERE id = ${id} AND NOT dead`;
  return rows.length ? rowToForwardQueue(rows[0]) : null;
}

export async function updateForwardQueueItem(item: ForwardQueueItem): Promise<void> {
  const expiresAt = new Date(Date.now() + QUEUE_TTL);
  await sql`
    UPDATE forward_queue SET
      attempt_count = ${item.attemptCount},
      next_retry_at = ${item.nextRetryAt},
      last_error = ${item.lastError ?? null}
    WHERE id = ${item.id} AND NOT dead`;
}

export async function dequeueForward(id: string): Promise<void> {
  await sql`DELETE FROM forward_queue WHERE id = ${id}`;
}

export async function listForwardQueue(): Promise<ForwardQueueItem[]> {
  const rows = await sql`SELECT * FROM forward_queue WHERE NOT dead AND expires_at > NOW()`;
  return rows.map(rowToForwardQueue);
}

export async function moveToDeadLetter(item: ForwardQueueItem): Promise<void> {
  await sql`UPDATE forward_queue SET dead = TRUE, expires_at = NOW() + INTERVAL '30 days' WHERE id = ${item.id}`;
}

export async function getQueueDepth(): Promise<number> {
  const rows = await sql`SELECT COUNT(*)::int AS c FROM forward_queue WHERE NOT dead AND expires_at > NOW()`;
  return rows[0].c;
}

export async function getDeadLetterCount(): Promise<number> {
  const rows = await sql`SELECT COUNT(*)::int AS c FROM forward_queue WHERE dead`;
  return rows[0].c;
}

// --- Mesa: Conversations ---

export interface Conversation {
  id: string;
  domainId: string;
  from: string;
  to: string;
  subject: string;
  status: "open" | "snoozed" | "closed";
  assignedTo?: string;
  priority: "normal" | "urgent";
  lastMessageAt: string;
  messageCount: number;
  tags: string[];
  threadReferences: string[];
}

export interface Message {
  id: string;
  conversationId: string;
  from: string;
  body?: string;
  html?: string;
  s3Bucket?: string;
  s3Key?: string;
  direction: "inbound" | "outbound";
  createdAt: string;
  messageId?: string;
}

export interface Note {
  id: string;
  conversationId: string;
  author: string;
  body: string;
  createdAt: string;
}

export interface Agent {
  id: string;
  domainId: string;
  email: string;
  name: string;
  role: "admin" | "agent";
  createdAt: string;
}

export interface BulkJob {
  id: string;
  domainId: string;
  recipients: string[];
  subject: string;
  html: string;
  from: string;
  status: "queued" | "processing" | "completed" | "failed";
  totalRecipients: number;
  sent: number;
  failed: number;
  skippedSuppressed: number;
  createdAt: string;
  completedAt?: string;
  lastError?: string;
}

function rowToConversation(r: any): Conversation {
  return {
    id: r.id,
    domainId: r.domain_id,
    from: r.from,
    to: r.to,
    subject: r.subject,
    status: r.status,
    assignedTo: r.assigned_to ?? undefined,
    priority: r.priority,
    lastMessageAt: r.last_message_at instanceof Date ? r.last_message_at.toISOString() : r.last_message_at,
    messageCount: r.message_count,
    tags: r.tags ?? [],
    threadReferences: r.thread_refs ?? [],
  };
}

function rowToMessage(r: any): Message {
  return {
    id: r.id,
    conversationId: r.conversation_id,
    from: r.from,
    body: r.body ?? undefined,
    html: r.html ?? undefined,
    s3Bucket: r.s3_bucket ?? undefined,
    s3Key: r.s3_key ?? undefined,
    direction: r.direction,
    createdAt: r.created_at instanceof Date ? r.created_at.toISOString() : r.created_at,
    messageId: r.message_id ?? undefined,
  };
}

function rowToNote(r: any): Note {
  return {
    id: r.id,
    conversationId: r.conversation_id,
    author: r.author,
    body: r.body,
    createdAt: r.created_at instanceof Date ? r.created_at.toISOString() : r.created_at,
  };
}

function rowToAgent(r: any): Agent {
  return {
    id: r.id,
    domainId: r.domain_id,
    email: r.email,
    name: r.name,
    role: r.role,
    createdAt: r.created_at instanceof Date ? r.created_at.toISOString() : r.created_at,
  };
}

function rowToBulkJob(r: any): BulkJob {
  return {
    id: r.id,
    domainId: r.domain_id,
    recipients: r.recipients ?? [],
    subject: r.subject,
    html: r.html,
    from: r.from,
    status: r.status,
    totalRecipients: r.total_recipients,
    sent: r.sent,
    failed: r.failed,
    skippedSuppressed: r.skipped_suppressed,
    createdAt: r.created_at instanceof Date ? r.created_at.toISOString() : r.created_at,
    completedAt: r.completed_at ? (r.completed_at instanceof Date ? r.completed_at.toISOString() : r.completed_at) : undefined,
    lastError: r.last_error ?? undefined,
  };
}

// --- Mesa CRUD ---

export async function createConversation(conv: Omit<Conversation, "id">): Promise<Conversation> {
  const rows = await sql`
    INSERT INTO conversations (domain_id, "from", "to", subject, status, assigned_to, priority, last_message_at, message_count, tags, thread_refs)
    VALUES (${conv.domainId}, ${conv.from}, ${conv.to}, ${conv.subject}, ${conv.status}, ${conv.assignedTo ?? null}, ${conv.priority}, ${conv.lastMessageAt}, ${conv.messageCount}, ${conv.tags}, ${conv.threadReferences})
    RETURNING *`;
  return rowToConversation(rows[0]);
}

export async function getConversation(domainId: string, id: string): Promise<Conversation | null> {
  const rows = await sql`SELECT * FROM conversations WHERE domain_id = ${domainId} AND id = ${id}`;
  return rows.length ? rowToConversation(rows[0]) : null;
}

export async function listConversations(domainId: string, opts?: { status?: string; assignedTo?: string }): Promise<Conversation[]> {
  if (opts?.status && opts?.assignedTo) {
    const rows = await sql`SELECT * FROM conversations WHERE domain_id = ${domainId} AND status = ${opts.status} AND assigned_to = ${opts.assignedTo} ORDER BY last_message_at DESC`;
    return rows.map(rowToConversation);
  }
  if (opts?.status) {
    const rows = await sql`SELECT * FROM conversations WHERE domain_id = ${domainId} AND status = ${opts.status} ORDER BY last_message_at DESC`;
    return rows.map(rowToConversation);
  }
  if (opts?.assignedTo) {
    const rows = await sql`SELECT * FROM conversations WHERE domain_id = ${domainId} AND assigned_to = ${opts.assignedTo} ORDER BY last_message_at DESC`;
    return rows.map(rowToConversation);
  }
  const rows = await sql`SELECT * FROM conversations WHERE domain_id = ${domainId} ORDER BY last_message_at DESC`;
  return rows.map(rowToConversation);
}

export async function updateConversation(domainId: string, id: string, updates: Partial<Pick<Conversation, "status" | "assignedTo" | "priority" | "tags" | "lastMessageAt" | "messageCount" | "threadReferences">>): Promise<Conversation | null> {
  const conv = await getConversation(domainId, id);
  if (!conv) return null;
  const merged = { ...conv, ...updates };
  const rows = await sql`
    UPDATE conversations SET
      status = ${merged.status},
      assigned_to = ${merged.assignedTo ?? null},
      priority = ${merged.priority},
      tags = ${merged.tags},
      thread_refs = ${merged.threadReferences},
      last_message_at = ${merged.lastMessageAt},
      message_count = ${merged.messageCount}
    WHERE domain_id = ${domainId} AND id = ${id}
    RETURNING *`;
  return rows.length ? rowToConversation(rows[0]) : null;
}

export async function findConversationByThread(domainId: string, _from: string, references: string[]): Promise<Conversation | null> {
  if (!references.length) return null;
  const rows = await sql`
    SELECT * FROM conversations
    WHERE domain_id = ${domainId} AND thread_refs && ${references}::text[]
    LIMIT 1`;
  return rows.length ? rowToConversation(rows[0]) : null;
}

// --- Messages ---

export async function addMessage(msg: Omit<Message, "id">): Promise<Message> {
  const rows = await sql`
    INSERT INTO messages (conversation_id, "from", body, html, s3_bucket, s3_key, direction, message_id)
    VALUES (${msg.conversationId}, ${msg.from}, ${msg.body ?? null}, ${msg.html ?? null}, ${msg.s3Bucket ?? null}, ${msg.s3Key ?? null}, ${msg.direction}, ${msg.messageId ?? null})
    RETURNING *`;
  return rowToMessage(rows[0]);
}

export async function listMessages(conversationId: string): Promise<Message[]> {
  const rows = await sql`SELECT * FROM messages WHERE conversation_id = ${conversationId} ORDER BY created_at`;
  return rows.map(rowToMessage);
}

// --- Notes ---

export async function addNote(note: Omit<Note, "id">): Promise<Note> {
  const rows = await sql`
    INSERT INTO notes (conversation_id, author, body)
    VALUES (${note.conversationId}, ${note.author}, ${note.body})
    RETURNING *`;
  return rowToNote(rows[0]);
}

export async function listNotes(conversationId: string): Promise<Note[]> {
  const rows = await sql`SELECT * FROM notes WHERE conversation_id = ${conversationId} ORDER BY created_at`;
  return rows.map(rowToNote);
}

// --- Agents ---

export async function createAgent(agent: Omit<Agent, "id" | "createdAt">): Promise<Agent> {
  const rows = await sql`
    INSERT INTO agents (domain_id, email, name, role)
    VALUES (${agent.domainId}, ${agent.email}, ${agent.name}, ${agent.role})
    RETURNING *`;
  return rowToAgent(rows[0]);
}

export async function getAgent(domainId: string, agentId: string): Promise<Agent | null> {
  const rows = await sql`SELECT * FROM agents WHERE domain_id = ${domainId} AND id = ${agentId}`;
  return rows.length ? rowToAgent(rows[0]) : null;
}

export async function getAgentByEmail(domainId: string, email: string): Promise<Agent | null> {
  const rows = await sql`SELECT * FROM agents WHERE domain_id = ${domainId} AND email = ${email}`;
  return rows.length ? rowToAgent(rows[0]) : null;
}

export async function listAgents(domainId: string): Promise<Agent[]> {
  const rows = await sql`SELECT * FROM agents WHERE domain_id = ${domainId}`;
  return rows.map(rowToAgent);
}

export async function deleteAgent(domainId: string, agentId: string): Promise<boolean> {
  const res = await sql`DELETE FROM agents WHERE domain_id = ${domainId} AND id = ${agentId}`;
  return res.count > 0;
}

export async function countAgents(domainId: string): Promise<number> {
  const rows = await sql`SELECT COUNT(*)::int AS c FROM agents WHERE domain_id = ${domainId}`;
  return rows[0].c;
}

// --- Suppression list ---

export async function addSuppression(domainId: string, email: string, reason: string): Promise<void> {
  await sql`
    INSERT INTO suppressions (domain_id, email, reason)
    VALUES (${domainId}, ${email}, ${reason})
    ON CONFLICT (domain_id, email) DO UPDATE SET reason = EXCLUDED.reason`;
}

export async function isSuppressed(domainId: string, email: string): Promise<boolean> {
  const rows = await sql`SELECT 1 FROM suppressions WHERE domain_id = ${domainId} AND email = ${email}`;
  return rows.length > 0;
}

export async function removeSuppression(domainId: string, email: string): Promise<void> {
  await sql`DELETE FROM suppressions WHERE domain_id = ${domainId} AND email = ${email}`;
}

// --- Send counter (monthly) ---

export async function incrementSendCount(domainId: string): Promise<number> {
  const month = new Date().toISOString().slice(0, 7);
  const expiresAt = new Date(Date.now() + 45 * 24 * 60 * 60 * 1000);
  const rows = await sql`
    INSERT INTO send_counts (domain_id, month, count, expires_at)
    VALUES (${domainId}, ${month}, 1, ${expiresAt})
    ON CONFLICT (domain_id, month) DO UPDATE SET count = send_counts.count + 1
    RETURNING count`;
  return rows[0].count;
}

export async function getSendCount(domainId: string): Promise<number> {
  const month = new Date().toISOString().slice(0, 7);
  const rows = await sql`SELECT count FROM send_counts WHERE domain_id = ${domainId} AND month = ${month}`;
  return rows.length ? rows[0].count : 0;
}

// --- Bulk jobs ---

export async function createBulkJob(job: Omit<BulkJob, "id" | "createdAt" | "sent" | "failed" | "skippedSuppressed" | "status">): Promise<BulkJob> {
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  const rows = await sql`
    INSERT INTO bulk_jobs (domain_id, recipients, subject, html, "from", total_recipients, expires_at)
    VALUES (${job.domainId}, ${job.recipients}, ${job.subject}, ${job.html}, ${job.from}, ${job.totalRecipients}, ${expiresAt})
    RETURNING *`;
  return rowToBulkJob(rows[0]);
}

export async function getBulkJob(domainId: string, jobId: string): Promise<BulkJob | null> {
  const rows = await sql`SELECT * FROM bulk_jobs WHERE domain_id = ${domainId} AND id = ${jobId}`;
  return rows.length ? rowToBulkJob(rows[0]) : null;
}

export async function updateBulkJob(job: BulkJob): Promise<void> {
  await sql`
    UPDATE bulk_jobs SET
      status = ${job.status},
      sent = ${job.sent},
      failed = ${job.failed},
      skipped_suppressed = ${job.skippedSuppressed},
      completed_at = ${job.completedAt ?? null},
      last_error = ${job.lastError ?? null}
    WHERE id = ${job.id}`;
}

export async function listPendingBulkJobs(): Promise<BulkJob[]> {
  const rows = await sql`
    SELECT * FROM bulk_jobs WHERE status IN ('queued', 'processing') ORDER BY created_at`;
  return rows.map(rowToBulkJob);
}

// --- Agent invite tokens ---

export async function createAgentInvite(domainId: string, email: string, name: string, role: "admin" | "agent"): Promise<string> {
  const token = crypto.randomUUID();
  await sql`
    INSERT INTO tokens (token, kind, value, expires_at)
    VALUES (${token}, 'agent-invite', ${JSON.stringify({ domainId, email, name, role })}, NOW() + INTERVAL '7 days')`;
  return token;
}

export async function getAgentInvite(token: string): Promise<{ domainId: string; email: string; name: string; role: "admin" | "agent" } | null> {
  const rows = await sql`
    SELECT value FROM tokens WHERE token = ${token} AND kind = 'agent-invite' AND expires_at > NOW()`;
  if (!rows.length) return null;
  return rows[0].value as any;
}

export async function deleteAgentInvite(token: string): Promise<void> {
  await sql`DELETE FROM tokens WHERE token = ${token} AND kind = 'agent-invite'`;
}

// --- Plan limits extension for Mesa/agents ---

export const PLAN_MESA_LIMITS = {
  basico:     { mesaActions: false, agents: 0 },
  freelancer: { mesaActions: true,  agents: 3 },
  developer:  { mesaActions: true,  agents: 10 },
  pro:        { mesaActions: true,  agents: 3 },
  agencia:    { mesaActions: true,  agents: 10 },
} as const;

// --- Admin: list all users ---

export async function listAllUsers(): Promise<Omit<User, "passwordHash">[]> {
  const rows = await sql`SELECT * FROM users ORDER BY created_at DESC`;
  return rows.map(r => {
    const u = rowToUser(r);
    const { passwordHash: _, ...safe } = u;
    return safe;
  });
}

export async function deleteUser(email: string): Promise<boolean> {
  // CASCADE from domains handles most cleanup
  const res = await sql`DELETE FROM users WHERE email = ${email}`;
  if (res.count === 0) return false;
  // Clean up tokens related to this user
  await sql`DELETE FROM tokens WHERE kind IN ('verify', 'password') AND value->>'email' = ${email}`;
  return true;
}

// --- Test helpers ---

export function _getSql() {
  return sql;
}

export function _setSql(newSql: typeof sql) {
  sql = newSql;
}
