import { db, sqlite } from "./pg.js";
import { eq, and, gt, lte, lt, sql as rawSql, inArray, isNull, isNotNull, desc, asc, count } from "drizzle-orm";
import {
  users,
  domains,
  alias,
  rules,
  emailLogs,
  tokens,
  forwardQueue,
  conversations,
  messages,
  notes,
  agents,
  suppressions,
  sendCounts,
  bulkJobs,
  coupons,
  smtpCredentials,
  referrals,
  referralCredits,
} from "./schema.js";

export { db };

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
  basico:     { price: 49_00,  yearlyPrice: 490_00,  domains: 1,  aliases: 5,   rules: 0,   logDays: 15, sends: 10,    api: false, webhooks: false, forwardPerHour: 100,  smtpRelay: false },
  freelancer: { price: 449_00, yearlyPrice: 4490_00, domains: 15, aliases: 50,  rules: 10,  logDays: 30, sends: 50,    api: false, webhooks: false, forwardPerHour: 500,  smtpRelay: false },
  developer:  { price: 999_00, yearlyPrice: 9990_00, domains: 20, aliases: 100, rules: 50,  logDays: 90, sends: 200,   api: true,  webhooks: true,  forwardPerHour: 2000, smtpRelay: true },
  pro:     { price: 299_00, yearlyPrice: 2990_00, domains: 15, aliases: 50,  rules: 10,  logDays: 30, sends: 500,   api: false, webhooks: false, forwardPerHour: 500,  smtpRelay: true },
  agencia: { price: 999_00, yearlyPrice: 9990_00, domains: 20, aliases: 100, rules: 50,  logDays: 90, sends: 2000,  api: true,  webhooks: true,  forwardPerHour: 2000, smtpRelay: true },
} as const;

// --- Row → interface mappers ---

function rowToUser(r: typeof users.$inferSelect): User {
  const user: User = {
    email: r.email,
    passwordHash: r.passwordHash,
    createdAt: r.createdAt,
    emailVerified: r.emailVerified ?? false,
    passwordChangedAt: r.passwordChangedAt ?? undefined,
  };
  if (r.subPlan) {
    user.subscription = {
      plan: r.subPlan as any,
      status: (r.subStatus ?? "none") as any,
      mpSubscriptionId: r.subMpId ?? undefined,
      currentPeriodEnd: r.subPeriodEnd ?? undefined,
    };
  }
  return user;
}

function rowToDomain(r: typeof domains.$inferSelect): Domain {
  return {
    id: r.id,
    ownerEmail: r.ownerEmail,
    domain: r.domain,
    verified: r.verified,
    mxConfigured: r.mxConfigured,
    dkimTokens: r.dkimTokens ?? [],
    verificationToken: r.verificationToken,
    createdAt: r.createdAt,
  };
}

function rowToAlias(r: typeof alias.$inferSelect): Alias {
  return {
    alias: r.alias,
    domainId: r.domainId,
    destinations: r.destinations ?? [],
    enabled: r.enabled,
    createdAt: r.createdAt,
    forwardCount: r.forwardCount || undefined,
    lastFrom: r.lastFrom ?? undefined,
    lastAt: r.lastAt ?? undefined,
  };
}

function rowToRule(r: typeof rules.$inferSelect): Rule {
  return {
    id: r.id,
    domainId: r.domainId,
    field: r.field as any,
    match: r.match as any,
    value: r.value,
    action: r.action as any,
    target: r.target,
    priority: r.priority,
    enabled: r.enabled,
    createdAt: r.createdAt,
  };
}

function rowToLog(r: typeof emailLogs.$inferSelect): EmailLog {
  return {
    id: r.id,
    domainId: r.domainId,
    timestamp: r.timestamp,
    from: r.from,
    to: r.to,
    subject: r.subject,
    status: r.status as any,
    forwardedTo: r.forwardedTo,
    sizeBytes: r.sizeBytes,
    error: r.error ?? undefined,
  };
}

function rowToConversation(r: typeof conversations.$inferSelect): Conversation {
  return {
    id: r.id,
    domainId: r.domainId,
    from: r.from,
    to: r.to,
    subject: r.subject,
    status: r.status as any,
    assignedTo: r.assignedTo ?? undefined,
    priority: r.priority as any,
    lastMessageAt: r.lastMessageAt,
    messageCount: r.messageCount ?? 0,
    tags: r.tags ?? [],
    threadReferences: r.threadRefs ?? [],
    deletedAt: r.deletedAt ?? undefined,
  };
}

function rowToMessage(r: typeof messages.$inferSelect): Message {
  return {
    id: r.id,
    conversationId: r.conversationId,
    from: r.from,
    body: r.body ?? undefined,
    html: r.html ?? undefined,
    s3Bucket: r.s3Bucket ?? undefined,
    s3Key: r.s3Key ?? undefined,
    direction: r.direction as any,
    createdAt: r.createdAt,
    messageId: r.messageId ?? undefined,
  };
}

function rowToNote(r: typeof notes.$inferSelect): Note {
  return {
    id: r.id,
    conversationId: r.conversationId,
    author: r.author,
    body: r.body,
    createdAt: r.createdAt,
  };
}

function rowToAgent(r: typeof agents.$inferSelect): Agent {
  return {
    id: r.id,
    domainId: r.domainId,
    email: r.email,
    name: r.name,
    role: r.role as any,
    createdAt: r.createdAt,
  };
}

function rowToBulkJob(r: typeof bulkJobs.$inferSelect): BulkJob {
  return {
    id: r.id,
    domainId: r.domainId,
    recipients: r.recipients ?? [],
    subject: r.subject,
    html: r.html,
    from: r.from,
    status: r.status as any,
    totalRecipients: r.totalRecipients,
    sent: r.sent,
    failed: r.failed,
    skippedSuppressed: r.skippedSuppressed,
    createdAt: r.createdAt,
    completedAt: r.completedAt ?? undefined,
    lastError: r.lastError ?? undefined,
  };
}

function rowToCoupon(r: typeof coupons.$inferSelect): Coupon {
  return {
    code: r.code,
    plan: r.plan,
    fixedPrice: r.fixedPrice,
    description: r.description,
    singleUse: r.singleUse,
    used: r.used,
    expiresAt: r.expiresAt ?? undefined,
    createdAt: r.createdAt,
  };
}

function rowToForwardQueue(r: typeof forwardQueue.$inferSelect): ForwardQueueItem {
  return {
    id: r.id,
    rawContent: r.rawContent,
    from: r.from,
    to: r.to,
    domainId: r.domainId,
    domainName: r.domainName,
    originalTo: r.originalTo,
    subject: r.subject,
    logDays: r.logDays,
    attemptCount: r.attemptCount,
    nextRetryAt: r.nextRetryAt,
    createdAt: r.createdAt,
    lastError: r.lastError ?? undefined,
    s3Bucket: r.s3Bucket ?? undefined,
    s3Key: r.s3Key ?? undefined,
  };
}

// --- Users ---

export function getUser(email: string): User | null {
  const rows = db.select().from(users).where(eq(users.email, email)).all();
  return rows.length ? rowToUser(rows[0]) : null;
}

export function createUser(email: string, passwordHash: string): User {
  const rows = db.insert(users).values({ email, passwordHash }).returning().all();
  return rowToUser(rows[0]);
}

export function getUserByVerifyToken(token: string): User | null {
  const now = new Date().toISOString();
  const rows = db.select().from(tokens)
    .where(and(eq(tokens.token, token), eq(tokens.kind, "verify"), gt(tokens.expiresAt, now)))
    .all();
  if (!rows.length) return null;
  const email = (rows[0].value as any)?.email;
  if (!email) return null;
  return getUser(email);
}

export function setVerifyToken(email: string, token: string): void {
  const user = getUser(email);
  if (!user) return;
  db.update(users).set({ emailVerified: false }).where(eq(users.email, email)).run();
  const expiresAt = new Date(Date.now() + 7 * 24 * 3600_000).toISOString();
  db.insert(tokens).values({ token, kind: "verify", value: { email }, expiresAt })
    .onConflictDoUpdate({ target: tokens.token, set: { value: { email }, expiresAt } })
    .run();
}

export function verifyUserEmail(email: string): void {
  db.update(users).set({ emailVerified: true }).where(eq(users.email, email)).run();
  // Clean up verify tokens for this user — use raw SQL for JSON field access
  sqlite.prepare(`DELETE FROM tokens WHERE kind = 'verify' AND json_extract(value, '$.email') = ?`).run(email);
}

// --- Domains ---

export function createDomain(ownerEmail: string, domain: string, dkimTokens: string[], verificationToken: string): Domain {
  const rows = db.insert(domains).values({ ownerEmail, domain, dkimTokens, verificationToken }).returning().all();
  return rowToDomain(rows[0]);
}

export function getDomain(id: string): Domain | null {
  const rows = db.select().from(domains).where(eq(domains.id, id)).all();
  return rows.length ? rowToDomain(rows[0]) : null;
}

export function getDomainByName(domain: string): Domain | null {
  const rows = db.select().from(domains).where(eq(domains.domain, domain)).all();
  return rows.length ? rowToDomain(rows[0]) : null;
}

export function listUserDomains(email: string): Domain[] {
  const rows = db.select().from(domains).where(eq(domains.ownerEmail, email)).orderBy(asc(domains.createdAt)).all();
  return rows.map(rowToDomain);
}

export function updateDomain(id: string, updates: Partial<Pick<Domain, "verified" | "mxConfigured">>): Domain | null {
  if (updates.verified === undefined && updates.mxConfigured === undefined) return getDomain(id);
  const set: Record<string, any> = {};
  if (updates.verified !== undefined) set.verified = updates.verified;
  if (updates.mxConfigured !== undefined) set.mxConfigured = updates.mxConfigured;
  const rows = db.update(domains).set(set).where(eq(domains.id, id)).returning().all();
  return rows.length ? rowToDomain(rows[0]) : null;
}

export function deleteDomain(id: string): boolean {
  const result = db.delete(domains).where(eq(domains.id, id)).run();
  return result.changes > 0;
}

export function countUserDomains(email: string): number {
  const rows = db.select({ c: count() }).from(domains).where(eq(domains.ownerEmail, email)).all();
  return rows[0].c;
}

// --- Aliases ---

export function createAlias(domainId: string, aliasName: string, destinations: string[]): Alias {
  const rows = db.insert(alias).values({ domainId, alias: aliasName, destinations }).returning().all();
  return rowToAlias(rows[0]);
}

export function getAlias(domainId: string, aliasName: string): Alias | null {
  const rows = db.select().from(alias).where(and(eq(alias.domainId, domainId), eq(alias.alias, aliasName))).all();
  return rows.length ? rowToAlias(rows[0]) : null;
}

export function listAliases(domainId: string): Alias[] {
  const rows = db.select().from(alias).where(eq(alias.domainId, domainId)).orderBy(asc(alias.createdAt)).all();
  return rows.map(rowToAlias);
}

export function updateAlias(domainId: string, aliasName: string, updates: Partial<Pick<Alias, "destinations" | "enabled">>): Alias | null {
  const set: Record<string, any> = {};
  if (updates.destinations !== undefined) set.destinations = updates.destinations;
  if (updates.enabled !== undefined) set.enabled = updates.enabled;
  if (!Object.keys(set).length) return getAlias(domainId, aliasName);
  const rows = db.update(alias).set(set)
    .where(and(eq(alias.domainId, domainId), eq(alias.alias, aliasName)))
    .returning().all();
  return rows.length ? rowToAlias(rows[0]) : null;
}

export function bumpAliasStats(domainId: string, aliasName: string, from: string): void {
  db.update(alias).set({
    forwardCount: rawSql`${alias.forwardCount} + 1`,
    lastFrom: from,
    lastAt: new Date().toISOString(),
  }).where(and(eq(alias.domainId, domainId), eq(alias.alias, aliasName))).run();
}

export function deleteAlias(domainId: string, aliasName: string): boolean {
  const result = db.delete(alias).where(and(eq(alias.domainId, domainId), eq(alias.alias, aliasName))).run();
  return result.changes > 0;
}

export function countAliases(domainId: string): number {
  const rows = db.select({ c: count() }).from(alias).where(eq(alias.domainId, domainId)).all();
  return rows[0].c;
}

// --- Rules ---

export function createRule(domainId: string, rule: Omit<Rule, "id" | "domainId" | "createdAt">): Rule {
  const rows = db.insert(rules).values({
    domainId,
    field: rule.field,
    match: rule.match,
    value: rule.value,
    action: rule.action,
    target: rule.target,
    priority: rule.priority,
    enabled: rule.enabled,
  }).returning().all();
  return rowToRule(rows[0]);
}

export function listRules(domainId: string): Rule[] {
  const rows = db.select().from(rules).where(eq(rules.domainId, domainId)).orderBy(asc(rules.priority)).all();
  return rows.map(rowToRule);
}

export function updateRule(domainId: string, ruleId: string, updates: Partial<Pick<Rule, "field" | "match" | "value" | "action" | "target" | "priority" | "enabled">>): Rule | null {
  const set: Record<string, any> = {};
  if (updates.field !== undefined) set.field = updates.field;
  if (updates.match !== undefined) set.match = updates.match;
  if (updates.value !== undefined) set.value = updates.value;
  if (updates.action !== undefined) set.action = updates.action;
  if (updates.target !== undefined) set.target = updates.target;
  if (updates.priority !== undefined) set.priority = updates.priority;
  if (updates.enabled !== undefined) set.enabled = updates.enabled;
  if (!Object.keys(set).length) {
    const rows = db.select().from(rules).where(and(eq(rules.domainId, domainId), eq(rules.id, ruleId))).all();
    return rows.length ? rowToRule(rows[0]) : null;
  }
  const rows = db.update(rules).set(set)
    .where(and(eq(rules.domainId, domainId), eq(rules.id, ruleId)))
    .returning().all();
  return rows.length ? rowToRule(rows[0]) : null;
}

export function countRules(domainId: string): number {
  const rows = db.select({ c: count() }).from(rules).where(eq(rules.domainId, domainId)).all();
  return rows[0].c;
}

export function deleteRule(domainId: string, ruleId: string): boolean {
  const result = db.delete(rules).where(and(eq(rules.domainId, domainId), eq(rules.id, ruleId))).run();
  return result.changes > 0;
}

// --- Logs ---

export function addLog(log: Omit<EmailLog, "id">, logDays = 30): EmailLog {
  const expiresAt = new Date(Date.now() + logDays * 24 * 3600_000).toISOString();
  const rows = db.insert(emailLogs).values({
    domainId: log.domainId,
    timestamp: log.timestamp,
    from: log.from,
    to: log.to,
    subject: log.subject,
    status: log.status,
    forwardedTo: log.forwardedTo,
    sizeBytes: log.sizeBytes,
    error: log.error ?? null,
    expiresAt,
  }).returning().all();
  return rowToLog(rows[0]);
}

export function listLogs(domainId: string, limit = 50): EmailLog[] {
  const now = new Date().toISOString();
  const rows = db.select().from(emailLogs)
    .where(and(eq(emailLogs.domainId, domainId), gt(emailLogs.expiresAt, now)))
    .orderBy(desc(emailLogs.timestamp))
    .limit(limit)
    .all();
  return rows.map(rowToLog);
}

export function getMonthlyForwardCounts(domainIds: string[]): Map<string, number> {
  if (domainIds.length === 0) return new Map();
  const firstOfMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString();
  const rows = db.select({ domainId: emailLogs.domainId, c: count() })
    .from(emailLogs)
    .where(and(inArray(emailLogs.domainId, domainIds), gt(emailLogs.timestamp, firstOfMonth)))
    .groupBy(emailLogs.domainId)
    .all();
  const map = new Map<string, number>();
  for (const r of rows) map.set(r.domainId, r.c);
  return map;
}

// --- Subscription helpers ---

export function getUserBySubscriptionId(mpSubId: string): User | null {
  const rows = db.select().from(users).where(eq(users.subMpId, mpSubId)).all();
  return rows.length ? rowToUser(rows[0]) : null;
}

export function extendSubscriptionPeriod(email: string, days: number): void {
  const user = getUser(email);
  if (!user?.subscription) return;
  const existing = user.subscription.currentPeriodEnd
    ? new Date(user.subscription.currentPeriodEnd)
    : new Date();
  const base = existing > new Date() ? existing : new Date();
  base.setDate(base.getDate() + days);
  updateUserSubscription(email, {
    ...user.subscription,
    status: "active",
    currentPeriodEnd: base.toISOString(),
  });
}

export function updateUserSubscription(email: string, sub: Subscription): User | null {
  const rows = db.update(users).set({
    subPlan: sub.plan,
    subStatus: sub.status,
    subMpId: sub.mpSubscriptionId ?? null,
    subPeriodEnd: sub.currentPeriodEnd ?? null,
  }).where(eq(users.email, email)).returning().all();
  return rows.length ? rowToUser(rows[0]) : null;
}

export function getUserPlanLimits(user: User): { domains: number; aliases: number; rules: number; logDays: number; sends: number; api: boolean; webhooks: boolean; forwardPerHour: number; smtpRelay: boolean } {
  const sub = user.subscription;
  if (sub && (sub.status === "active" || sub.status === "cancelled")) {
    if (sub.currentPeriodEnd && new Date(sub.currentPeriodEnd) < new Date()) {
      return { domains: 0, aliases: 0, rules: 0, logDays: 0, sends: 0, api: false, webhooks: false, forwardPerHour: 0, smtpRelay: false };
    }
    const plan = PLANS[sub.plan];
    return { domains: plan.domains, aliases: plan.aliases, rules: plan.rules, logDays: plan.logDays, sends: plan.sends, api: plan.api, webhooks: plan.webhooks, forwardPerHour: plan.forwardPerHour, smtpRelay: plan.smtpRelay };
  }
  return { domains: 0, aliases: 0, rules: 0, logDays: 0, sends: 0, api: false, webhooks: false, forwardPerHour: 0, smtpRelay: false };
}

// --- Pending checkout (guest flow) ---

export function createPendingCheckout(token: string, plan: string): void {
  const expiresAt = new Date(Date.now() + 24 * 3600_000).toISOString();
  db.insert(tokens).values({ token, kind: "pending-checkout", value: { plan }, expiresAt })
    .onConflictDoUpdate({ target: tokens.token, set: { value: { plan }, expiresAt } })
    .run();
}

export function getPendingCheckout(token: string): string | null {
  const now = new Date().toISOString();
  const rows = db.select().from(tokens)
    .where(and(eq(tokens.token, token), eq(tokens.kind, "pending-checkout"), gt(tokens.expiresAt, now)))
    .all();
  if (!rows.length) return null;
  return (rows[0].value as any)?.plan ?? null;
}

export function deletePendingCheckout(token: string): void {
  db.delete(tokens).where(and(eq(tokens.token, token), eq(tokens.kind, "pending-checkout"))).run();
}

// --- Password token (set-password flow) ---

export function setPasswordToken(email: string, token: string): void {
  const expiresAt = new Date(Date.now() + 7 * 24 * 3600_000).toISOString();
  db.insert(tokens).values({ token, kind: "password", value: { email }, expiresAt })
    .onConflictDoUpdate({ target: tokens.token, set: { value: { email }, expiresAt } })
    .run();
}

export function getEmailByPasswordToken(token: string): string | null {
  const now = new Date().toISOString();
  const rows = db.select().from(tokens)
    .where(and(eq(tokens.token, token), eq(tokens.kind, "password"), gt(tokens.expiresAt, now)))
    .all();
  if (!rows.length) return null;
  return (rows[0].value as any)?.email ?? null;
}

export function deletePasswordToken(token: string): void {
  db.delete(tokens).where(and(eq(tokens.token, token), eq(tokens.kind, "password"))).run();
}

// --- Update user password ---

export function updateUserPassword(email: string, passwordHash: string): void {
  db.update(users).set({ passwordHash, passwordChangedAt: new Date().toISOString() }).where(eq(users.email, email)).run();
}

// --- Webhook idempotency ---

export function isWebhookProcessed(id: string): boolean {
  const now = new Date().toISOString();
  const rows = db.select().from(tokens)
    .where(and(eq(tokens.token, id), eq(tokens.kind, "webhook"), gt(tokens.expiresAt, now)))
    .all();
  return rows.length > 0;
}

export function markWebhookProcessed(id: string): void {
  const expiresAt = new Date(Date.now() + 7 * 24 * 3600_000).toISOString();
  db.insert(tokens).values({ token: id, kind: "webhook", value: {}, expiresAt })
    .onConflictDoNothing()
    .run();
}

// --- Atomic user creation (guest checkout) ---

export function createUserIfNotExists(email: string, passwordHash: string): boolean {
  const rows = db.insert(users).values({ email, passwordHash })
    .onConflictDoNothing()
    .returning()
    .all();
  return rows.length > 0;
}

// --- SNS message dedup ---

export function isMessageProcessed(messageId: string): boolean {
  const now = new Date().toISOString();
  const rows = db.select().from(tokens)
    .where(and(eq(tokens.token, messageId), eq(tokens.kind, "sns"), gt(tokens.expiresAt, now)))
    .all();
  return rows.length > 0;
}

export function markMessageProcessed(messageId: string): void {
  const expiresAt = new Date(Date.now() + 24 * 3600_000).toISOString();
  db.insert(tokens).values({ token: messageId, kind: "sns", value: {}, expiresAt })
    .onConflictDoNothing()
    .run();
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

export function enqueueForward(item: Omit<ForwardQueueItem, "id" | "createdAt" | "attemptCount" | "nextRetryAt">, error?: string): ForwardQueueItem {
  const nextRetryAt = new Date(Date.now() + RETRY_DELAYS[0]).toISOString();
  const expiresAt = new Date(Date.now() + QUEUE_TTL).toISOString();
  const rows = db.insert(forwardQueue).values({
    rawContent: item.rawContent,
    from: item.from,
    to: item.to,
    domainId: item.domainId,
    domainName: item.domainName,
    originalTo: item.originalTo,
    subject: item.subject,
    logDays: item.logDays,
    attemptCount: 0,
    nextRetryAt,
    lastError: error ?? null,
    s3Bucket: item.s3Bucket ?? null,
    s3Key: item.s3Key ?? null,
    expiresAt,
  }).returning().all();
  return rowToForwardQueue(rows[0]);
}

export function getForwardQueueItem(id: string): ForwardQueueItem | null {
  const rows = db.select().from(forwardQueue)
    .where(and(eq(forwardQueue.id, id), eq(forwardQueue.dead, false)))
    .all();
  return rows.length ? rowToForwardQueue(rows[0]) : null;
}

export function updateForwardQueueItem(item: ForwardQueueItem): void {
  db.update(forwardQueue).set({
    attemptCount: item.attemptCount,
    nextRetryAt: item.nextRetryAt,
    lastError: item.lastError ?? null,
  }).where(and(eq(forwardQueue.id, item.id), eq(forwardQueue.dead, false))).run();
}

export function dequeueForward(id: string): void {
  db.delete(forwardQueue).where(eq(forwardQueue.id, id)).run();
}

export function listForwardQueue(): ForwardQueueItem[] {
  const now = new Date().toISOString();
  const rows = db.select().from(forwardQueue)
    .where(and(eq(forwardQueue.dead, false), gt(forwardQueue.expiresAt, now)))
    .all();
  return rows.map(rowToForwardQueue);
}

export function moveToDeadLetter(item: ForwardQueueItem): void {
  const expiresAt = new Date(Date.now() + 30 * 24 * 3600_000).toISOString();
  db.update(forwardQueue).set({ dead: true, expiresAt }).where(eq(forwardQueue.id, item.id)).run();
}

export function getQueueDepth(): number {
  const now = new Date().toISOString();
  const rows = db.select({ c: count() }).from(forwardQueue)
    .where(and(eq(forwardQueue.dead, false), gt(forwardQueue.expiresAt, now)))
    .all();
  return rows[0].c;
}

export function getDeadLetterCount(): number {
  const rows = db.select({ c: count() }).from(forwardQueue)
    .where(eq(forwardQueue.dead, true))
    .all();
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
  deletedAt?: string;
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

// --- Mesa CRUD ---

export function createConversation(conv: Omit<Conversation, "id">): Conversation {
  const rows = db.insert(conversations).values({
    domainId: conv.domainId,
    from: conv.from,
    to: conv.to,
    subject: conv.subject,
    status: conv.status,
    assignedTo: conv.assignedTo ?? null,
    priority: conv.priority,
    lastMessageAt: conv.lastMessageAt,
    messageCount: conv.messageCount ?? 1,
    tags: conv.tags,
    threadRefs: conv.threadReferences,
  }).returning().all();
  return rowToConversation(rows[0]);
}

export function getConversation(domainId: string, id: string): Conversation | null {
  const rows = db.select().from(conversations)
    .where(and(eq(conversations.domainId, domainId), eq(conversations.id, id)))
    .all();
  return rows.length ? rowToConversation(rows[0]) : null;
}

export function listConversations(domainId: string, opts?: { status?: string; assignedTo?: string }): Conversation[] {
  // status=deleted → show soft-deleted conversations
  if (opts?.status === "deleted") {
    const conditions = [eq(conversations.domainId, domainId), isNotNull(conversations.deletedAt)];
    if (opts?.assignedTo) conditions.push(eq(conversations.assignedTo, opts.assignedTo));
    const rows = db.select().from(conversations)
      .where(and(...conditions))
      .orderBy(desc(conversations.lastMessageAt))
      .all();
    return rows.map(rowToConversation);
  }
  // Default: exclude deleted
  const conditions = [eq(conversations.domainId, domainId), isNull(conversations.deletedAt)];
  if (opts?.status) conditions.push(eq(conversations.status, opts.status));
  if (opts?.assignedTo) conditions.push(eq(conversations.assignedTo, opts.assignedTo));
  const rows = db.select().from(conversations)
    .where(and(...conditions))
    .orderBy(desc(conversations.lastMessageAt))
    .all();
  return rows.map(rowToConversation);
}

export function updateConversation(domainId: string, id: string, updates: Partial<Pick<Conversation, "status" | "assignedTo" | "priority" | "tags" | "lastMessageAt" | "messageCount" | "threadReferences">>): Conversation | null {
  const conv = getConversation(domainId, id);
  if (!conv) return null;
  const merged = { ...conv, ...updates };
  const rows = db.update(conversations).set({
    status: merged.status,
    assignedTo: merged.assignedTo ?? null,
    priority: merged.priority,
    tags: merged.tags,
    threadRefs: merged.threadReferences,
    lastMessageAt: merged.lastMessageAt,
    messageCount: merged.messageCount ?? 1,
  }).where(and(eq(conversations.domainId, domainId), eq(conversations.id, id))).returning().all();
  return rows.length ? rowToConversation(rows[0]) : null;
}

export function findConversationByThread(domainId: string, _from: string, references: string[]): Conversation | null {
  if (!references.length) return null;
  const placeholders = references.map(() => "?").join(",");
  const row = sqlite.prepare(`
    SELECT * FROM conversations
    WHERE domain_id = ? AND deleted_at IS NULL AND EXISTS (
      SELECT 1 FROM json_each(thread_refs) WHERE value IN (${placeholders})
    )
    LIMIT 1
  `).get(domainId, ...references) as any;
  if (!row) return null;
  // Raw SQL returns snake_case — map to camelCase for rowToConversation
  return rowToConversation({
    ...row,
    domainId: row.domain_id,
    assignedTo: row.assigned_to,
    lastMessageAt: row.last_message_at,
    messageCount: row.message_count,
    threadRefs: row.thread_refs,
    deletedAt: row.deleted_at,
  });
}

export function softDeleteConversation(domainId: string, id: string): boolean {
  const result = db.update(conversations).set({ deletedAt: new Date().toISOString() })
    .where(and(eq(conversations.domainId, domainId), eq(conversations.id, id), isNull(conversations.deletedAt)))
    .run();
  return result.changes > 0;
}

export function restoreConversation(domainId: string, id: string): boolean {
  const result = db.update(conversations).set({ deletedAt: null })
    .where(and(eq(conversations.domainId, domainId), eq(conversations.id, id), isNotNull(conversations.deletedAt)))
    .run();
  return result.changes > 0;
}

export function purgeDeletedConversations(days: number): { s3Bucket: string; s3Key: string }[] {
  const cutoff = new Date(Date.now() - days * 24 * 3600_000).toISOString();
  // Collect S3 keys from messages belonging to conversations that will be purged
  const s3Rows = sqlite.prepare(`
    SELECT m.s3_bucket, m.s3_key FROM messages m
    JOIN conversations c ON m.conversation_id = c.id
    WHERE c.deleted_at IS NOT NULL AND c.deleted_at < ?
      AND m.s3_bucket IS NOT NULL AND m.s3_key IS NOT NULL
  `).all(cutoff) as any[];
  const s3Keys = s3Rows.map((r: any) => ({ s3Bucket: r.s3_bucket, s3Key: r.s3_key }));

  // Delete conversations (CASCADE handles messages + notes)
  db.delete(conversations)
    .where(and(isNotNull(conversations.deletedAt), lt(conversations.deletedAt, cutoff)))
    .run();

  return s3Keys;
}

// --- Messages ---

export function addMessage(msg: Omit<Message, "id">): Message {
  const rows = db.insert(messages).values({
    conversationId: msg.conversationId,
    from: msg.from,
    body: msg.body ?? null,
    html: msg.html ?? null,
    s3Bucket: msg.s3Bucket ?? null,
    s3Key: msg.s3Key ?? null,
    direction: msg.direction,
    messageId: msg.messageId ?? null,
  }).returning().all();
  return rowToMessage(rows[0]);
}

export function listMessages(conversationId: string): Message[] {
  const rows = db.select().from(messages)
    .where(eq(messages.conversationId, conversationId))
    .orderBy(asc(messages.createdAt))
    .all();
  return rows.map(rowToMessage);
}

// --- Notes ---

export function addNote(note: Omit<Note, "id">): Note {
  const rows = db.insert(notes).values({
    conversationId: note.conversationId,
    author: note.author,
    body: note.body,
  }).returning().all();
  return rowToNote(rows[0]);
}

export function listNotes(conversationId: string): Note[] {
  const rows = db.select().from(notes)
    .where(eq(notes.conversationId, conversationId))
    .orderBy(asc(notes.createdAt))
    .all();
  return rows.map(rowToNote);
}

// --- Agents ---

export function createAgent(agent: Omit<Agent, "id" | "createdAt">): Agent {
  const rows = db.insert(agents).values({
    domainId: agent.domainId,
    email: agent.email,
    name: agent.name,
    role: agent.role,
  }).returning().all();
  return rowToAgent(rows[0]);
}

export function getAgent(domainId: string, agentId: string): Agent | null {
  const rows = db.select().from(agents)
    .where(and(eq(agents.domainId, domainId), eq(agents.id, agentId)))
    .all();
  return rows.length ? rowToAgent(rows[0]) : null;
}

export function getAgentByEmail(domainId: string, email: string): Agent | null {
  const rows = db.select().from(agents)
    .where(and(eq(agents.domainId, domainId), eq(agents.email, email)))
    .all();
  return rows.length ? rowToAgent(rows[0]) : null;
}

export function listAgents(domainId: string): Agent[] {
  const rows = db.select().from(agents).where(eq(agents.domainId, domainId)).all();
  return rows.map(rowToAgent);
}

export function deleteAgent(domainId: string, agentId: string): boolean {
  const result = db.delete(agents)
    .where(and(eq(agents.domainId, domainId), eq(agents.id, agentId)))
    .run();
  return result.changes > 0;
}

export function countAgents(domainId: string): number {
  const rows = db.select({ c: count() }).from(agents).where(eq(agents.domainId, domainId)).all();
  return rows[0].c;
}

// --- Suppression list ---

export function addSuppression(domainId: string, email: string, reason: string): void {
  db.insert(suppressions).values({ domainId, email, reason })
    .onConflictDoUpdate({ target: [suppressions.domainId, suppressions.email], set: { reason } })
    .run();
}

export function isSuppressed(domainId: string, email: string): boolean {
  const rows = db.select().from(suppressions)
    .where(and(eq(suppressions.domainId, domainId), eq(suppressions.email, email)))
    .all();
  return rows.length > 0;
}

export function removeSuppression(domainId: string, email: string): void {
  db.delete(suppressions)
    .where(and(eq(suppressions.domainId, domainId), eq(suppressions.email, email)))
    .run();
}

// --- Send counter (monthly) ---

export function incrementSendCount(domainId: string): number {
  const month = new Date().toISOString().slice(0, 10); // daily key (YYYY-MM-DD)
  const expiresAt = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString();
  const rows = db.insert(sendCounts).values({ domainId, month, count: 1, expiresAt })
    .onConflictDoUpdate({
      target: [sendCounts.domainId, sendCounts.month],
      set: { count: rawSql`${sendCounts.count} + 1` },
    })
    .returning()
    .all();
  return rows[0].count;
}

export function getSendCount(domainId: string): number {
  const month = new Date().toISOString().slice(0, 10); // daily key (YYYY-MM-DD)
  const rows = db.select().from(sendCounts)
    .where(and(eq(sendCounts.domainId, domainId), eq(sendCounts.month, month)))
    .all();
  return rows.length ? rows[0].count : 0;
}

// --- Bulk jobs ---

export function createBulkJob(job: Omit<BulkJob, "id" | "createdAt" | "sent" | "failed" | "skippedSuppressed" | "status">): BulkJob {
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  const rows = db.insert(bulkJobs).values({
    domainId: job.domainId,
    recipients: job.recipients,
    subject: job.subject,
    html: job.html,
    from: job.from,
    totalRecipients: job.totalRecipients,
    expiresAt,
  }).returning().all();
  return rowToBulkJob(rows[0]);
}

export function getBulkJob(domainId: string, jobId: string): BulkJob | null {
  const rows = db.select().from(bulkJobs)
    .where(and(eq(bulkJobs.domainId, domainId), eq(bulkJobs.id, jobId)))
    .all();
  return rows.length ? rowToBulkJob(rows[0]) : null;
}

export function updateBulkJob(job: BulkJob): void {
  db.update(bulkJobs).set({
    status: job.status,
    sent: job.sent,
    failed: job.failed,
    skippedSuppressed: job.skippedSuppressed,
    completedAt: job.completedAt ?? null,
    lastError: job.lastError ?? null,
  }).where(eq(bulkJobs.id, job.id)).run();
}

export function listPendingBulkJobs(): BulkJob[] {
  const rows = db.select().from(bulkJobs)
    .where(inArray(bulkJobs.status, ["queued", "processing"]))
    .orderBy(asc(bulkJobs.createdAt))
    .all();
  return rows.map(rowToBulkJob);
}

// --- Agent invite tokens ---

export function createAgentInvite(domainId: string, email: string, name: string, role: "admin" | "agent"): string {
  const token = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + 7 * 24 * 3600_000).toISOString();
  db.insert(tokens).values({ token, kind: "agent-invite", value: { domainId, email, name, role }, expiresAt }).run();
  return token;
}

export function getAgentInvite(token: string): { domainId: string; email: string; name: string; role: "admin" | "agent" } | null {
  const now = new Date().toISOString();
  const rows = db.select().from(tokens)
    .where(and(eq(tokens.token, token), eq(tokens.kind, "agent-invite"), gt(tokens.expiresAt, now)))
    .all();
  if (!rows.length) return null;
  return rows[0].value as any;
}

export function deleteAgentInvite(token: string): void {
  db.delete(tokens).where(and(eq(tokens.token, token), eq(tokens.kind, "agent-invite"))).run();
}

// --- Plan limits extension for Mesa/agents ---

export const PLAN_MESA_LIMITS = {
  basico:     { mesaActions: true,  agents: 0 },
  freelancer: { mesaActions: true,  agents: 3 },
  developer:  { mesaActions: true,  agents: 10 },
  pro:        { mesaActions: true,  agents: 3 },
  agencia:    { mesaActions: true,  agents: 10 },
} as const;

// --- Admin: list all users ---

export function listAllUsers(): Omit<User, "passwordHash">[] {
  const rows = db.select().from(users).orderBy(desc(users.createdAt)).all();
  return rows.map(r => {
    const u = rowToUser(r);
    const { passwordHash: _, ...safe } = u;
    return safe;
  });
}

export function deleteUser(email: string): boolean {
  // CASCADE from domains handles most cleanup
  const result = db.delete(users).where(eq(users.email, email)).run();
  if (result.changes === 0) return false;
  // Clean up tokens related to this user
  sqlite.prepare(`DELETE FROM tokens WHERE kind IN ('verify', 'password') AND json_extract(value, '$.email') = ?`).run(email);
  return true;
}

// --- Coupons ---

export interface Coupon {
  code: string;
  plan: string;
  fixedPrice: number;
  description: string;
  singleUse: boolean;
  used: boolean;
  expiresAt?: string;
  createdAt: string;
}

export function getCoupon(code: string): Coupon | null {
  const rows = db.select().from(coupons).where(eq(coupons.code, code)).all();
  if (!rows.length) return null;
  const coupon = rowToCoupon(rows[0]);
  if (coupon.singleUse && coupon.used) return null;
  if (coupon.expiresAt && new Date(coupon.expiresAt) < new Date()) return null;
  return coupon;
}

export function createCoupon(coupon: Omit<Coupon, "used" | "createdAt">): Coupon {
  const rows = db.insert(coupons).values({
    code: coupon.code,
    plan: coupon.plan,
    fixedPrice: coupon.fixedPrice,
    description: coupon.description,
    singleUse: coupon.singleUse,
    expiresAt: coupon.expiresAt ?? null,
  }).returning().all();
  return rowToCoupon(rows[0]);
}

export function listCoupons(): Coupon[] {
  const rows = db.select().from(coupons).orderBy(desc(coupons.createdAt)).all();
  return rows.map(rowToCoupon);
}

export function deleteCoupon(code: string): boolean {
  const result = db.delete(coupons).where(eq(coupons.code, code)).run();
  return result.changes > 0;
}

export function markCouponUsed(code: string): void {
  db.update(coupons).set({ used: true }).where(eq(coupons.code, code)).run();
}

// --- SMTP Credentials ---

export interface SmtpCredential {
  id: string;
  domainId: string;
  label: string;
  iamUsername: string;
  accessKeyId: string;
  createdAt: string;
  revokedAt?: string;
}

function rowToSmtpCredential(r: typeof smtpCredentials.$inferSelect): SmtpCredential {
  return {
    id: r.id,
    domainId: r.domainId,
    label: r.label,
    iamUsername: r.iamUsername,
    accessKeyId: r.accessKeyId,
    createdAt: r.createdAt,
    revokedAt: r.revokedAt ?? undefined,
  };
}

export function createSmtpCredential(domainId: string, label: string, iamUsername: string, accessKeyId: string): SmtpCredential {
  const rows = db.insert(smtpCredentials).values({ domainId, label, iamUsername, accessKeyId }).returning().all();
  return rowToSmtpCredential(rows[0]);
}

export function listSmtpCredentials(domainId: string): SmtpCredential[] {
  const rows = db.select().from(smtpCredentials)
    .where(and(eq(smtpCredentials.domainId, domainId), isNull(smtpCredentials.revokedAt)))
    .orderBy(asc(smtpCredentials.createdAt))
    .all();
  return rows.map(rowToSmtpCredential);
}

export function revokeSmtpCredential(domainId: string, id: string): { iamUsername: string; accessKeyId: string } | null {
  const rows = db.select().from(smtpCredentials)
    .where(and(eq(smtpCredentials.domainId, domainId), eq(smtpCredentials.id, id), isNull(smtpCredentials.revokedAt)))
    .all();
  if (!rows.length) return null;
  const cred = rows[0];
  db.update(smtpCredentials)
    .set({ revokedAt: new Date().toISOString() })
    .where(eq(smtpCredentials.id, id))
    .run();
  return { iamUsername: cred.iamUsername, accessKeyId: cred.accessKeyId };
}

// --- Referrals ---

export function generateReferralSlug(email: string): string | null {
  const local = email.split("@")[0].toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  const base = local.length < 3 ? local.padEnd(3, "0") : local.slice(0, 30);
  if (setReferralSlug(email, base)) return base;
  for (let i = 0; i < 10; i++) {
    const suffix = Math.random().toString(36).slice(2, 6);
    const candidate = `${base.slice(0, 25)}-${suffix}`;
    if (setReferralSlug(email, candidate)) return candidate;
  }
  return null;
}

export function setReferralSlug(email: string, slug: string): boolean {
  if (!/^[a-z0-9-]+$/.test(slug) || slug.length < 3 || slug.length > 30) return false;
  try {
    db.update(users).set({ referralSlug: slug }).where(eq(users.email, email)).run();
    return true;
  } catch {
    return false; // unique constraint violation
  }
}

export function getUserByReferralSlug(slug: string): { email: string } | null {
  const rows = db.select({ email: users.email }).from(users).where(eq(users.referralSlug, slug)).all();
  return rows.length ? rows[0] : null;
}

export function createReferral(referrerEmail: string, referredEmail: string): void {
  db.insert(referrals).values({ referrerEmail, referredEmail }).onConflictDoNothing().run();
}

export function getReferralByReferred(referredEmail: string): { id: string; referrerEmail: string; status: string } | null {
  const rows = db.select().from(referrals).where(eq(referrals.referredEmail, referredEmail)).all();
  return rows.length ? { id: rows[0].id, referrerEmail: rows[0].referrerEmail, status: rows[0].status } : null;
}

export function listReferrals(email: string): { id: string; referredEmail: string; status: string; createdAt: string; convertedAt?: string }[] {
  const rows = db.select().from(referrals).where(eq(referrals.referrerEmail, email)).orderBy(desc(referrals.createdAt)).all();
  return rows.map(r => ({
    id: r.id,
    referredEmail: r.referredEmail,
    status: r.status,
    createdAt: r.createdAt,
    convertedAt: r.convertedAt ?? undefined,
  }));
}

export function markReferralConverted(referralId: string): void {
  db.update(referrals).set({ status: "converted", convertedAt: new Date().toISOString() })
    .where(and(eq(referrals.id, referralId), eq(referrals.status, "pending"))).run();
}

export function createReferralCredit(email: string, referralId: string): void {
  db.insert(referralCredits).values({ email, referralId }).run();
  db.update(referrals).set({ status: "credited", creditedAt: new Date().toISOString() })
    .where(eq(referrals.id, referralId)).run();
}

export function getUnusedCredits(email: string): { id: string; discountPercent: number }[] {
  const rows = db.select().from(referralCredits)
    .where(and(eq(referralCredits.email, email), eq(referralCredits.used, false)))
    .all();
  return rows.map(r => ({ id: r.id, discountPercent: r.discountPercent }));
}

export function markCreditsUsed(creditIds: string[]): void {
  if (!creditIds.length) return;
  db.update(referralCredits).set({ used: true, usedAt: new Date().toISOString() })
    .where(and(inArray(referralCredits.id, creditIds), eq(referralCredits.used, false))).run();
}

export function getReferralStats(email: string): { total: number; pending: number; converted: number; creditsAvailable: number; slug: string | null } {
  const rows = db.select().from(referrals).where(eq(referrals.referrerEmail, email)).all();
  const total = rows.length;
  const pending = rows.filter(r => r.status === "pending").length;
  const converted = rows.filter(r => r.status === "converted" || r.status === "credited").length;
  const credits = db.select({ c: count() }).from(referralCredits)
    .where(and(eq(referralCredits.email, email), eq(referralCredits.used, false))).all();
  const userRow = db.select({ referralSlug: users.referralSlug }).from(users).where(eq(users.email, email)).all();
  return {
    total,
    pending,
    converted,
    creditsAvailable: credits[0]?.c ?? 0,
    slug: userRow[0]?.referralSlug ?? null,
  };
}

export function incrementPaymentCount(email: string): number {
  db.update(users).set({ paymentCount: rawSql`${users.paymentCount} + 1` }).where(eq(users.email, email)).run();
  const rows = db.select({ paymentCount: users.paymentCount }).from(users).where(eq(users.email, email)).all();
  return rows[0]?.paymentCount ?? 0;
}

export function getUserReferredBy(email: string): string | null {
  const rows = db.select({ referredBy: users.referredBy }).from(users).where(eq(users.email, email)).all();
  return rows[0]?.referredBy ?? null;
}

export function setUserReferredBy(email: string, referrerEmail: string): void {
  db.update(users).set({ referredBy: referrerEmail }).where(eq(users.email, email)).run();
}
