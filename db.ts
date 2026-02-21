let kv = await Deno.openKv();

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
  alias: string; // local part (e.g. "ventas") or "*" for catch-all
  domainId: string;
  destinations: string[]; // email addresses to forward to
  enabled: boolean;
  createdAt: string;
  // Stats (updated on each forward)
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
  target: string; // email or webhook URL
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
  // Legacy plan mappings (kept for existing subscribers)
  pro:     { price: 299_00, yearlyPrice: 2990_00, domains: 15, aliases: 50,  rules: 10,  logDays: 30, sends: 500,   api: false, webhooks: false, forwardPerHour: 500 },
  agencia: { price: 999_00, yearlyPrice: 9990_00, domains: 20, aliases: 100, rules: 50,  logDays: 90, sends: 2000,  api: true,  webhooks: true,  forwardPerHour: 2000 },
} as const;

// --- Users ---

export async function getUser(email: string): Promise<User | null> {
  const entry = await kv.get<User>(["users", email]);
  return entry.value;
}

export async function createUser(email: string, passwordHash: string): Promise<User> {
  const user: User = { email, passwordHash, createdAt: new Date().toISOString() };
  await kv.set(["users", email], user);
  return user;
}

export async function getUserByVerifyToken(token: string): Promise<User | null> {
  const entry = await kv.get<string>(["verify-tokens", token]);
  if (!entry.value) return null;
  return getUser(entry.value);
}

export async function setVerifyToken(email: string, token: string): Promise<void> {
  const user = await getUser(email);
  if (!user) return;
  await kv.set(["users", email], { ...user, verifyToken: token, emailVerified: false });
  await kv.set(["verify-tokens", token], email);
}

export async function verifyUserEmail(email: string): Promise<void> {
  const user = await getUser(email);
  if (!user) return;
  const token = user.verifyToken;
  await kv.set(["users", email], { ...user, emailVerified: true, verifyToken: undefined });
  if (token) await kv.delete(["verify-tokens", token]);
}

// --- Domains ---

export async function createDomain(ownerEmail: string, domain: string, dkimTokens: string[], verificationToken: string): Promise<Domain> {
  const id = crypto.randomUUID();
  const d: Domain = {
    id,
    ownerEmail,
    domain,
    verified: false,
    mxConfigured: false,
    dkimTokens,
    verificationToken,
    createdAt: new Date().toISOString(),
  };
  await kv.atomic()
    .set(["domains", id], d)
    .set(["domain-lookup", domain], id)
    .set(["user-domains", ownerEmail, id], true)
    .commit();
  return d;
}

export async function getDomain(id: string): Promise<Domain | null> {
  const entry = await kv.get<Domain>(["domains", id]);
  return entry.value;
}

export async function getDomainByName(domain: string): Promise<Domain | null> {
  const lookup = await kv.get<string>(["domain-lookup", domain]);
  if (!lookup.value) return null;
  return getDomain(lookup.value);
}

export async function listUserDomains(email: string): Promise<Domain[]> {
  const domains: Domain[] = [];
  for await (const entry of kv.list<boolean>({ prefix: ["user-domains", email] })) {
    const domainId = entry.key[2] as string;
    const domain = await getDomain(domainId);
    if (domain) domains.push(domain);
  }
  return domains;
}

export async function updateDomain(id: string, updates: Partial<Pick<Domain, "verified" | "mxConfigured">>): Promise<Domain | null> {
  const domain = await getDomain(id);
  if (!domain) return null;
  const updated = { ...domain, ...updates };
  await kv.set(["domains", id], updated);
  return updated;
}

export async function deleteDomain(id: string): Promise<boolean> {
  const domain = await getDomain(id);
  if (!domain) return false;

  // Collect all keys to delete
  const keysToDelete: Deno.KvKey[] = [];
  for await (const entry of kv.list({ prefix: ["aliases", id] })) {
    keysToDelete.push(entry.key);
  }
  for await (const entry of kv.list({ prefix: ["rules", id] })) {
    keysToDelete.push(entry.key);
  }

  // Delete domain + aliases + rules in a single atomic batch
  // Deno KV atomic ops limited to ~10 mutations per call, batch if needed
  const coreKeys: Deno.KvKey[] = [
    ["domains", id],
    ["domain-lookup", domain.domain],
    ["user-domains", domain.ownerEmail, id],
  ];
  const allKeys = [...coreKeys, ...keysToDelete];

  // Deno KV supports up to ~1000 mutations per atomic, batch in chunks of 500
  for (let i = 0; i < allKeys.length; i += 500) {
    const batch = allKeys.slice(i, i + 500);
    const op = kv.atomic();
    for (const key of batch) op.delete(key);
    await op.commit();
  }

  // Delete logs in background (can be large, non-critical)
  (async () => {
    for await (const entry of kv.list({ prefix: ["logs", id] })) {
      await kv.delete(entry.key);
    }
  })();

  return true;
}

export function countUserDomains(email: string): Promise<number> {
  return listUserDomains(email).then((d) => d.length);
}

// --- Aliases ---

export async function createAlias(domainId: string, alias: string, destinations: string[]): Promise<Alias> {
  const a: Alias = {
    alias,
    domainId,
    destinations,
    enabled: true,
    createdAt: new Date().toISOString(),
  };
  await kv.set(["aliases", domainId, alias], a);
  return a;
}

export async function getAlias(domainId: string, alias: string): Promise<Alias | null> {
  const entry = await kv.get<Alias>(["aliases", domainId, alias]);
  return entry.value;
}

export async function listAliases(domainId: string): Promise<Alias[]> {
  const aliases: Alias[] = [];
  for await (const entry of kv.list<Alias>({ prefix: ["aliases", domainId] })) {
    aliases.push(entry.value);
  }
  return aliases;
}

export async function updateAlias(domainId: string, alias: string, updates: Partial<Pick<Alias, "destinations" | "enabled">>): Promise<Alias | null> {
  const existing = await getAlias(domainId, alias);
  if (!existing) return null;
  const updated = { ...existing, ...updates };
  await kv.set(["aliases", domainId, alias], updated);
  return updated;
}

export async function bumpAliasStats(domainId: string, alias: string, from: string): Promise<void> {
  const existing = await getAlias(domainId, alias);
  if (!existing) return;
  await kv.set(["aliases", domainId, alias], {
    ...existing,
    forwardCount: (existing.forwardCount ?? 0) + 1,
    lastFrom: from,
    lastAt: new Date().toISOString(),
  });
}

export async function deleteAlias(domainId: string, alias: string): Promise<boolean> {
  const existing = await getAlias(domainId, alias);
  if (!existing) return false;
  await kv.delete(["aliases", domainId, alias]);
  return true;
}

export async function countAliases(domainId: string): Promise<number> {
  return listAliases(domainId).then((a) => a.length);
}

// --- Rules ---

export async function createRule(domainId: string, rule: Omit<Rule, "id" | "domainId" | "createdAt">): Promise<Rule> {
  const id = crypto.randomUUID();
  const r: Rule = { ...rule, id, domainId, createdAt: new Date().toISOString() };
  await kv.set(["rules", domainId, id], r);
  return r;
}

export async function listRules(domainId: string): Promise<Rule[]> {
  const rules: Rule[] = [];
  for await (const entry of kv.list<Rule>({ prefix: ["rules", domainId] })) {
    rules.push(entry.value);
  }
  return rules.sort((a, b) => a.priority - b.priority);
}

export async function deleteRule(domainId: string, ruleId: string): Promise<boolean> {
  const entry = await kv.get(["rules", domainId, ruleId]);
  if (!entry.value) return false;
  await kv.delete(["rules", domainId, ruleId]);
  return true;
}

// --- Logs ---

export async function addLog(log: Omit<EmailLog, "id">, logDays = 30): Promise<EmailLog> {
  const id = crypto.randomUUID();
  const entry: EmailLog = { ...log, id };
  await kv.set(["logs", log.domainId, log.timestamp + ":" + id], entry, { expireIn: logDays * 24 * 60 * 60 * 1000 });
  return entry;
}

export async function listLogs(domainId: string, limit = 50): Promise<EmailLog[]> {
  const logs: EmailLog[] = [];
  for await (const entry of kv.list<EmailLog>({ prefix: ["logs", domainId] }, { limit, reverse: true })) {
    logs.push(entry.value);
  }
  return logs;
}

// --- Subscription helpers ---

export async function getUserBySubscriptionId(mpSubId: string): Promise<User | null> {
  for await (const entry of kv.list<User>({ prefix: ["users"] })) {
    if (entry.value.subscription?.mpSubscriptionId === mpSubId) return entry.value;
  }
  return null;
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
  const user = await getUser(email);
  if (!user) return null;
  const updated = { ...user, subscription: sub };
  await kv.set(["users", email], updated);
  return updated;
}

export function getUserPlanLimits(user: User): { domains: number; aliases: number; rules: number; logDays: number; sends: number; api: boolean; webhooks: boolean; forwardPerHour: number } {
  const sub = user.subscription;
  if (sub && (sub.status === "active" || sub.status === "cancelled")) {
    // Expired: period ended (applies to both active and cancelled)
    if (sub.currentPeriodEnd && new Date(sub.currentPeriodEnd) < new Date()) {
      return { domains: 0, aliases: 0, rules: 0, logDays: 0, sends: 0, api: false, webhooks: false, forwardPerHour: 0 };
    }
    // Active or cancelled-but-still-in-paid-period: grant plan limits
    const plan = PLANS[sub.plan];
    return { domains: plan.domains, aliases: plan.aliases, rules: plan.rules, logDays: plan.logDays, sends: plan.sends, api: plan.api, webhooks: plan.webhooks, forwardPerHour: plan.forwardPerHour };
  }
  // Sin plan = sin acceso. Bloquear todo.
  return { domains: 0, aliases: 0, rules: 0, logDays: 0, sends: 0, api: false, webhooks: false, forwardPerHour: 0 };
}

// --- Pending checkout (guest flow) ---

export async function createPendingCheckout(token: string, plan: string): Promise<void> {
  await kv.set(["pending-checkout", token], plan, { expireIn: 24 * 60 * 60 * 1000 }); // 24h TTL
}

export async function getPendingCheckout(token: string): Promise<string | null> {
  const entry = await kv.get<string>(["pending-checkout", token]);
  return entry.value;
}

export async function deletePendingCheckout(token: string): Promise<void> {
  await kv.delete(["pending-checkout", token]);
}

// --- Password token (set-password flow) ---

export async function setPasswordToken(email: string, token: string): Promise<void> {
  await kv.set(["password-token", token], email, { expireIn: 7 * 24 * 60 * 60 * 1000 }); // 7d TTL
}

export async function getEmailByPasswordToken(token: string): Promise<string | null> {
  const entry = await kv.get<string>(["password-token", token]);
  return entry.value;
}

export async function deletePasswordToken(token: string): Promise<void> {
  await kv.delete(["password-token", token]);
}

// --- Update user password ---

export async function updateUserPassword(email: string, passwordHash: string): Promise<void> {
  const user = await getUser(email);
  if (!user) return;
  await kv.set(["users", email], { ...user, passwordHash, passwordChangedAt: new Date().toISOString() });
}

// --- Webhook idempotency ---

export async function isWebhookProcessed(id: string): Promise<boolean> {
  const entry = await kv.get(["webhook-processed", id]);
  return entry.value !== null;
}

export async function markWebhookProcessed(id: string): Promise<void> {
  await kv.set(["webhook-processed", id], true, { expireIn: 7 * 24 * 60 * 60 * 1000 });
}

// --- Atomic user creation (guest checkout) ---

export async function createUserIfNotExists(email: string, passwordHash: string): Promise<boolean> {
  const user: User = { email, passwordHash, createdAt: new Date().toISOString() };
  const result = await kv.atomic()
    .check({ key: ["users", email], versionstamp: null })
    .set(["users", email], user)
    .commit();
  return result.ok;
}

// --- SNS message dedup ---

export async function isMessageProcessed(messageId: string): Promise<boolean> {
  const entry = await kv.get(["sns-processed", messageId]);
  return entry.value !== null;
}

export async function markMessageProcessed(messageId: string): Promise<void> {
  await kv.set(["sns-processed", messageId], true, { expireIn: 24 * 60 * 60 * 1000 });
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
  nextRetryAt: string; // ISO date
  createdAt: string;
  lastError?: string;
  s3Bucket?: string;
  s3Key?: string;
}

const RETRY_DELAYS = [5 * 60_000, 30 * 60_000, 2 * 60 * 60_000]; // 5min, 30min, 2hrs
const MAX_ATTEMPTS = 3;
const QUEUE_TTL = 48 * 60 * 60 * 1000; // 48h

export { RETRY_DELAYS, MAX_ATTEMPTS };

export async function enqueueForward(item: Omit<ForwardQueueItem, "id" | "createdAt" | "attemptCount" | "nextRetryAt">, error?: string): Promise<ForwardQueueItem> {
  const id = crypto.randomUUID();
  const now = new Date();
  const entry: ForwardQueueItem = {
    ...item,
    id,
    attemptCount: 0,
    nextRetryAt: new Date(now.getTime() + RETRY_DELAYS[0]).toISOString(),
    createdAt: now.toISOString(),
    lastError: error,
  };
  await kv.set(["forward-queue", id], entry, { expireIn: QUEUE_TTL });
  return entry;
}

export async function getForwardQueueItem(id: string): Promise<ForwardQueueItem | null> {
  const entry = await kv.get<ForwardQueueItem>(["forward-queue", id]);
  return entry.value;
}

export async function updateForwardQueueItem(item: ForwardQueueItem): Promise<void> {
  await kv.set(["forward-queue", item.id], item, { expireIn: QUEUE_TTL });
}

export async function dequeueForward(id: string): Promise<void> {
  await kv.delete(["forward-queue", id]);
}

export async function listForwardQueue(): Promise<ForwardQueueItem[]> {
  const items: ForwardQueueItem[] = [];
  for await (const entry of kv.list<ForwardQueueItem>({ prefix: ["forward-queue"] })) {
    items.push(entry.value);
  }
  return items;
}

export async function moveToDeadLetter(item: ForwardQueueItem): Promise<void> {
  await kv.set(["dead-letter", item.id], item, { expireIn: 30 * 24 * 60 * 60 * 1000 }); // 30d
  await kv.delete(["forward-queue", item.id]);
}

export async function getQueueDepth(): Promise<number> {
  let count = 0;
  for await (const _ of kv.list({ prefix: ["forward-queue"] })) {
    count++;
  }
  return count;
}

export async function getDeadLetterCount(): Promise<number> {
  let count = 0;
  for await (const _ of kv.list({ prefix: ["dead-letter"] })) {
    count++;
  }
  return count;
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
  threadReferences: string[]; // Message-ID / In-Reply-To for threading
}

export interface Message {
  id: string;
  conversationId: string;
  from: string;
  body: string;
  html: string;
  direction: "inbound" | "outbound";
  createdAt: string;
  messageId?: string; // SMTP Message-ID header
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

export async function createConversation(conv: Omit<Conversation, "id">): Promise<Conversation> {
  const id = crypto.randomUUID();
  const c: Conversation = { ...conv, id };
  await kv.atomic()
    .set(["conversations", conv.domainId, id], c)
    .commit();
  return c;
}

export async function getConversation(domainId: string, id: string): Promise<Conversation | null> {
  const entry = await kv.get<Conversation>(["conversations", domainId, id]);
  return entry.value;
}

export async function listConversations(domainId: string, opts?: { status?: string; assignedTo?: string }): Promise<Conversation[]> {
  const convs: Conversation[] = [];
  for await (const entry of kv.list<Conversation>({ prefix: ["conversations", domainId] })) {
    const c = entry.value;
    if (opts?.status && c.status !== opts.status) continue;
    if (opts?.assignedTo && c.assignedTo !== opts.assignedTo) continue;
    convs.push(c);
  }
  return convs.sort((a, b) => b.lastMessageAt.localeCompare(a.lastMessageAt));
}

export async function updateConversation(domainId: string, id: string, updates: Partial<Pick<Conversation, "status" | "assignedTo" | "priority" | "tags" | "lastMessageAt" | "messageCount" | "threadReferences">>): Promise<Conversation | null> {
  const conv = await getConversation(domainId, id);
  if (!conv) return null;
  const updated = { ...conv, ...updates };
  await kv.set(["conversations", domainId, id], updated);
  return updated;
}

export async function findConversationByThread(domainId: string, from: string, references: string[]): Promise<Conversation | null> {
  // Try to match by thread references first
  for await (const entry of kv.list<Conversation>({ prefix: ["conversations", domainId] })) {
    const c = entry.value;
    // Match by In-Reply-To / References overlap
    if (references.length > 0 && c.threadReferences.some(ref => references.includes(ref))) {
      return c;
    }
  }
  return null;
}

// --- Messages ---

export async function addMessage(msg: Omit<Message, "id">): Promise<Message> {
  const id = crypto.randomUUID();
  const m: Message = { ...msg, id };
  await kv.set(["messages", msg.conversationId, msg.createdAt + ":" + id], m);
  return m;
}

export async function listMessages(conversationId: string): Promise<Message[]> {
  const msgs: Message[] = [];
  for await (const entry of kv.list<Message>({ prefix: ["messages", conversationId] })) {
    msgs.push(entry.value);
  }
  return msgs.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

// --- Notes ---

export async function addNote(note: Omit<Note, "id">): Promise<Note> {
  const id = crypto.randomUUID();
  const n: Note = { ...note, id };
  await kv.set(["notes", note.conversationId, note.createdAt + ":" + id], n);
  return n;
}

export async function listNotes(conversationId: string): Promise<Note[]> {
  const notes: Note[] = [];
  for await (const entry of kv.list<Note>({ prefix: ["notes", conversationId] })) {
    notes.push(entry.value);
  }
  return notes.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

// --- Agents ---

export async function createAgent(agent: Omit<Agent, "id" | "createdAt">): Promise<Agent> {
  const id = crypto.randomUUID();
  const a: Agent = { ...agent, id, createdAt: new Date().toISOString() };
  await kv.atomic()
    .set(["agents", agent.domainId, id], a)
    .set(["agent-lookup", agent.domainId, agent.email], id)
    .commit();
  return a;
}

export async function getAgent(domainId: string, agentId: string): Promise<Agent | null> {
  const entry = await kv.get<Agent>(["agents", domainId, agentId]);
  return entry.value;
}

export async function getAgentByEmail(domainId: string, email: string): Promise<Agent | null> {
  const lookup = await kv.get<string>(["agent-lookup", domainId, email]);
  if (!lookup.value) return null;
  return getAgent(domainId, lookup.value);
}

export async function listAgents(domainId: string): Promise<Agent[]> {
  const agents: Agent[] = [];
  for await (const entry of kv.list<Agent>({ prefix: ["agents", domainId] })) {
    agents.push(entry.value);
  }
  return agents;
}

export async function deleteAgent(domainId: string, agentId: string): Promise<boolean> {
  const agent = await getAgent(domainId, agentId);
  if (!agent) return false;
  await kv.atomic()
    .delete(["agents", domainId, agentId])
    .delete(["agent-lookup", domainId, agent.email])
    .commit();
  return true;
}

export async function countAgents(domainId: string): Promise<number> {
  return listAgents(domainId).then(a => a.length);
}

// --- Suppression list ---

export async function addSuppression(domainId: string, email: string, reason: string): Promise<void> {
  await kv.set(["suppression", domainId, email], { reason, createdAt: new Date().toISOString() });
}

export async function isSuppressed(domainId: string, email: string): Promise<boolean> {
  const entry = await kv.get(["suppression", domainId, email]);
  return entry.value !== null;
}

export async function removeSuppression(domainId: string, email: string): Promise<void> {
  await kv.delete(["suppression", domainId, email]);
}

// --- Send counter (monthly) ---

export async function incrementSendCount(domainId: string): Promise<number> {
  const month = new Date().toISOString().slice(0, 7); // "2026-02"
  const key: Deno.KvKey = ["sends", domainId, month];
  const entry = await kv.get<number>(key);
  const count = (entry.value ?? 0) + 1;
  await kv.set(key, count, { expireIn: 45 * 24 * 60 * 60 * 1000 }); // 45d TTL
  return count;
}

export async function getSendCount(domainId: string): Promise<number> {
  const month = new Date().toISOString().slice(0, 7);
  const entry = await kv.get<number>(["sends", domainId, month]);
  return entry.value ?? 0;
}

// --- Bulk jobs ---

export async function createBulkJob(job: Omit<BulkJob, "id" | "createdAt" | "sent" | "failed" | "skippedSuppressed" | "status">): Promise<BulkJob> {
  const id = crypto.randomUUID();
  const j: BulkJob = { ...job, id, status: "queued", sent: 0, failed: 0, skippedSuppressed: 0, createdAt: new Date().toISOString() };
  await kv.set(["bulk", job.domainId, id], j, { expireIn: 7 * 24 * 60 * 60 * 1000 }); // 7d
  return j;
}

export async function getBulkJob(domainId: string, jobId: string): Promise<BulkJob | null> {
  const entry = await kv.get<BulkJob>(["bulk", domainId, jobId]);
  return entry.value;
}

export async function updateBulkJob(job: BulkJob): Promise<void> {
  await kv.set(["bulk", job.domainId, job.id], job, { expireIn: 7 * 24 * 60 * 60 * 1000 });
}

export async function listPendingBulkJobs(): Promise<BulkJob[]> {
  const jobs: BulkJob[] = [];
  // We need to scan across all domains — use a broader prefix approach
  // Since bulk jobs have TTL, this list stays small
  for await (const entry of kv.list<BulkJob>({ prefix: ["bulk"] })) {
    if (entry.value.status === "queued" || entry.value.status === "processing") {
      jobs.push(entry.value);
    }
  }
  return jobs.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

// --- Agent invite tokens ---

export async function createAgentInvite(domainId: string, email: string, name: string, role: "admin" | "agent"): Promise<string> {
  const token = crypto.randomUUID();
  await kv.set(["agent-invite", token], { domainId, email, name, role }, { expireIn: 7 * 24 * 60 * 60 * 1000 });
  return token;
}

export async function getAgentInvite(token: string): Promise<{ domainId: string; email: string; name: string; role: "admin" | "agent" } | null> {
  const entry = await kv.get<{ domainId: string; email: string; name: string; role: "admin" | "agent" }>(["agent-invite", token]);
  return entry.value;
}

export async function deleteAgentInvite(token: string): Promise<void> {
  await kv.delete(["agent-invite", token]);
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
  const users: Omit<User, "passwordHash">[] = [];
  for await (const entry of kv.list<User>({ prefix: ["users"] })) {
    const { passwordHash: _, ...safe } = entry.value;
    users.push(safe);
  }
  return users;
}

export async function deleteUser(email: string): Promise<boolean> {
  const user = await getUser(email);
  if (!user) return false;

  // Delete all user domains (which cascades to aliases, rules, logs)
  const domains = await listUserDomains(email);
  for (const d of domains) {
    await deleteDomain(d.id);
  }

  // Delete the user record
  await kv.delete(["users", email]);

  // Clean up verify token if exists
  if (user.verifyToken) {
    await kv.delete(["verify-tokens", user.verifyToken]);
  }

  return true;
}

// --- Test helpers ---

export function _getKv() {
  return kv;
}

export function _setKv(newKv: Deno.Kv) {
  kv = newKv;
}
