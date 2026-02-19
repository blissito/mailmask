const kv = await Deno.openKv();

// --- Types ---

export interface User {
  email: string;
  passwordHash: string;
  createdAt: string;
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

// --- Pricing ---

export const PRICING = {
  perDomain: 99_00, // $99 MXN in centavos
  pack3: 199_00,
  pack10: 499_00,
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

  // Delete all aliases
  for await (const entry of kv.list({ prefix: ["aliases", id] })) {
    await kv.delete(entry.key);
  }
  // Delete all rules
  for await (const entry of kv.list({ prefix: ["rules", id] })) {
    await kv.delete(entry.key);
  }
  // Delete logs (fire-and-forget)
  (async () => {
    for await (const entry of kv.list({ prefix: ["logs", id] })) {
      await kv.delete(entry.key);
    }
  })();

  await kv.atomic()
    .delete(["domains", id])
    .delete(["domain-lookup", domain.domain])
    .delete(["user-domains", domain.ownerEmail, id])
    .commit();
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

export async function addLog(log: Omit<EmailLog, "id">): Promise<EmailLog> {
  const id = crypto.randomUUID();
  const entry: EmailLog = { ...log, id };
  // TTL 30 days
  await kv.set(["logs", log.domainId, log.timestamp + ":" + id], entry, { expireIn: 30 * 24 * 60 * 60 * 1000 });
  return entry;
}

export async function listLogs(domainId: string, limit = 50): Promise<EmailLog[]> {
  const logs: EmailLog[] = [];
  for await (const entry of kv.list<EmailLog>({ prefix: ["logs", domainId] }, { limit, reverse: true })) {
    logs.push(entry.value);
  }
  return logs;
}

// --- Test helpers ---

export function _getKv() {
  return kv;
}
