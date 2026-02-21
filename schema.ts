import {
  sqliteTable,
  text,
  integer,
  primaryKey,
  unique,
} from "drizzle-orm/sqlite-core";

export const users = sqliteTable("users", {
  email: text("email").primaryKey(),
  passwordHash: text("password_hash").notNull(),
  emailVerified: integer("email_verified", { mode: "boolean" }).notNull().default(false),
  createdAt: text("created_at").$defaultFn(() => new Date().toISOString()).notNull(),
  passwordChangedAt: text("password_changed_at"),
  subPlan: text("sub_plan"),
  subStatus: text("sub_status"),
  subMpId: text("sub_mp_id"),
  subPeriodEnd: text("sub_period_end"),
});

export const domains = sqliteTable("domains", {
  id: text("id").$defaultFn(() => crypto.randomUUID()).primaryKey(),
  ownerEmail: text("owner_email").notNull().references(() => users.email, { onDelete: "cascade" }),
  domain: text("domain").notNull().unique(),
  verified: integer("verified", { mode: "boolean" }).notNull().default(false),
  mxConfigured: integer("mx_configured", { mode: "boolean" }).notNull().default(false),
  dkimTokens: text("dkim_tokens", { mode: "json" }).$type<string[]>().notNull().default([]),
  verificationToken: text("verification_token").notNull(),
  createdAt: text("created_at").$defaultFn(() => new Date().toISOString()).notNull(),
});

export const alias = sqliteTable("alias", {
  domainId: text("domain_id").notNull().references(() => domains.id, { onDelete: "cascade" }),
  alias: text("alias").notNull(),
  destinations: text("destinations", { mode: "json" }).$type<string[]>().notNull().default([]),
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  forwardCount: integer("forward_count").notNull().default(0),
  lastFrom: text("last_from"),
  lastAt: text("last_at"),
  createdAt: text("created_at").$defaultFn(() => new Date().toISOString()).notNull(),
}, (table) => [
  primaryKey({ columns: [table.domainId, table.alias] }),
]);

export const rules = sqliteTable("rules", {
  id: text("id").$defaultFn(() => crypto.randomUUID()).primaryKey(),
  domainId: text("domain_id").notNull().references(() => domains.id, { onDelete: "cascade" }),
  field: text("field").notNull(),
  match: text("match").notNull(),
  value: text("value").notNull(),
  action: text("action").notNull(),
  target: text("target").notNull(),
  priority: integer("priority").notNull().default(0),
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  createdAt: text("created_at").$defaultFn(() => new Date().toISOString()).notNull(),
});

export const conversations = sqliteTable("conversations", {
  id: text("id").$defaultFn(() => crypto.randomUUID()).primaryKey(),
  domainId: text("domain_id").notNull().references(() => domains.id, { onDelete: "cascade" }),
  from: text("from").notNull(),
  to: text("to").notNull(),
  subject: text("subject").notNull(),
  status: text("status").notNull().default("open"),
  assignedTo: text("assigned_to"),
  priority: text("priority").notNull().default("normal"),
  lastMessageAt: text("last_message_at").$defaultFn(() => new Date().toISOString()).notNull(),
  messageCount: integer("message_count").notNull().default(0),
  tags: text("tags", { mode: "json" }).$type<string[]>().notNull().default([]),
  threadRefs: text("thread_refs", { mode: "json" }).$type<string[]>().notNull().default([]),
  deletedAt: text("deleted_at"),
});

export const messages = sqliteTable("messages", {
  id: text("id").$defaultFn(() => crypto.randomUUID()).primaryKey(),
  conversationId: text("conversation_id").notNull().references(() => conversations.id, { onDelete: "cascade" }),
  from: text("from").notNull(),
  body: text("body"),
  html: text("html"),
  s3Bucket: text("s3_bucket"),
  s3Key: text("s3_key"),
  direction: text("direction").notNull(),
  messageId: text("message_id"),
  createdAt: text("created_at").$defaultFn(() => new Date().toISOString()).notNull(),
});

export const notes = sqliteTable("notes", {
  id: text("id").$defaultFn(() => crypto.randomUUID()).primaryKey(),
  conversationId: text("conversation_id").notNull().references(() => conversations.id, { onDelete: "cascade" }),
  author: text("author").notNull(),
  body: text("body").notNull(),
  createdAt: text("created_at").$defaultFn(() => new Date().toISOString()).notNull(),
});

export const agents = sqliteTable("agents", {
  id: text("id").$defaultFn(() => crypto.randomUUID()).primaryKey(),
  domainId: text("domain_id").notNull().references(() => domains.id, { onDelete: "cascade" }),
  email: text("email").notNull(),
  name: text("name").notNull(),
  role: text("role").notNull().default("agent"),
  createdAt: text("created_at").$defaultFn(() => new Date().toISOString()).notNull(),
}, (table) => [
  unique().on(table.domainId, table.email),
]);

export const suppressions = sqliteTable("suppressions", {
  domainId: text("domain_id").notNull().references(() => domains.id, { onDelete: "cascade" }),
  email: text("email").notNull(),
  reason: text("reason").notNull(),
  createdAt: text("created_at").$defaultFn(() => new Date().toISOString()).notNull(),
}, (table) => [
  primaryKey({ columns: [table.domainId, table.email] }),
]);

export const tokens = sqliteTable("tokens", {
  token: text("token").primaryKey(),
  kind: text("kind").notNull(),
  value: text("value", { mode: "json" }),
  expiresAt: text("expires_at").notNull(),
});

export const emailLogs = sqliteTable("email_logs", {
  id: text("id").$defaultFn(() => crypto.randomUUID()).primaryKey(),
  domainId: text("domain_id").notNull().references(() => domains.id, { onDelete: "cascade" }),
  timestamp: text("timestamp").$defaultFn(() => new Date().toISOString()).notNull(),
  from: text("from").notNull(),
  to: text("to").notNull(),
  subject: text("subject").notNull(),
  status: text("status").notNull(),
  forwardedTo: text("forwarded_to").notNull(),
  sizeBytes: integer("size_bytes").notNull().default(0),
  error: text("error"),
  expiresAt: text("expires_at").notNull(),
});

export const forwardQueue = sqliteTable("forward_queue", {
  id: text("id").$defaultFn(() => crypto.randomUUID()).primaryKey(),
  rawContent: text("raw_content").notNull(),
  from: text("from").notNull(),
  to: text("to").notNull(),
  domainId: text("domain_id").notNull(),
  domainName: text("domain_name").notNull(),
  originalTo: text("original_to").notNull(),
  subject: text("subject").notNull(),
  logDays: integer("log_days").notNull().default(30),
  attemptCount: integer("attempt_count").notNull().default(0),
  nextRetryAt: text("next_retry_at").notNull(),
  lastError: text("last_error"),
  s3Bucket: text("s3_bucket"),
  s3Key: text("s3_key"),
  dead: integer("dead", { mode: "boolean" }).notNull().default(false),
  createdAt: text("created_at").$defaultFn(() => new Date().toISOString()).notNull(),
  expiresAt: text("expires_at").notNull(),
});

export const sendCounts = sqliteTable("send_counts", {
  domainId: text("domain_id").notNull(),
  month: text("month").notNull(),
  count: integer("count").notNull().default(0),
  expiresAt: text("expires_at").notNull(),
}, (table) => [
  primaryKey({ columns: [table.domainId, table.month] }),
]);

export const bulkJobs = sqliteTable("bulk_jobs", {
  id: text("id").$defaultFn(() => crypto.randomUUID()).primaryKey(),
  domainId: text("domain_id").notNull(),
  recipients: text("recipients", { mode: "json" }).$type<string[]>().notNull().default([]),
  subject: text("subject").notNull(),
  html: text("html").notNull(),
  from: text("from").notNull(),
  status: text("status").notNull().default("queued"),
  totalRecipients: integer("total_recipients").notNull().default(0),
  sent: integer("sent").notNull().default(0),
  failed: integer("failed").notNull().default(0),
  skippedSuppressed: integer("skipped_suppressed").notNull().default(0),
  lastError: text("last_error"),
  createdAt: text("created_at").$defaultFn(() => new Date().toISOString()).notNull(),
  completedAt: text("completed_at"),
  expiresAt: text("expires_at").notNull(),
});

export const coupons = sqliteTable("coupons", {
  code: text("code").primaryKey(),
  plan: text("plan").notNull(),
  fixedPrice: integer("fixed_price").notNull(),
  description: text("description").notNull(),
  singleUse: integer("single_use", { mode: "boolean" }).notNull().default(false),
  used: integer("used", { mode: "boolean" }).notNull().default(false),
  expiresAt: text("expires_at"),
  createdAt: text("created_at").$defaultFn(() => new Date().toISOString()).notNull(),
});

export const smtpCredentials = sqliteTable("smtp_credentials", {
  id: text("id").primaryKey().$defaultFn(() => crypto.randomUUID()),
  domainId: text("domain_id").notNull().references(() => domains.id, { onDelete: "cascade" }),
  label: text("label").notNull(),
  iamUsername: text("iam_username").notNull().unique(),
  accessKeyId: text("access_key_id").notNull(),
  createdAt: text("created_at").notNull().$defaultFn(() => new Date().toISOString()),
  revokedAt: text("revoked_at"),
});

export const rateLimits = sqliteTable("rate_limits", {
  key: text("key").primaryKey(),
  count: integer("count").notNull().default(0),
  windowStart: integer("window_start", { mode: "number" }).notNull(),
  expiresAt: text("expires_at").notNull(),
});
