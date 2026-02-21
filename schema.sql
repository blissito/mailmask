-- MailMask PostgreSQL Schema
-- Run once against provisioned database: psql $DATABASE_URL < schema.sql

-- Users
CREATE TABLE IF NOT EXISTS users (
  email         TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  password_changed_at TIMESTAMPTZ,
  -- Subscription (embedded)
  sub_plan      TEXT,  -- basico, freelancer, developer, pro, agencia
  sub_status    TEXT,  -- active, past_due, cancelled, none
  sub_mp_id     TEXT,
  sub_period_end TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_users_sub_mp_id ON users (sub_mp_id) WHERE sub_mp_id IS NOT NULL;

-- Domains
CREATE TABLE IF NOT EXISTS domains (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_email        TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  domain             TEXT NOT NULL UNIQUE,
  verified           BOOLEAN NOT NULL DEFAULT FALSE,
  mx_configured      BOOLEAN NOT NULL DEFAULT FALSE,
  dkim_tokens        TEXT[] NOT NULL DEFAULT '{}',
  verification_token TEXT NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_domains_owner ON domains (owner_email);

-- Alias (renamed from "aliases")
CREATE TABLE IF NOT EXISTS alias (
  domain_id    UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  alias        TEXT NOT NULL,
  destinations TEXT[] NOT NULL DEFAULT '{}',
  enabled      BOOLEAN NOT NULL DEFAULT TRUE,
  forward_count INTEGER NOT NULL DEFAULT 0,
  last_from    TEXT,
  last_at      TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (domain_id, alias)
);

-- Rules
CREATE TABLE IF NOT EXISTS rules (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain_id  UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  field      TEXT NOT NULL,  -- to, from, subject
  match      TEXT NOT NULL,  -- contains, equals, regex
  value      TEXT NOT NULL,
  action     TEXT NOT NULL,  -- forward, webhook, discard
  target     TEXT NOT NULL,
  priority   INTEGER NOT NULL DEFAULT 0,
  enabled    BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_rules_domain ON rules (domain_id);

-- Conversations (Mesa)
CREATE TABLE IF NOT EXISTS conversations (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain_id       UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  "from"          TEXT NOT NULL,
  "to"            TEXT NOT NULL,
  subject         TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'open',  -- open, snoozed, closed
  assigned_to     TEXT,
  priority        TEXT NOT NULL DEFAULT 'normal',  -- normal, urgent
  last_message_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  message_count   INTEGER NOT NULL DEFAULT 0,
  tags            TEXT[] NOT NULL DEFAULT '{}',
  thread_refs     TEXT[] NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_conversations_domain ON conversations (domain_id, last_message_at DESC);
CREATE INDEX IF NOT EXISTS idx_conversations_thread ON conversations USING GIN (thread_refs);

-- Messages
CREATE TABLE IF NOT EXISTS messages (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  "from"          TEXT NOT NULL,
  body            TEXT,
  html            TEXT,
  s3_bucket       TEXT,
  s3_key          TEXT,
  direction       TEXT NOT NULL,  -- inbound, outbound
  message_id      TEXT,  -- SMTP Message-ID
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages (conversation_id, created_at);

-- Notes
CREATE TABLE IF NOT EXISTS notes (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  author          TEXT NOT NULL,
  body            TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_notes_conversation ON notes (conversation_id, created_at);

-- Agents
CREATE TABLE IF NOT EXISTS agents (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain_id  UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  email      TEXT NOT NULL,
  name       TEXT NOT NULL,
  role       TEXT NOT NULL DEFAULT 'agent',  -- admin, agent
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (domain_id, email)
);
CREATE INDEX IF NOT EXISTS idx_agents_domain ON agents (domain_id);

-- Suppressions
CREATE TABLE IF NOT EXISTS suppressions (
  domain_id  UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  email      TEXT NOT NULL,
  reason     TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (domain_id, email)
);

-- === Tables with TTL (use expires_at, cleaned by cron) ===

-- Tokens (generic: verify, password, pending-checkout, webhook, sns, agent-invite, alert-throttle, expiry-warned)
CREATE TABLE IF NOT EXISTS tokens (
  token      TEXT PRIMARY KEY,
  kind       TEXT NOT NULL,
  value      JSONB,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tokens_expires ON tokens (expires_at);
CREATE INDEX IF NOT EXISTS idx_tokens_kind ON tokens (kind);

-- Email logs
CREATE TABLE IF NOT EXISTS email_logs (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain_id    UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  timestamp    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  "from"       TEXT NOT NULL,
  "to"         TEXT NOT NULL,
  subject      TEXT NOT NULL,
  status       TEXT NOT NULL,  -- forwarded, discarded, failed, rule_matched
  forwarded_to TEXT NOT NULL,
  size_bytes   INTEGER NOT NULL DEFAULT 0,
  error        TEXT,
  expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_email_logs_domain ON email_logs (domain_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_email_logs_expires ON email_logs (expires_at);

-- Forward queue
CREATE TABLE IF NOT EXISTS forward_queue (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  raw_content   TEXT NOT NULL,
  "from"        TEXT NOT NULL,
  "to"          TEXT NOT NULL,
  domain_id     UUID NOT NULL,
  domain_name   TEXT NOT NULL,
  original_to   TEXT NOT NULL,
  subject       TEXT NOT NULL,
  log_days      INTEGER NOT NULL DEFAULT 30,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  next_retry_at TIMESTAMPTZ NOT NULL,
  last_error    TEXT,
  s3_bucket     TEXT,
  s3_key        TEXT,
  dead          BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_forward_queue_retry ON forward_queue (next_retry_at) WHERE NOT dead;
CREATE INDEX IF NOT EXISTS idx_forward_queue_expires ON forward_queue (expires_at);

-- Send counts (monthly)
CREATE TABLE IF NOT EXISTS send_counts (
  domain_id  UUID NOT NULL,
  month      TEXT NOT NULL,  -- "2026-02"
  count      INTEGER NOT NULL DEFAULT 0,
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (domain_id, month)
);

-- Bulk jobs
CREATE TABLE IF NOT EXISTS bulk_jobs (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain_id          UUID NOT NULL,
  recipients         TEXT[] NOT NULL DEFAULT '{}',
  subject            TEXT NOT NULL,
  html               TEXT NOT NULL,
  "from"             TEXT NOT NULL,
  status             TEXT NOT NULL DEFAULT 'queued',
  total_recipients   INTEGER NOT NULL DEFAULT 0,
  sent               INTEGER NOT NULL DEFAULT 0,
  failed             INTEGER NOT NULL DEFAULT 0,
  skipped_suppressed INTEGER NOT NULL DEFAULT 0,
  last_error         TEXT,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at       TIMESTAMPTZ,
  expires_at         TIMESTAMPTZ NOT NULL
);

-- Rate limits
CREATE TABLE IF NOT EXISTS rate_limits (
  key          TEXT PRIMARY KEY,
  count        INTEGER NOT NULL DEFAULT 0,
  window_start BIGINT NOT NULL,
  expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_limits_expires ON rate_limits (expires_at);
