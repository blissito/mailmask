// Migration: Hash existing API keys (plaintext → SHA-256)
// Run once: npx tsx scripts/migrate-api-keys-hash.ts

import Database from "better-sqlite3";

const DB_PATH = process.env.DB_PATH ?? "mailmask.db";
const db = new Database(DB_PATH);

async function hashKey(key: string): Promise<string> {
  const data = new TextEncoder().encode(key);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function migrate() {
  // Check if migration is needed (column 'key' still exists)
  const tableInfo = db.pragma("table_info(api_keys)") as { name: string }[];
  const hasKeyCol = tableInfo.some(c => c.name === "key");
  const hasKeyHashCol = tableInfo.some(c => c.name === "key_hash");

  if (!hasKeyCol && hasKeyHashCol) {
    console.log("Migration already applied.");
    return;
  }

  if (!hasKeyCol && !hasKeyHashCol) {
    console.log("api_keys table not found or empty schema. Run drizzle-kit push first.");
    return;
  }

  console.log("Migrating API keys: plaintext → SHA-256 hash...");

  // Add new columns
  if (!hasKeyHashCol) {
    db.exec("ALTER TABLE api_keys ADD COLUMN key_hash TEXT");
    db.exec("ALTER TABLE api_keys ADD COLUMN key_prefix TEXT");
  }

  // Hash existing keys
  const rows = db.prepare("SELECT id, key FROM api_keys WHERE key IS NOT NULL").all() as { id: string; key: string }[];
  const update = db.prepare("UPDATE api_keys SET key_hash = ?, key_prefix = ? WHERE id = ?");

  for (const row of rows) {
    const hash = await hashKey(row.key);
    const prefix = row.key.slice(0, 11);
    update.run(hash, prefix, row.id);
  }

  console.log(`Hashed ${rows.length} API key(s).`);

  // Drop old column (SQLite doesn't support DROP COLUMN before 3.35.0, so recreate table)
  db.exec(`
    CREATE TABLE api_keys_new (
      id TEXT PRIMARY KEY,
      user_email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
      key_hash TEXT NOT NULL UNIQUE,
      key_prefix TEXT NOT NULL,
      name TEXT NOT NULL,
      last_used_at TEXT,
      revoked_at TEXT,
      created_at TEXT NOT NULL
    );
    INSERT INTO api_keys_new SELECT id, user_email, key_hash, key_prefix, name, last_used_at, revoked_at, created_at FROM api_keys;
    DROP TABLE api_keys;
    ALTER TABLE api_keys_new RENAME TO api_keys;
    CREATE INDEX idx_api_keys_user ON api_keys(user_email);
    CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
  `);

  console.log("Migration complete. Old plaintext keys removed.");
}

migrate().catch(console.error);
