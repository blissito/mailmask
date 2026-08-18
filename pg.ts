import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { createHash } from "crypto";
import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";
import * as schema from "./schema.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const dbPath = process.env.DATABASE_PATH ?? "./data/mailmask.db";
const sqlite = new Database(dbPath);
sqlite.pragma("journal_mode = WAL");
sqlite.pragma("foreign_keys = ON");

export const db = drizzle(sqlite, { schema });
export { sqlite };

// Run migrations on startup
migrate(db, { migrationsFolder: join(__dirname, "drizzle") });

// El paso de llaves en claro a SHA-256 se aplicó a producción con un script
// suelto (scripts/migrate-api-keys-hash.ts) que nunca entró a las migraciones.
// Resultado: toda base nueva —tests, dev, un despliegue limpio— nacía con la
// tabla vieja y `createApiKey` moría con "no column named key_hash".
//
// Va aquí y no como .sql porque hay bases en los dos estados y SQL no puede
// preguntar por una columna: es idempotente, y sobre una base ya migrada no
// hace nada. Las llaves existentes se conservan hasheadas, nunca se tiran.
const columnasApiKeys = sqlite.pragma("table_info(api_keys)") as { name: string }[];
if (columnasApiKeys.some((c) => c.name === "key")) {
  const hashDe = (valor: string) =>
    createHash("sha256").update(valor, "utf8").digest("hex");

  sqlite.transaction(() => {
    if (!columnasApiKeys.some((c) => c.name === "key_hash")) {
      sqlite.exec("ALTER TABLE api_keys ADD COLUMN key_hash TEXT");
      sqlite.exec("ALTER TABLE api_keys ADD COLUMN key_prefix TEXT");
    }

    const filas = sqlite
      .prepare("SELECT id, key FROM api_keys WHERE key IS NOT NULL")
      .all() as { id: string; key: string }[];
    const update = sqlite.prepare(
      "UPDATE api_keys SET key_hash = ?, key_prefix = ? WHERE id = ?"
    );
    for (const fila of filas) {
      update.run(hashDe(fila.key), fila.key.slice(0, 11), fila.id);
    }

    // SQLite viejo no tiene DROP COLUMN: se recrea la tabla.
    sqlite.exec(`
      CREATE TABLE api_keys_nueva (
        id TEXT PRIMARY KEY,
        user_email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
        key_hash TEXT NOT NULL UNIQUE,
        key_prefix TEXT NOT NULL,
        name TEXT NOT NULL,
        last_used_at TEXT,
        revoked_at TEXT,
        created_at TEXT NOT NULL
      );
      INSERT INTO api_keys_nueva
        SELECT id, user_email, key_hash, key_prefix, name, last_used_at, revoked_at, created_at
        FROM api_keys WHERE key_hash IS NOT NULL;
      DROP TABLE api_keys;
      ALTER TABLE api_keys_nueva RENAME TO api_keys;
      CREATE INDEX idx_api_keys_user ON api_keys(user_email);
      CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
    `);
  })();
}
