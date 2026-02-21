import { fileURLToPath } from "url";
import { dirname, join } from "path";
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
