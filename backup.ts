import fs from "fs";
import os from "os";
import path from "path";
import { gzipSync } from "zlib";
import Database from "better-sqlite3";
import { sqlite } from "./pg.js";
import { log } from "./logger.js";
import { putBackupBinaryToS3, deleteOldBackups } from "./ses.js";

export const DB_BACKUP_SUFFIX = ".sqlite.gz";

export interface DbBackupResult {
  key: string;
  users: number;
  tables: number;
  rawBytes: number;
  gzipBytes: number;
}

/**
 * Full-database backup.
 *
 * The previous JSON export only covered users, domains, aliases and rules — 4 of the
 * 22 tables — and dropped the domains' DKIM and verification tokens, so a domain could
 * not even be rebuilt from it. Messages, conversations, notes, agents, API keys, SMTP
 * credentials, coupons and referrals were absent entirely. This takes the whole file.
 *
 * `VACUUM INTO` is used rather than copying mailmask.db: the database runs in WAL mode,
 * so the main file on its own is missing every committed page still living in the -wal.
 * VACUUM INTO asks SQLite for a consistent snapshot of the *logical* contents, safe to
 * run while the app is serving.
 */
export async function runDbBackup(): Promise<DbBackupResult> {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-").replace(/Z$/, "");
  const tmpPath = path.join(os.tmpdir(), `mailmask-backup-${stamp}.sqlite`);

  try {
    sqlite.exec(`VACUUM INTO '${tmpPath.replace(/'/g, "''")}'`);

    // Verify before shipping: an unreadable or truncated backup that sits in S3 looking
    // healthy is worse than a loud failure, which is exactly how the old ones went bad.
    const verify = new Database(tmpPath, { readonly: true });
    let users = 0;
    let tables = 0;
    try {
      const integrity = verify.pragma("integrity_check", { simple: true });
      if (integrity !== "ok") throw new Error(`integrity_check: ${integrity}`);

      tables = (verify
        .prepare("SELECT count(*) AS c FROM sqlite_master WHERE type = 'table'")
        .get() as { c: number }).c;
      users = (verify
        .prepare("SELECT count(*) AS c FROM users")
        .get() as { c: number }).c;

      if (tables < 10) throw new Error(`only ${tables} tables in backup, expected the full schema`);
    } finally {
      verify.close();
    }

    const raw = fs.readFileSync(tmpPath);
    const gz = gzipSync(raw, { level: 9 });
    const key = `mailmask-db-${stamp}${DB_BACKUP_SUFFIX}`;
    await putBackupBinaryToS3(key, gz);
    await deleteOldBackups();

    log("info", "backup", "Database backup uploaded", {
      key, users, tables, rawBytes: raw.length, gzipBytes: gz.length,
    });

    return { key, users, tables, rawBytes: raw.length, gzipBytes: gz.length };
  } finally {
    try { fs.unlinkSync(tmpPath); } catch { /* nothing to clean up */ }
  }
}
