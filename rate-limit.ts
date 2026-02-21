// --- Persistent rate limiter using SQLite with Drizzle ORM ---

import { sqlite } from "./pg.js";
import { rateLimits } from "./schema.js";

export function checkRateLimit(
  ip: string,
  limit: number,
  windowMs: number,
): { allowed: boolean; remaining: number; resetAt: number } {
  const now = Date.now();
  const key = `${ip}:${limit}:${windowMs}`;
  const expiresAt = new Date(now + windowMs).toISOString();

  // Use raw SQL for the upsert with CASE logic (SQLite compatible)
  const stmt = sqlite.prepare(`
    INSERT INTO rate_limits (key, count, window_start, expires_at)
    VALUES (?, 1, ?, ?)
    ON CONFLICT (key) DO UPDATE SET
      count = CASE
        WHEN rate_limits.window_start + ? <= ?
        THEN 1
        ELSE rate_limits.count + 1
      END,
      window_start = CASE
        WHEN rate_limits.window_start + ? <= ?
        THEN ?
        ELSE rate_limits.window_start
      END,
      expires_at = CASE
        WHEN rate_limits.window_start + ? <= ?
        THEN ?
        ELSE rate_limits.expires_at
      END
    RETURNING count, window_start
  `);

  const row = stmt.get(
    key,
    now,
    expiresAt,
    windowMs,
    now,
    windowMs,
    now,
    now,
    windowMs,
    now,
    expiresAt,
  ) as { count: number; window_start: number };

  const resetAt = Number(row.window_start) + windowMs;

  if (row.count > limit) {
    return { allowed: false, remaining: 0, resetAt };
  }

  return { allowed: true, remaining: limit - row.count, resetAt };
}
