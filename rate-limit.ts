// --- Persistent rate limiter using PostgreSQL ---

import { sql } from "./pg.ts";

export async function checkRateLimit(
  ip: string,
  limit: number,
  windowMs: number,
): Promise<{ allowed: boolean; remaining: number; resetAt: number }> {
  const now = Date.now();
  const key = `${ip}:${limit}:${windowMs}`;
  const expiresAt = new Date(now + windowMs);

  // Upsert: if window expired, reset; otherwise increment
  const rows = await sql`
    INSERT INTO rate_limits (key, count, window_start, expires_at)
    VALUES (${key}, 1, ${now}, ${expiresAt})
    ON CONFLICT (key) DO UPDATE SET
      count = CASE
        WHEN rate_limits.window_start + ${windowMs} <= ${now}
        THEN 1
        ELSE rate_limits.count + 1
      END,
      window_start = CASE
        WHEN rate_limits.window_start + ${windowMs} <= ${now}
        THEN ${now}
        ELSE rate_limits.window_start
      END,
      expires_at = CASE
        WHEN rate_limits.window_start + ${windowMs} <= ${now}
        THEN ${expiresAt}
        ELSE rate_limits.expires_at
      END
    RETURNING count, window_start`;

  const { count, window_start } = rows[0];
  const resetAt = Number(window_start) + windowMs;

  if (count > limit) {
    return { allowed: false, remaining: 0, resetAt };
  }

  return { allowed: true, remaining: limit - count, resetAt };
}
