// --- Persistent rate limiter using Deno KV (atomic) ---

let kv: Deno.Kv | null = null;
async function getKv(): Promise<Deno.Kv> {
  if (!kv) kv = await Deno.openKv(Deno.env.get("DENO_KV_URL"));
  return kv;
}

export async function checkRateLimit(
  ip: string,
  limit: number,
  windowMs: number,
): Promise<{ allowed: boolean; remaining: number; resetAt: number }> {
  const db = await getKv();
  const now = Date.now();
  const key = ["rate", `${ip}:${limit}:${windowMs}`];
  const entry = await db.get<{ count: number; windowStart: number }>(key);

  if (!entry.value || entry.value.windowStart + windowMs <= now) {
    // New window — use atomic check to prevent race
    const result = await db.atomic()
      .check(entry)
      .set(key, { count: 1, windowStart: now }, { expireIn: windowMs })
      .commit();
    if (!result.ok) {
      // Concurrent write — fail-safe: deny
      return { allowed: false, remaining: 0, resetAt: now + windowMs };
    }
    return { allowed: true, remaining: limit - 1, resetAt: now + windowMs };
  }

  const newCount = entry.value.count + 1;
  const resetAt = entry.value.windowStart + windowMs;

  if (newCount > limit) {
    return { allowed: false, remaining: 0, resetAt };
  }

  const result = await db.atomic()
    .check(entry)
    .set(key, { count: newCount, windowStart: entry.value.windowStart }, { expireIn: resetAt - now })
    .commit();

  if (!result.ok) {
    // Concurrent write — fail-safe: deny
    return { allowed: false, remaining: 0, resetAt };
  }

  return { allowed: true, remaining: limit - newCount, resetAt };
}
