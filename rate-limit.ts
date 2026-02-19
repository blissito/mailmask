// --- Persistent rate limiter using Deno KV ---

const kv = await Deno.openKv();

export async function checkRateLimit(
  ip: string,
  limit: number,
  windowMs: number,
): Promise<{ allowed: boolean; remaining: number; resetAt: number }> {
  const now = Date.now();
  const key = ["rate", `${ip}:${limit}:${windowMs}`];
  const entry = await kv.get<{ count: number; windowStart: number }>(key);

  if (!entry.value || entry.value.windowStart + windowMs <= now) {
    await kv.set(key, { count: 1, windowStart: now }, { expireIn: windowMs });
    return { allowed: true, remaining: limit - 1, resetAt: now + windowMs };
  }

  const newCount = entry.value.count + 1;
  const resetAt = entry.value.windowStart + windowMs;

  await kv.set(key, { count: newCount, windowStart: entry.value.windowStart }, { expireIn: resetAt - now });

  if (newCount > limit) {
    return { allowed: false, remaining: 0, resetAt };
  }

  return { allowed: true, remaining: limit - newCount, resetAt };
}
