// Webhooks de eventos por dominio.
//
// `emitEvent` sólo encola: una fila por webhook activo que suscriba el evento.
// `deliverPending` (cron cada minuto) hace el POST con firma HMAC y reintenta
// con backoff. Así un receptor caído no frena el reenvío ni el envío.
import { createHmac, timingSafeEqual, randomBytes } from "node:crypto";
import { db } from "./pg.js";
import { webhooks, webhookDeliveries } from "./schema.js";
import { and, eq, lte, lt, desc } from "drizzle-orm";
import { log } from "./logger.js";

export const WEBHOOK_EVENTS = ["email.received", "email.sent", "email.delivered", "email.bounced", "email.complained"] as const;
export type WebhookEvent = typeof WEBHOOK_EVENTS[number] | "ping";

export const MAX_WEBHOOKS_PER_DOMAIN = 10;
export const MAX_ATTEMPTS = 5;
/** Espera antes del intento n (1-based). El primer intento sale en el siguiente tick del cron. */
export const RETRY_DELAYS_MS = [60_000, 5 * 60_000, 30 * 60_000, 2 * 3600_000, 12 * 3600_000];
const TIMEOUT_MS = 10_000;

export interface Webhook {
  id: string;
  domainId: string;
  url: string;
  events: string[];
  enabled: boolean;
  createdAt: string;
}

const publicView = (r: typeof webhooks.$inferSelect): Webhook => ({
  id: r.id, domainId: r.domainId, url: r.url, events: r.events, enabled: r.enabled, createdAt: r.createdAt,
});

export function listWebhooks(domainId: string): Webhook[] {
  return db.select().from(webhooks).where(eq(webhooks.domainId, domainId)).orderBy(desc(webhooks.createdAt)).all().map(publicView);
}

export function getWebhook(domainId: string, id: string): Webhook | null {
  const r = db.select().from(webhooks).where(and(eq(webhooks.id, id), eq(webhooks.domainId, domainId))).get();
  return r ? publicView(r) : null;
}

/** El secreto se devuelve aquí y nunca más: sólo sirve para verificar la firma. */
export function createWebhook(domainId: string, url: string, events: string[]): Webhook & { secret: string } {
  const secret = `whsec_${randomBytes(24).toString("base64url")}`;
  const rows = db.insert(webhooks).values({ domainId, url, secret, events }).returning().all();
  return { ...publicView(rows[0]), secret };
}

export function updateWebhook(domainId: string, id: string, patch: { url?: string; events?: string[]; enabled?: boolean }): Webhook | null {
  const set: Partial<typeof webhooks.$inferInsert> = {};
  if (patch.url !== undefined) set.url = patch.url;
  if (patch.events !== undefined) set.events = patch.events;
  if (patch.enabled !== undefined) set.enabled = patch.enabled;
  if (Object.keys(set).length) {
    db.update(webhooks).set(set).where(and(eq(webhooks.id, id), eq(webhooks.domainId, domainId))).run();
  }
  return getWebhook(domainId, id);
}

export function deleteWebhook(domainId: string, id: string): boolean {
  return db.delete(webhooks).where(and(eq(webhooks.id, id), eq(webhooks.domainId, domainId))).returning().all().length > 0;
}

export interface WebhookDelivery {
  id: string;
  webhookId: string;
  event: string;
  attempts: number;
  status: string;
  nextAt: string;
  lastError: string | null;
  lastStatusCode: number | null;
  createdAt: string;
}

export function listDeliveries(webhookId: string, limit = 50): WebhookDelivery[] {
  return db.select({
    id: webhookDeliveries.id, webhookId: webhookDeliveries.webhookId, event: webhookDeliveries.event,
    attempts: webhookDeliveries.attempts, status: webhookDeliveries.status, nextAt: webhookDeliveries.nextAt,
    lastError: webhookDeliveries.lastError, lastStatusCode: webhookDeliveries.lastStatusCode, createdAt: webhookDeliveries.createdAt,
  }).from(webhookDeliveries).where(eq(webhookDeliveries.webhookId, webhookId))
    .orderBy(desc(webhookDeliveries.createdAt)).limit(limit).all();
}

/** Encola el evento para cada webhook activo del dominio que lo suscriba. Nunca lanza. */
export function emitEvent(domainId: string, event: WebhookEvent, data: Record<string, unknown>): number {
  try {
    const targets = db.select().from(webhooks)
      .where(and(eq(webhooks.domainId, domainId), eq(webhooks.enabled, true))).all()
      .filter((w) => event === "ping" || w.events.includes(event));
    if (!targets.length) return 0;
    const now = new Date().toISOString();
    for (const w of targets) {
      db.insert(webhookDeliveries).values({
        webhookId: w.id, event, nextAt: now,
        payload: { event, domainId, timestamp: now, data },
      }).run();
    }
    return targets.length;
  } catch (err) {
    log("error", "webhook", "emitEvent failed", { domainId, event, error: String(err) });
    return 0;
  }
}

/** Encola un `ping` sólo para ese webhook, aunque no suscriba nada. */
export function enqueuePing(webhookId: string, domainId: string): string {
  const now = new Date().toISOString();
  const rows = db.insert(webhookDeliveries).values({
    webhookId, event: "ping", nextAt: now,
    payload: { event: "ping", domainId, timestamp: now, data: {} },
  }).returning().all();
  return rows[0].id;
}

export function signPayload(secret: string, timestamp: string, body: string): string {
  return `sha256=${createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex")}`;
}

/** Para el receptor: compara la firma en tiempo constante y rechaza timestamps de más de 5 min. */
export function verifyWebhookSignature(secret: string, headers: { signature: string; timestamp: string }, rawBody: string, toleranceMs = 5 * 60_000): boolean {
  const ts = Number(headers.timestamp);
  if (!Number.isFinite(ts) || Math.abs(Date.now() - ts) > toleranceMs) return false;
  const expected = Buffer.from(signPayload(secret, headers.timestamp, rawBody));
  const got = Buffer.from(headers.signature);
  return expected.length === got.length && timingSafeEqual(expected, got);
}

/** Procesa hasta `batch` entregas vencidas. Devuelve cuántas quedaron entregadas. */
export async function deliverPending(batch = 50, doFetch: typeof fetch = fetch): Promise<{ delivered: number; retried: number; failed: number }> {
  const now = new Date().toISOString();
  const due = db.select().from(webhookDeliveries)
    .where(and(eq(webhookDeliveries.status, "pending"), lte(webhookDeliveries.nextAt, now)))
    .orderBy(webhookDeliveries.nextAt).limit(batch).all();
  const out = { delivered: 0, retried: 0, failed: 0 };
  for (const d of due) {
    const hook = db.select().from(webhooks).where(eq(webhooks.id, d.webhookId)).get();
    if (!hook || !hook.enabled) {
      db.update(webhookDeliveries).set({ status: "failed", lastError: "webhook desactivado" }).where(eq(webhookDeliveries.id, d.id)).run();
      out.failed++;
      continue;
    }
    const body = JSON.stringify(d.payload);
    const timestamp = String(Date.now());
    let statusCode: number | null = null;
    let error: string | null = null;
    try {
      const res = await doFetch(hook.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "user-agent": "MailMask-Webhooks/1.0",
          "x-mailmask-event": d.event,
          "x-mailmask-delivery": d.id,
          "x-mailmask-timestamp": timestamp,
          "x-mailmask-signature": signPayload(hook.secret, timestamp, body),
        },
        body,
        signal: AbortSignal.timeout(TIMEOUT_MS),
        redirect: "manual",
      });
      statusCode = res.status;
      if (!res.ok) error = `HTTP ${res.status}`;
    } catch (err) {
      error = String(err).slice(0, 300);
    }
    const attempts = d.attempts + 1;
    if (!error) {
      db.update(webhookDeliveries).set({ status: "delivered", attempts, lastStatusCode: statusCode, lastError: null }).where(eq(webhookDeliveries.id, d.id)).run();
      out.delivered++;
    } else if (attempts >= MAX_ATTEMPTS) {
      db.update(webhookDeliveries).set({ status: "failed", attempts, lastStatusCode: statusCode, lastError: error }).where(eq(webhookDeliveries.id, d.id)).run();
      out.failed++;
      log("warn", "webhook", "Delivery gave up", { deliveryId: d.id, url: hook.url, error });
    } else {
      const nextAt = new Date(Date.now() + RETRY_DELAYS_MS[Math.min(attempts - 1, RETRY_DELAYS_MS.length - 1)]).toISOString();
      db.update(webhookDeliveries).set({ attempts, nextAt, lastStatusCode: statusCode, lastError: error }).where(eq(webhookDeliveries.id, d.id)).run();
      out.retried++;
    }
  }
  return out;
}

/** Borra entregas terminadas de más de `days` días. */
export function purgeOldDeliveries(days = 7): number {
  const cutoff = new Date(Date.now() - days * 864e5).toISOString();
  return db.delete(webhookDeliveries)
    .where(and(lt(webhookDeliveries.createdAt, cutoff), eq(webhookDeliveries.status, "delivered")))
    .returning().all().length
    + db.delete(webhookDeliveries)
    .where(and(lt(webhookDeliveries.createdAt, cutoff), eq(webhookDeliveries.status, "failed")))
    .returning().all().length;
}
