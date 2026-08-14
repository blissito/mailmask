import { log } from "./logger.js";
import { db } from "./pg.js";
import { addons } from "./schema.js";
import { and, eq, isNotNull } from "drizzle-orm";
import { getAddonById, updateAddon, recordOrder, addonLabel } from "./db.js";
import { sendTemplate, addonPurchase } from "./emails.js";

// MercadoPago no siempre guarda el `notification_url` que mandamos al crear el
// preapproval del add-on: pasó en producción el 13-ago-2026 — la clienta pagó $49,
// MP lo dejó `authorized` y nunca notificó, así que el add-on se quedó en `pending`
// y la cuenta siguió sin poder enviar. El webhook no es una garantía; esto sí.
// Reconcilia contra MP cualquier add-on `pending` que ya tenga preapproval.
export async function reconcilePendingAddons(): Promise<void> {
  const mpToken = process.env.MP_ACCESS_TOKEN;
  if (!mpToken) return;

  const pending = await db.select().from(addons)
    .where(and(eq(addons.status, "pending"), isNotNull(addons.mpPreapprovalId)))
    .all();
  if (pending.length === 0) return;

  for (const row of pending) {
    try {
      const res = await fetch(`https://api.mercadopago.com/preapproval/${row.mpPreapprovalId}`, {
        headers: { Authorization: `Bearer ${mpToken}` },
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) {
        log("error", "cron", "Reconcile add-on: MP fetch failed", { addonId: row.id, status: res.status });
        continue;
      }
      const sub = await res.json();
      if (sub.status !== "authorized") continue;

      // Releemos por id para no pisar un cambio hecho por el webhook mientras tanto.
      const addon = getAddonById(row.id);
      if (!addon || addon.status !== "pending") continue;

      const end = new Date();
      end.setDate(end.getDate() + 35);
      updateAddon(addon.id, { status: "active", currentPeriodEnd: end.toISOString() });
      log("warn", "billing", "Add-on activado por reconciliación (el webhook nunca llegó)", {
        addonId: addon.id, kind: addon.kind, email: addon.userEmail,
      });

      // Misma eventKey que el webhook: si este llega después, no duplica el cobro.
      const order = recordOrder({
        userEmail: addon.userEmail,
        kind: "charge",
        subject: "addon",
        subjectId: addon.id,
        subjectKey: addon.kind,
        description: addonLabel(addon.kind),
        amountCents: Math.round((sub.auto_recurring?.transaction_amount ?? 0) * 100),
        listPriceCents: addon.priceCents,
        currency: sub.auto_recurring?.currency_id ?? "MXN",
        periodEnd: end.toISOString(),
        mpPreapprovalId: String(row.mpPreapprovalId),
        mpStatus: sub.status,
        eventKey: `addon-activate:${addon.id}`,
        occurredAt: sub.date_created ?? undefined,
        raw: sub,
      });
      if (order) {
        try {
          await sendTemplate(addon.userEmail, addonPurchase({
            addonLabel: addonLabel(addon.kind),
            order,
            nextChargeAt: end.toISOString(),
          }));
        } catch (err) {
          log("error", "billing", "No se pudo mandar el recibo del add-on reconciliado", { addonId: addon.id, error: String(err) });
        }
      }
    } catch (err) {
      log("error", "cron", "Reconcile add-on failed", { addonId: row.id, error: String(err) });
    }
  }
}
