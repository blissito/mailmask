import { sendFromDomain } from "./ses.ts";
import { log } from "./logger.ts";

const kv = await Deno.openKv(Deno.env.get("KV_URL") || undefined);

// Daily at 14:00 UTC — warn users whose subscription expires within 3 days
Deno.cron("expiry-warnings", "0 14 * * *", async () => {
  const now = Date.now();
  const threeDaysMs = 3 * 24 * 60 * 60 * 1000;
  const alertFrom = Deno.env.get("ALERT_FROM_EMAIL") ?? "noreply@mailmask.app";
  const baseUrl = Deno.env.get("MAIN_DOMAIN")
    ? `https://${Deno.env.get("MAIN_DOMAIN")!.replace(/^https?:\/\//, "").replace(/\/+$/, "")}`
    : "https://mailmask.deno.dev";

  let warned = 0;
  for await (const entry of kv.list<{ email: string; subscription?: { currentPeriodEnd?: string; status?: string } }>({ prefix: ["users"] })) {
    const user = entry.value;
    const sub = user.subscription;
    if (!sub?.currentPeriodEnd) continue;
    if (sub.status !== "active" && sub.status !== "cancelled") continue;

    const expiresAt = new Date(sub.currentPeriodEnd).getTime();
    const daysLeft = expiresAt - now;
    if (daysLeft <= 0 || daysLeft > threeDaysMs) continue;

    // Check if already warned
    const warnKey = ["expiry-warned", user.email];
    const already = await kv.get(warnKey);
    if (already.value) continue;

    try {
      await sendFromDomain(
        alertFrom,
        user.email,
        "Tu plan de MailMask está por vencer",
        `Hola,\n\nTu suscripción de MailMask vence el ${new Date(sub.currentPeriodEnd).toLocaleDateString("es-MX")}.\n\nSi tu pago está al día, tu plan se renovará automáticamente. Si no, reactiva tu suscripción para no perder acceso:\n${baseUrl}/app\n\n— MailMask`,
      );
      // Mark as warned with TTL matching the expiry window
      await kv.set(warnKey, true, { expireIn: threeDaysMs + 24 * 60 * 60 * 1000 });
      warned++;
    } catch (err) {
      log("error", "cron", "Failed to send expiry warning", { email: user.email, error: String(err) });
    }
  }

  if (warned > 0) log("info", "cron", "Sent expiry warnings", { count: warned });
});
