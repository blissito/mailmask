import { sendFromDomain } from "./ses.ts";
import { log } from "./logger.ts";
import { sql } from "./pg.ts";

// Daily at 14:00 UTC — warn users whose subscription expires within 3 days
Deno.cron("expiry-warnings", "0 14 * * *", async () => {
  const alertFrom = Deno.env.get("ALERT_FROM_EMAIL") ?? "noreply@mailmask.app";
  const baseUrl = Deno.env.get("MAIN_DOMAIN")
    ? `https://${Deno.env.get("MAIN_DOMAIN")!.replace(/^https?:\/\//, "").replace(/\/+$/, "")}`
    : "https://mailmask.deno.dev";

  // Find users expiring within 3 days who haven't been warned
  const users = await sql`
    SELECT email, sub_period_end FROM users
    WHERE sub_status IN ('active', 'cancelled')
      AND sub_period_end IS NOT NULL
      AND sub_period_end > NOW()
      AND sub_period_end <= NOW() + INTERVAL '3 days'
      AND email NOT IN (
        SELECT value->>'email' FROM tokens WHERE kind = 'expiry-warned' AND expires_at > NOW()
      )`;

  let warned = 0;
  for (const user of users) {
    try {
      const endDate = new Date(user.sub_period_end).toLocaleDateString("es-MX");
      await sendFromDomain(
        alertFrom,
        user.email,
        "Tu plan de MailMask está por vencer",
        `Hola,\n\nTu suscripción de MailMask vence el ${endDate}.\n\nSi tu pago está al día, tu plan se renovará automáticamente. Si no, reactiva tu suscripción para no perder acceso:\n${baseUrl}/app\n\n— MailMask`,
      );
      await sql`
        INSERT INTO tokens (token, kind, value, expires_at)
        VALUES (${crypto.randomUUID()}, 'expiry-warned', ${JSON.stringify({ email: user.email })}, NOW() + INTERVAL '4 days')`;
      warned++;
    } catch (err) {
      log("error", "cron", "Failed to send expiry warning", { email: user.email, error: String(err) });
    }
  }

  if (warned > 0) log("info", "cron", "Sent expiry warnings", { count: warned });
});

// Every 15 minutes — clean up expired rows
Deno.cron("cleanup-expired", "*/15 * * * *", async () => {
  try {
    const results = await Promise.all([
      sql`DELETE FROM tokens WHERE expires_at <= NOW()`,
      sql`DELETE FROM email_logs WHERE expires_at <= NOW()`,
      sql`DELETE FROM forward_queue WHERE expires_at <= NOW()`,
      sql`DELETE FROM rate_limits WHERE expires_at <= NOW()`,
      sql`DELETE FROM send_counts WHERE expires_at <= NOW()`,
      sql`DELETE FROM bulk_jobs WHERE expires_at <= NOW()`,
    ]);
    const total = results.reduce((sum, r) => sum + r.count, 0);
    if (total > 0) log("info", "cron", "Cleaned expired rows", { count: total });
  } catch (err) {
    log("error", "cron", "Cleanup failed", { error: String(err) });
  }
});
