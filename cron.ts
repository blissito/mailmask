import cron from "node-cron";
import { sendFromDomain, deleteEmailFromS3, sendAlert } from "./ses.js";
import { log } from "./logger.js";
import { db } from "./pg.js";
import { tokens, emailLogs, forwardQueue, rateLimits, sendCounts, bulkJobs, users, addons } from "./schema.js";
import { lte, and, eq, inArray, isNotNull, gt, sql as rawSql } from "drizzle-orm";
import { purgeDeletedConversations, getDomainRegistrationsByStatus, updateDomainRegistration, createDomain, listEffectiveAddons, updateAddon } from "./db.js";

// Daily at 14:00 UTC — warn users whose subscription expires within 3 days
cron.schedule("0 14 * * *", async () => {
  const alertFrom = process.env.ALERT_FROM_EMAIL ?? "noreply@mailmask.studio";
  const baseUrl = process.env.MAIN_DOMAIN
    ? `https://${process.env.MAIN_DOMAIN.replace(/^https?:\/\//, "").replace(/\/+$/, "")}`
    : "https://mailmask.studio";

  // Find users expiring within 3 days who haven't been warned yet.
  // Step 1: get emails of already-warned users (stored as JSON value)
  const now = new Date().toISOString();
  const threeDaysLater = new Date(Date.now() + 3 * 24 * 3600_000).toISOString();

  const warnedRows = await db.select({ value: tokens.value })
    .from(tokens)
    .where(and(rawSql`${tokens.kind} = 'expiry-warned'`, gt(tokens.expiresAt, now)));
  const warnedEmails = new Set(
    warnedRows
      .map((r) => (r.value as { email?: string } | null)?.email)
      .filter((e): e is string => typeof e === "string"),
  );

  // Step 2: get users expiring within 3 days with active/cancelled status
  const expiringUsers = await db.select({ email: users.email, subPeriodEnd: users.subPeriodEnd, subMpId: users.subMpId })
    .from(users)
    .where(
      and(
        inArray(users.subStatus, ["active", "cancelled"]),
        isNotNull(users.subPeriodEnd),
        gt(users.subPeriodEnd, now),
        lte(users.subPeriodEnd, threeDaysLater),
      ),
    );

  const toWarn = expiringUsers.filter((u) => !warnedEmails.has(u.email));

  let warned = 0;
  for (const user of toWarn) {
    try {
      const endDate = new Date(user.subPeriodEnd!).toLocaleDateString("es-MX");
      // Sin suscripción en MercadoPago no hay nada que renueve el plano: decirle "se
      // renovará automáticamente" es mentirle y que se quede sin servicio sin avisar.
      const seRenueva = !!user.subMpId;
      const cuerpo = seRenueva
        ? `Hola,\n\nTu suscripción de MailMask vence el ${endDate}.\n\nSi tu pago está al día, tu plan se renovará automáticamente. Si no, reactiva tu suscripción para no perder acceso:\n${baseUrl}/app\n\n— MailMask`
        : `Hola,\n\nTu plan de MailMask vence el ${endDate} y no tiene una suscripción activa que lo renueve, así que ese día perderías el acceso.\n\nActiva tu suscripción aquí para no quedarte sin servicio:\n${baseUrl}/app\n\n— MailMask`;
      await sendFromDomain(
        alertFrom,
        user.email,
        "Tu plan de MailMask está por vencer",
        cuerpo,
      );
      const expiresAt = new Date(Date.now() + 4 * 24 * 3600_000).toISOString();
      await db.insert(tokens).values({
        token: crypto.randomUUID(),
        kind: "expiry-warned",
        value: { email: user.email },
        expiresAt,
      });
      warned++;
    } catch (err) {
      log("error", "cron", "Failed to send expiry warning", { email: user.email, error: String(err) });
    }
  }

  if (warned > 0) log("info", "cron", "Sent expiry warnings", { count: warned });
});

// Every 15 minutes — clean up expired rows
cron.schedule("*/15 * * * *", async () => {
  try {
    const now = new Date().toISOString();
    const results = await Promise.all([
      db.delete(tokens).where(lte(tokens.expiresAt, now)),
      db.delete(emailLogs).where(lte(emailLogs.expiresAt, now)),
      db.delete(forwardQueue).where(lte(forwardQueue.expiresAt, now)),
      db.delete(rateLimits).where(lte(rateLimits.expiresAt, now)),
      db.delete(sendCounts).where(lte(sendCounts.expiresAt, now)),
      db.delete(bulkJobs).where(lte(bulkJobs.expiresAt, now)),
    ]);
    const total = results.reduce((sum, r) => sum + (r.changes ?? 0), 0);
    if (total > 0) log("info", "cron", "Cleaned expired rows", { count: total });

    // Add-ons abandonados en el checkout de MP. No se borran (queda el rastro de intento),
    // solo se marcan para que no bloqueen una compra nueva del mismo tipo.
    const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const stale = await db.update(addons)
      .set({ status: "expired" })
      .where(and(eq(addons.status, "pending"), lte(addons.createdAt, dayAgo)));
    if ((stale.changes ?? 0) > 0) log("info", "cron", "Expired abandoned add-ons", { count: stale.changes });
  } catch (err) {
    log("error", "cron", "Cleanup failed", { error: String(err) });
  }
});

// Diario 4:00 UTC — apagar add-ons cuyo plan base ya expiró.
// Sin esto MercadoPago sigue cobrando el add-on mientras getUserPlanLimits devuelve cero:
// se le cobra al cliente por algo que no recibe.
cron.schedule("0 4 * * *", async () => {
  const mpToken = process.env.MP_ACCESS_TOKEN;
  try {
    const now = new Date().toISOString();
    const vencidos = await db.select({ email: users.email })
      .from(users)
      .where(and(isNotNull(users.subPeriodEnd), lte(users.subPeriodEnd, now)));

    let apagados = 0;
    for (const u of vencidos) {
      for (const addon of listEffectiveAddons(u.email)) {
        try {
          if (addon.mpPreapprovalId && mpToken) {
            const res = await fetch(`https://api.mercadopago.com/preapproval/${addon.mpPreapprovalId}`, {
              method: "PUT",
              headers: { Authorization: `Bearer ${mpToken}`, "Content-Type": "application/json" },
              body: JSON.stringify({ status: "cancelled" }),
              signal: AbortSignal.timeout(10_000),
            });
            if (!res.ok) throw new Error(`MP ${res.status}: ${await res.text()}`);
          }
          updateAddon(addon.id, { status: "cancelled", cancelledAt: new Date().toISOString() });
          apagados++;
          log("info", "billing", "Add-on cancelado: el plan base expiró", { email: u.email, addonId: addon.id, kind: addon.kind });
        } catch (err) {
          log("error", "billing", "No se pudo cancelar add-on de plan expirado", { email: u.email, addonId: addon.id, error: String(err) });
        }
      }
    }
    if (apagados > 0) log("info", "cron", "Add-ons apagados por plan expirado", { count: apagados });
  } catch (err) {
    log("error", "cron", "Expired add-on cleanup failed", { error: String(err) });
  }
});

// Diario 5:00 UTC — reconciliar MercadoPago contra la base.
// Existe porque una clienta pagó y el webhook no la registró; nadie se enteró en semanas.
cron.schedule("0 5 * * *", async () => {
  const mpToken = process.env.MP_ACCESS_TOKEN;
  if (!mpToken) return;
  try {
    const rows = await db.select({ email: users.email, subMpId: users.subMpId }).from(users);
    const huerfanos: string[] = [];
    for (const u of rows) {
      if (u.subMpId) continue;
      const res = await fetch(
        `https://api.mercadopago.com/preapproval/search?payer_email=${encodeURIComponent(u.email)}`,
        { headers: { Authorization: `Bearer ${mpToken}` }, signal: AbortSignal.timeout(15_000) },
      );
      if (!res.ok) continue;
      const j = await res.json();
      const dePlan = (j.results ?? []).filter((p: { status: string; external_reference?: string }) =>
        p.status === "authorized" && !(p.external_reference ?? "").startsWith("addon:"));
      if (dePlan.length > 0) huerfanos.push(`${u.email} → ${dePlan[0].id}`);
    }
    if (huerfanos.length > 0) {
      log("error", "billing", "PAGOS SIN VINCULAR detectados", { count: huerfanos.length, huerfanos });
      await sendAlert("mp-unlinked", `Hay ${huerfanos.length} pago(s) en MercadoPago sin vincular en la base:\n\n${huerfanos.join("\n")}\n\nCorre: npx tsx scripts/reconcile-mp.ts --fix`);
    }
  } catch (err) {
    log("error", "cron", "MP reconciliation failed", { error: String(err) });
  }
});

// Daily at 3:00 UTC — purge conversations deleted >15 days ago + their S3 objects
cron.schedule("0 3 * * *", async () => {
  try {
    const s3Keys = await purgeDeletedConversations(15);
    for (const { s3Bucket, s3Key } of s3Keys) {
      try {
        await deleteEmailFromS3(s3Bucket, s3Key);
      } catch (err) {
        log("warn", "cron", "Failed to delete S3 object during purge", { s3Key, error: String(err) });
      }
    }
    if (s3Keys.length > 0) log("info", "cron", "Purged deleted conversations", { s3Objects: s3Keys.length });
  } catch (err) {
    log("error", "cron", "Purge deleted conversations failed", { error: String(err) });
  }
});

// Every minute — poll Route 53 domain registrations in "registering" status
cron.schedule("* * * * *", async () => {
  let regs;
  try {
    regs = getDomainRegistrationsByStatus("registering");
  } catch {
    return; // table may not exist yet
  }
  if (!regs.length) return;

  for (const reg of regs) {
    if (!reg.route53OperationId) continue;
    try {
      const { getOperationStatus, createHostedZone, updateNameservers, configureDnsRecords } = await import("./route53.js");
      const { verifyDomain, createReceiptRule } = await import("./ses.js");

      const status = await getOperationStatus(reg.route53OperationId);
      log("info", "cron", "Domain registration poll", { domain: reg.domainName, status });

      if (status === "SUCCESSFUL") {
        // 1. Create hosted zone
        const { hostedZoneId, nameservers } = await createHostedZone(reg.domainName);

        // 2. Update nameservers to point to our hosted zone
        await updateNameservers(reg.domainName, nameservers);

        // 3. Verify domain with SES (get tokens)
        const dnsRecords = await verifyDomain(reg.domainName);

        // 4. Configure DNS records (MX, TXT, DKIM, SPF)
        await configureDnsRecords(hostedZoneId, reg.domainName, dnsRecords.verificationToken, dnsRecords.dkimTokens);

        // 5. Create SES receipt rule
        try {
          await createReceiptRule(reg.domainName);
        } catch (err: any) {
          // May fail if SNS_TOPIC_ARN not set, non-fatal
          log("warn", "cron", "Receipt rule creation failed (non-fatal)", { domain: reg.domainName, error: String(err) });
        }

        // 6. Insert into domains table
        const domainRow = createDomain(reg.ownerEmail, reg.domainName, dnsRecords.dkimTokens, dnsRecords.verificationToken);

        // 7. Mark domain as verified + registeredViaMailmask
        // We need to update directly since createDomain doesn't set these
        const { domains } = await import("./schema.js");
        const { eq } = await import("drizzle-orm");
        db.update(domains).set({
          verified: true,
          mxConfigured: true,
          registeredViaMailmask: true,
        }).where(eq(domains.id, domainRow.id)).run();

        // 8. Update registration record
        const expiresAt = new Date(Date.now() + 365 * 24 * 3600_000).toISOString();
        updateDomainRegistration(reg.id, {
          status: "registered",
          domainId: domainRow.id,
          hostedZoneId,
          registeredAt: new Date().toISOString(),
          expiresAt,
        });

        log("info", "cron", "Domain registration completed", { domain: reg.domainName, domainId: domainRow.id });
      } else if (status === "FAILED" || status === "ERROR") {
        updateDomainRegistration(reg.id, { status: "failed", lastError: `Route 53 operation ${status}` });
        log("error", "cron", "Domain registration failed", { domain: reg.domainName, operationId: reg.route53OperationId });
      }
      // IN_PROGRESS / SUBMITTED — just wait for next poll
    } catch (err: any) {
      log("error", "cron", "Domain registration poll error", { domain: reg.domainName, error: String(err) });
      updateDomainRegistration(reg.id, { lastError: String(err) });
    }
  }
});
