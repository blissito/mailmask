import cron from "node-cron";
import { sendFromDomain, deleteEmailFromS3 } from "./ses.js";
import { log } from "./logger.js";
import { db } from "./pg.js";
import { tokens, emailLogs, forwardQueue, rateLimits, sendCounts, bulkJobs, users } from "./schema.js";
import { lte, and, inArray, isNotNull, gt, sql as rawSql } from "drizzle-orm";
import { purgeDeletedConversations, getDomainRegistrationsByStatus, updateDomainRegistration, createDomain } from "./db.js";

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
  const expiringUsers = await db.select({ email: users.email, subPeriodEnd: users.subPeriodEnd })
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
      await sendFromDomain(
        alertFrom,
        user.email,
        "Tu plan de MailMask está por vencer",
        `Hola,\n\nTu suscripción de MailMask vence el ${endDate}.\n\nSi tu pago está al día, tu plan se renovará automáticamente. Si no, reactiva tu suscripción para no perder acceso:\n${baseUrl}/app\n\n— MailMask`,
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
  } catch (err) {
    log("error", "cron", "Cleanup failed", { error: String(err) });
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
