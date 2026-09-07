import { statSync } from "node:fs";
import { programar, esServidor } from "./scheduler.js";
import { deleteEmailFromS3, sendAlert } from "./ses.js";
import { log } from "./logger.js";
import { db } from "./pg.js";
import { tokens, emailLogs, forwardQueue, rateLimits, sendCounts, bulkJobs, users, addons } from "./schema.js";
import { lte, and, eq, inArray, isNotNull, gt, sql as rawSql } from "drizzle-orm";
import { purgeDeletedConversations, purgarConversacionesGratis, wakeSnoozedConversations, getDomainRegistrationsByStatus, updateDomainRegistration, createDomain, listEffectiveAddons, updateAddon, recordOrder, addonLabel } from "./db.js";
import { sendTemplate, expiryWarning } from "./emails.js";
import { reconcilePendingAddons } from "./addon-sync.js";
import { deliverPending, purgeOldDeliveries } from "./webhooks.js";
import { notifyBandeja } from "./sse-hub.js";
import { ejecutarBackfill, backfillPendiente } from "./search-backfill.js";
import { estaVivo, diasDeCertificado, leerUso, listarBuzones, congelarBuzon, borrarBuzon, stalwartConfigurado } from "./stalwart.js";
import { listarBuzonesActivos, anotarUsoBuzon, buzonesDelUsuario, fijarGraciaBuzon, buzonesConGraciaVencida, desmarcarBuzon } from "./db.js";

// Webhooks: entregas pendientes y reintentos vencidos.
programar("* * * * *", async () => {
  try {
    const r = await deliverPending();
    if (r.delivered || r.failed) log("info", "webhook", "Deliveries processed", r);
  } catch (err) {
    log("error", "webhook", "deliverPending crashed", { error: String(err) });
  }
});

// Cada 5 minutos — activar add-ons ya pagados cuyo webhook nunca llegó.
programar("*/5 * * * *", async () => {
  try {
    await reconcilePendingAddons();
  } catch (err) {
    log("error", "cron", "Reconcile add-ons failed", { error: String(err) });
  }
});

// Daily at 14:00 UTC — warn users whose subscription expires within 3 days
programar("0 14 * * *", async () => {
  // El remitente y la URL base salían de aquí con un dominio por defecto distinto al
  // de main.ts (`mailmask.studio` contra `www.mailmask.studio`). Ahora los dos vienen
  // de emails.ts.

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
      // Sin suscripción en MercadoPago no hay nada que renueve el plan: decirle "se
      // renovará automáticamente" es mentirle y que se quede sin servicio sin avisar.
      await sendTemplate(user.email, expiryWarning({
        endDate: user.subPeriodEnd!,
        hasMpSubscription: !!user.subMpId,
      }));
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
programar("*/15 * * * *", async () => {
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

// Diario 4:00 UTC — limpieza de entregas de webhooks.
// Aquí vivía el apagado de add-ons "cuyo plan base expiró". Desde el 7-sep-2026 los
// add-ons son independientes de cualquier plan (todas las cuentas son gratis y se compra
// por dominio), así que ese barrido cancelaría en MercadoPago compras legítimas. Fuera.
programar("0 4 * * *", async () => {
  try { purgeOldDeliveries(7); } catch (err) { log("warn", "webhook", "purge failed", { error: String(err) }); }
});

// Diario 5:00 UTC — reconciliar MercadoPago contra la base.
// Existe porque una clienta pagó y el webhook no la registró; nadie se enteró en semanas.
programar("0 5 * * *", async () => {
  const mpToken = process.env.MP_ACCESS_TOKEN;
  if (!mpToken) return;
  try {
    const rows = await db.select({ email: users.email, subMpId: users.subMpId }).from(users);
    const huerfanos: string[] = [];
    for (const u of rows) {
      if (u.subMpId) continue;
      // Se busca por los dos lados: `external_reference` es el correo de MailMask en el
      // checkout autenticado, y `payer_email` puede ser otro (el de la cuenta de MP del
      // pagador, que ahora se pregunta aparte). Buscar solo por payer_email dejaba de
      // encontrar justamente a quien pagó con otra cuenta de MercadoPago.
      const encontradas = new Map<string, { id: string; status: string; external_reference?: string }>();
      for (const q of [`external_reference=${encodeURIComponent(u.email)}`, `payer_email=${encodeURIComponent(u.email)}`]) {
        const res = await fetch(
          `https://api.mercadopago.com/preapproval/search?${q}`,
          { headers: { Authorization: `Bearer ${mpToken}` }, signal: AbortSignal.timeout(15_000) },
        );
        if (!res.ok) continue;
        const j = await res.json();
        for (const p of j.results ?? []) encontradas.set(p.id, p);
      }
      const dePlan = [...encontradas.values()].filter((p) =>
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
programar("0 3 * * *", async () => {
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
programar("* * * * *", async () => {
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

// --- Índice de búsqueda de la Bandeja ---
//
// Arranque diferido: al levantar, el servidor tiene cosas más urgentes que hacer
// (reconciliar SES, migraciones) y el backfill baja correo de S3.
if (esServidor) {
  setTimeout(() => {
    ejecutarBackfill().catch((err) =>
      log("error", "search", "Backfill inicial falló", { error: String(err) })
    );
  }, 30_000);
}

// Cada 10 minutos, mientras quede algo por indexar. Cuando termina, la consulta
// devuelve 0 y no hace nada: es barata (un COUNT sobre un LEFT JOIN indexado).
programar("*/10 * * * *", async () => {
  try {
    if (backfillPendiente() === 0) return;
    await ejecutarBackfill({ maxMensajes: 500 });
  } catch (err) {
    log("error", "search", "Backfill periódico falló", { error: String(err) });
  }
});

// Snooze: despertar los hilos cuyo plazo venció. Por minuto, que es la
// granularidad que ofrece la UI; la consulta cae sobre idx_conversations_snoozed
// y no devuelve nada el 99% de las veces.
programar("* * * * *", async () => {
  try {
    const despertadas = wakeSnoozedConversations();
    for (const c of despertadas) {
      notifyBandeja(c.domainId, "conv_unsnoozed", { conversationId: c.id, subject: c.subject });
    }
    if (despertadas.length) log("info", "mesa", "Conversaciones despertadas", { count: despertadas.length });
  } catch (err) {
    log("error", "mesa", "wakeSnoozedConversations falló", { error: String(err) });
  }
});

// --- Vigilancia del volumen ---
//
// El SQLite entero vive en el volumen de Fly, que hoy son 1 GB (fly.toml).
// Cuando se llene, SQLite deja de escribir y el sitio se cae: no hay degradación
// elegante. Guardar el texto de los entrantes para la búsqueda acelera el
// llenado, así que esta alerta no es opcional.
//
// Si salta: `fly volumes extend <id> --size 10` (~$28 MXN/mes) se hace en caliente.
const LIMITE_VOLUMEN_BYTES = 1024 * 1024 * 1024;
const UMBRAL_AVISO = 0.7;

programar("0 9 * * *", async () => {
  try {
    const ruta = process.env.DATABASE_PATH ?? "./data/mailmask.db";
    // El WAL puede ser una fracción importante del total y también ocupa disco.
    let bytes = 0;
    for (const sufijo of ["", "-wal", "-shm"]) {
      try { bytes += statSync(`${ruta}${sufijo}`).size; } catch { /* no existe: 0 */ }
    }

    const proporcion = bytes / LIMITE_VOLUMEN_BYTES;
    const mb = Math.round(bytes / 1024 / 1024);
    log("info", "cron", "Tamaño de la base", { mb, proporcion: proporcion.toFixed(2) });

    if (proporcion >= UMBRAL_AVISO) {
      log("error", "cron", "Volumen cerca del límite", { mb, proporcion });
      await sendAlert(
        "volumen-lleno",
        `La base pesa ${mb} MB, el ${Math.round(proporcion * 100)}% del volumen de 1 GB. ` +
        `Cuando se llene, SQLite deja de escribir y el sitio se cae. ` +
        `Extiéndelo en caliente con: fly volumes extend <id> --size 10`
      );
    }
  } catch (err) {
    log("error", "cron", "Chequeo de volumen falló", { error: String(err) });
  }
});


// --- Servidor IMAP: salud, certificado, cuota y huérfanas ---
//
// Nada de esto existía, y por eso el 6-sep-2026 el depósito de correo en los buzones
// estuvo cayéndose en silencio: el hostname quedó apuntando al puerto de submission,
// Caddy hablaba HTTP en claro contra un socket TLS, y el reenvío —que no depende del
// buzón, a propósito— siguió funcionando sin que nadie notara nada.

// Dos fallos seguidos antes de avisar: un 502 aislado durante un despliegue no es una
// caída, y una alerta que grita por cada parpadeo se aprende a ignorar.
let fallosSeguidos = 0;

programar("*/5 * * * *", async () => {
  if (!stalwartConfigurado()) return;
  try {
    if (await estaVivo()) {
      if (fallosSeguidos >= 2) log("info", "cron", "El servidor IMAP volvió");
      fallosSeguidos = 0;
      return;
    }
    fallosSeguidos++;
    log("warn", "cron", "El servidor IMAP no responde", { fallosSeguidos });
    if (fallosSeguidos === 2) {
      await sendAlert("imap-caido", "El servidor IMAP no responde en /jmap/session. Los buzones no reciben correo nuevo (el reenvío y la Bandeja siguen funcionando).");
    }
  } catch (err) {
    log("error", "cron", "Fallo comprobando el servidor IMAP", { error: String(err) });
  }
});

// Certificado. Se renueva solo con ACME, pero "se renueva solo" es exactamente el
// tipo de cosa que se descubre rota el día que caduca.
programar("0 6 * * *", async () => {
  if (!stalwartConfigurado()) return;
  try {
    const dias = await diasDeCertificado();
    if (dias === null) return;
    if (dias < 21) {
      await sendAlert("imap-certificado", `El certificado del servidor IMAP caduca en ${dias} días. Si expira, ningún cliente de correo podrá conectarse.`);
    }
  } catch (err) {
    log("error", "cron", "Fallo leyendo el certificado del servidor IMAP", { error: String(err) });
  }
});

// Uso por buzón. Lo que guardamos es una CACHÉ de lo que reporta el servidor: todo
// contador de cuota deriva, así que esto se reconcilia y no se factura contra ello.
programar("30 6 * * *", async () => {
  if (!stalwartConfigurado()) return;
  try {
    for (const b of listarBuzonesActivos()) {
      const r = await leerUso(b.accountId);
      if (!r.ok) continue;
      anotarUsoBuzon(b.domainId, b.alias, r.valor.usados);

      const limite = r.valor.limite ?? b.quotaBytes;
      if (limite && r.valor.usados / limite > 0.85) {
        const pct = Math.round((r.valor.usados / limite) * 100);
        await sendAlert("imap-cuota", `El buzón ${b.alias}@${b.domain} va al ${pct}% de su cuota. Al llenarse dejará de recibir.`);
      }
    }
  } catch (err) {
    log("error", "cron", "Fallo reconciliando el uso de los buzones", { error: String(err) });
  }
});

// Huérfanas: cuentas vivas en Stalwart que ya no tienen fila aquí. Pasa solo — borrar
// un dominio borra sus alias EN CASCADA, y la cuenta del servidor no se entera.
//
// Sólo REPORTA. Borrar correo por una discrepancia de inventario es mucho peor que
// pagar disco de más, y una lista corta en la alerta se revisa a mano en un minuto.
programar("0 7 * * *", async () => {
  if (!stalwartConfigurado()) return;
  try {
    const enServidor = await listarBuzones();
    if (!enServidor.ok) return;

    const conocidas = new Set(listarBuzonesActivos().map((b) => `${b.alias}@${b.domain}`.toLowerCase()));
    const huerfanas = enServidor.valor.filter((c) => !conocidas.has(c.email));
    if (!huerfanas.length) return;

    log("warn", "cron", "Buzones en el servidor IMAP sin fila en la base", { total: huerfanas.length });
    await sendAlert(
      "imap-huerfanas",
      `Hay ${huerfanas.length} buzón(es) en el servidor IMAP sin máscara en la base: ${huerfanas.map((c) => c.email).slice(0, 20).join(", ")}. ` +
      "Ocupan disco y contienen correo. Revísalos antes de borrar nada.",
    );
  } catch (err) {
    log("error", "cron", "Fallo buscando buzones huérfanos", { error: String(err) });
  }
});


// Gracia vencida: aquí sí se borra el correo, y es irreversible. Va aparte del cron de
// add-ons a propósito — apagar un cobro y destruir correo no deben compartir un try.
programar("15 7 * * *", async () => {
  if (!stalwartConfigurado()) return;
  for (const b of buzonesConGraciaVencida()) {
    try {
      const r = await borrarBuzon(b.accountId, `${b.alias}@${b.domain}`);
      if (!r.ok) {
        log("error", "cron", "No se pudo borrar un buzón con gracia vencida", { buzon: `${b.alias}@${b.domain}`, error: r.error });
        continue;
      }
      desmarcarBuzon(b.domainId, b.alias);
      log("info", "cron", "Buzón borrado tras 30 días de gracia", { buzon: `${b.alias}@${b.domain}` });
    } catch (err) {
      log("error", "cron", "Fallo borrando un buzón con gracia vencida", { buzon: `${b.alias}@${b.domain}`, error: String(err) });
    }
  }
});


// Diario 3:30 UTC — retención del dominio gratis: la Bandeja muestra 7 días, guarda 30
// (activar el dominio los recupera) y a los 30 se borran DE VERDAD, S3 e índice incluidos.
// Después de esto no hay "recuperable al pagar": los 30 días son duros, y la landing lo
// dice así. Va aparte de la papelera de 15 días a propósito: son promesas distintas.
programar("30 3 * * *", async () => {
  try {
    const { s3Keys, borradas } = purgarConversacionesGratis(30);
    for (const { s3Bucket, s3Key } of s3Keys) {
      try { await deleteEmailFromS3(s3Bucket, s3Key); }
      catch (err) { log("warn", "cron", "No se pudo borrar el objeto de S3 de un hilo purgado", { s3Key, error: String(err) }); }
    }
    // Una pestaña abierta mostraría hilos ya borrados hasta recargar.
    for (const c of borradas) notifyBandeja(c.domainId, "conv_deleted", { conversationId: c.id, actor: "sistema" });
    if (borradas.length) log("info", "cron", "Retención del gratis aplicada", { hilos: borradas.length, objetosS3: s3Keys.length });
  } catch (err) {
    log("error", "cron", "Falló la retención del dominio gratis", { error: String(err) });
  }
});
