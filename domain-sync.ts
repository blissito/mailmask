// Vigilancia de los dominios registrados: la fecha real de expiración, los avisos antes de
// que venza y la cobranza cuando el cobro anual falla.
//
// Todo esto existe porque `registerDomain` manda `AutoRenew: true` a AWS y nadie volvía a
// cobrarle al cliente. La consecuencia no era perder el dominio: era que AWS lo renovaba y
// nos lo cobraba a nosotros, en silencio, para siempre.
import { log } from "./logger.js";
import {
  getDomainRegistrationsByStatus,
  updateDomainRegistration,
  TLD_PRICES,
  type DomainRegistration,
} from "./db.js";

const DIA = 864e5;
/**
 * Días antes del vencimiento en los que se avisa, y sólo una vez cada uno. Ascendente a
 * propósito: a 25 días toca el hito de 30, no el de 75, o el aviso se quedaría en el
 * primero para siempre.
 */
const HITOS_AVISO = [7, 30, 75];
/** Reintentos de cobranza, en días desde el primer rechazo. */
const HITOS_COBRANZA = [3, 7, 14];
const DIAS_HASTA_DECISION_HUMANA = 21;

const dias = (iso: string | null) => (iso ? Math.floor((Date.parse(iso) - Date.now()) / DIA) : null);

/**
 * Relee de AWS la fecha de expiración y el AutoRenew. `expiresAt` se calculaba como
 * `ahora + 365 días`, y toda la ventana de cobro depende de esa fecha.
 */
export async function syncDomainExpirations(): Promise<void> {
  const regs = getDomainRegistrationsByStatus("registered");
  if (!regs.length) return;

  const { getDomainDetail } = await import("./route53.js");
  const { sendAlert } = await import("./ses.js");
  const sinRenovacion: string[] = [];

  for (const reg of regs) {
    try {
      const detalle = await getDomainDetail(reg.domainName);
      const expiresAt = detalle.expirationDate ?? reg.expiresAt;

      updateDomainRegistration(reg.id, {
        expiresAt,
        awsAutoRenew: detalle.autoRenew,
        lastSyncedAt: new Date().toISOString(),
        nextChargeAt: expiresAt ? new Date(Date.parse(expiresAt) - 60 * DIA).toISOString() : null,
      });

      // Este es el estado que pierde dominios, y nada de nuestro código lo produce: si
      // aparece, alguien lo apagó a mano en la consola de AWS.
      if (!detalle.autoRenew) {
        await sendAlert(
          "dominio-sin-autorenew",
          `AWS reporta AutoRenew apagado en ${reg.domainName} (${reg.ownerEmail}, vence ${expiresAt ?? "?"}).\n\nSi nadie lo apagó a propósito, vuelve a encenderlo YA: un dominio vencido se pierde y rescatarlo en redención cuesta ~$90 USD.`,
        );
      }

      const faltan = dias(expiresAt);
      if (faltan !== null && faltan < 90 && reg.renewalStatus !== "active") {
        sinRenovacion.push(`${reg.domainName} — ${reg.ownerEmail} — vence en ${faltan} días`);
      }
    } catch (err) {
      log("error", "cron", "No se pudo sincronizar el dominio con AWS", { domain: reg.domainName, error: String(err) });
    }
  }

  // Digest en vez de una alerta por dominio: es la red que evita que MailMask acabe
  // pagando dominios ajenos sin enterarse.
  if (sinRenovacion.length) {
    await sendAlert(
      "dominios-sin-renovacion",
      `Estos dominios vencen en menos de 90 días y NO tienen renovación cobrada:\n\n${sinRenovacion.join("\n")}\n\nAWS los va a renovar y nos los va a cobrar.`,
    );
  }
}

/** Avisos a T-75, T-30 y T-7. `warnedAt` guarda el hito ya avisado para no repetir. */
export async function avisarRenovaciones(): Promise<void> {
  const regs = getDomainRegistrationsByStatus("registered");
  if (!regs.length) return;

  const { sendTemplate, domainRenewalUpcoming } = await import("./emails.js");

  for (const reg of regs) {
    const faltan = dias(reg.expiresAt);
    if (faltan === null || faltan < 0) continue;

    const hito = HITOS_AVISO.find((h) => faltan <= h);
    if (hito === undefined) continue;
    // `warnedAt` guarda el hito, no una fecha: así el de 30 se manda aunque ya se haya
    // mandado el de 75.
    if (reg.warnedAt === String(hito)) continue;

    try {
      await sendTemplate(reg.ownerEmail, domainRenewalUpcoming({
        domain: reg.domainName,
        expiresAt: reg.expiresAt!,
        priceCents: reg.renewalPriceCents ?? TLD_PRICES[reg.tld]?.renewMxnCents ?? reg.priceCents,
        hasSubscription: reg.renewalStatus === "active",
      }));
      updateDomainRegistration(reg.id, { warnedAt: String(hito) });
      log("info", "cron", "Aviso de renovación enviado", { domain: reg.domainName, hito });
    } catch (err) {
      log("error", "cron", "No se pudo avisar de la renovación", { domain: reg.domainName, error: String(err) });
    }
  }
}

/**
 * Cobranza de los dominios en `past_due`. **Nunca automatiza la pérdida del dominio**: a los
 * 21 días deja de insistir y le pasa la decisión a una persona.
 */
export async function cobranzaDominios(): Promise<void> {
  const regs = getDomainRegistrationsByStatus("registered").filter((r) => r.renewalStatus === "past_due");
  if (!regs.length) return;

  const { sendTemplate, domainChargeFailed } = await import("./emails.js");
  const { sendAlert } = await import("./ses.js");

  for (const reg of regs) {
    const desde = reg.dunningStartedAt ? Math.floor((Date.now() - Date.parse(reg.dunningStartedAt)) / DIA) : 0;

    if (desde >= DIAS_HASTA_DECISION_HUMANA) {
      await sendAlert(
        "cobranza-dominio",
        `${reg.domainName} (${reg.ownerEmail}) lleva ${desde} días sin poder cobrarse y vence ${reg.expiresAt ?? "?"}.\n\nDecide: se le insiste, se le ofrece transfer-out, o se asume el costo. NO lo dejes vencer sin decidirlo.`,
      );
      continue;
    }

    if (!HITOS_COBRANZA.includes(desde)) continue;

    try {
      await sendTemplate(reg.ownerEmail, domainChargeFailed({
        domain: reg.domainName,
        attemptedCents: reg.renewalPriceCents ?? TLD_PRICES[reg.tld]?.renewMxnCents ?? reg.priceCents,
        expiresAt: reg.expiresAt,
      }));
      log("info", "cron", "Recordatorio de cobranza enviado", { domain: reg.domainName, dia: desde });
    } catch (err) {
      log("error", "cron", "No se pudo mandar el recordatorio de cobranza", { domain: reg.domainName, error: String(err) });
    }
  }
}

/**
 * Espejo de la reconciliación de add-ons: MercadoPago a veces pierde el `notification_url`
 * y el webhook nunca llega.
 */
export async function reconcileDomainRenewals(): Promise<void> {
  const token = process.env.MP_ACCESS_TOKEN;
  if (!token) return;

  const pendientes = getDomainRegistrationsByStatus("registered")
    .filter((r: DomainRegistration) => r.mpPreapprovalId && r.renewalStatus === "none");
  if (!pendientes.length) return;

  for (const reg of pendientes) {
    try {
      const res = await fetch(`https://api.mercadopago.com/preapproval/${reg.mpPreapprovalId}`, {
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) continue;
      const sub = await res.json();
      if (sub.status === "authorized") {
        updateDomainRegistration(reg.id, {
          renewalStatus: "active",
          nextChargeAt: sub.auto_recurring?.start_date ?? reg.nextChargeAt,
        });
        log("info", "billing", "Renovación de dominio activada por reconciliación", { domain: reg.domainName });
      }
    } catch (err) {
      log("error", "cron", "Reconciliación de renovación falló", { domain: reg.domainName, error: String(err) });
    }
  }
}
