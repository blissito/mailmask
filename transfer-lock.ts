// Candado de transferencia (`clientTransferProhibited`) de los dominios registrados aquí.
//
// El patrón es el de Cloudflare y Porkbun, y el que dejaron claro los secuestros de
// Squarespace en 2024: protegido por defecto, quitarlo cuesta un paso fuera del panel (un
// correo), se vuelve a poner solo a los 7 días y el titular se entera siempre. Ponerlo, en
// cambio, es un clic desde cualquier lado — incluso desde un agente o un enlace sin sesión —
// porque la dirección segura nunca debe tener fricción.
import { eq } from "drizzle-orm";
import { db, getDomainRegistration, updateDomainRegistration, type DomainRegistration } from "./db.js";
import { tokens as tokensTable } from "./schema.js";
import { log } from "./logger.js";

const DIA = 864e5;
/** Cuánto dura quitado antes de volver solo. Alcanza para una transferencia normal. */
export const UNLOCK_DAYS = 7;
const CONFIRM_TTL_MS = 30 * 60_000;

/** Pone el candado en AWS y guarda lo que AWS reporta después, no lo que pedimos. */
export async function lockTransfer(reg: DomainRegistration): Promise<boolean> {
  const { enableDomainTransferLock, getDomainDetail } = await import("./route53.js");
  await enableDomainTransferLock(reg.domainName);
  const locked = await getDomainDetail(reg.domainName).then((d) => d.transferLock).catch(() => true);
  updateDomainRegistration(reg.id, { transferLock: locked, transferUnlockedUntil: null });
  log("info", "route53", "Candado de transferencia puesto", { domain: reg.domainName });
  return locked;
}

/** Guarda la petición de quitar el candado y devuelve el token del correo (30 min, un uso). */
export async function createUnlockToken(regId: string): Promise<string> {
  const token = crypto.randomUUID();
  await db.insert(tokensTable).values({
    token,
    kind: "transfer-unlock",
    value: { regId },
    expiresAt: new Date(Date.now() + CONFIRM_TTL_MS).toISOString(),
  });
  return token;
}

/** Consume un token de un solo uso del tipo indicado; null si no existe o venció. */
export function consumeToken(token: string, kind: string): { regId: string } | null {
  if (!token) return null;
  const fila = db.select().from(tokensTable).where(eq(tokensTable.token, token)).get();
  if (!fila || fila.kind !== kind || fila.expiresAt < new Date().toISOString()) return null;
  db.delete(tokensTable).where(eq(tokensTable.token, token)).run();
  return fila.value as { regId: string };
}

/**
 * Quita el candado por `UNLOCK_DAYS` y avisa al dueño y al contacto WHOIS con un enlace
 * que lo vuelve a poner sin iniciar sesión. Lo usan la confirmación del correo y el
 * transfer-out (que antes dejaba el dominio abierto para siempre si nadie lo terminaba).
 */
export async function unlockTransfer(reg: DomainRegistration): Promise<string> {
  const { disableDomainTransferLock } = await import("./route53.js");
  await disableDomainTransferLock(reg.domainName);
  const until = new Date(Date.now() + UNLOCK_DAYS * DIA).toISOString();
  updateDomainRegistration(reg.id, { transferLock: false, transferUnlockedUntil: until });

  // El enlace de "no fui yo" vive lo mismo que el desbloqueo y sólo sabe poner el candado.
  const relockToken = crypto.randomUUID();
  await db.insert(tokensTable).values({
    token: relockToken,
    kind: "transfer-relock",
    value: { regId: reg.id },
    expiresAt: until,
  });

  const { sendTemplate, domainUnlocked, baseUrl } = await import("./emails.js");
  const email = domainUnlocked({
    domain: reg.domainName,
    relockAt: until,
    relockUrl: `${baseUrl()}/api/domains/transfer-lock/relock?token=${relockToken}`,
  });
  const destinos = new Set([reg.ownerEmail.toLowerCase()]);
  if (reg.whoisContact?.email) destinos.add(reg.whoisContact.email.toLowerCase());
  for (const to of destinos) {
    await sendTemplate(to, email).catch((err) =>
      log("error", "route53", "No se pudo avisar del candado quitado", { domain: reg.domainName, to, error: String(err) }));
  }
  log("warn", "route53", "Candado de transferencia quitado", { domain: reg.domainName, until });
  return until;
}

/** El enlace "no fui yo": pone el candado sin sesión. Devuelve el dominio o null. */
export async function relockByToken(token: string): Promise<string | null> {
  const value = consumeToken(token, "transfer-relock");
  if (!value) return null;
  const reg = getDomainRegistration(value.regId);
  if (!reg || reg.status !== "registered") return null;
  await lockTransfer(reg);
  return reg.domainName;
}

/**
 * Paso del cron diario con el detalle que ya se leyó de AWS: guarda el estado, vuelve a
 * poner el candado vencido y alerta si alguien lo quitó por fuera de nuestro flujo.
 */
export async function reconcileTransferLock(
  reg: DomainRegistration,
  detalle: { transferLock: boolean; statusList: string[] },
): Promise<void> {
  const ahora = new Date().toISOString();
  const vigente = !!reg.transferUnlockedUntil && reg.transferUnlockedUntil > ahora;

  if (detalle.transferLock) {
    updateDomainRegistration(reg.id, { transferLock: true, ...(reg.transferUnlockedUntil ? { transferUnlockedUntil: null } : {}) });
    return;
  }

  if (vigente) {
    updateDomainRegistration(reg.id, { transferLock: false });
    return;
  }

  // Con una transferencia de salida en curso, poner el candado la tumbaría: se espera.
  if (detalle.statusList.some((s) => /pendingtransfer/i.test(s))) {
    updateDomainRegistration(reg.id, { transferLock: false });
    return;
  }

  if (reg.transferUnlockedUntil) {
    // Venció el plazo: se vuelve a poner solo.
    try {
      await lockTransfer(reg);
      const { sendTemplate, domainRelocked } = await import("./emails.js");
      await sendTemplate(reg.ownerEmail, domainRelocked({ domain: reg.domainName }));
    } catch (err) {
      updateDomainRegistration(reg.id, { transferLock: false });
      log("error", "cron", "No se pudo volver a poner el candado de transferencia", { domain: reg.domainName, error: String(err) });
    }
    return;
  }

  // Sin candado y sin fecha de regreso: nadie lo quitó por la app.
  updateDomainRegistration(reg.id, { transferLock: false });
  const { sendAlert } = await import("./ses.js");
  await sendAlert(
    `dominio-sin-candado:${reg.domainName}`,
    `AWS reporta ${reg.domainName} (${reg.ownerEmail}) SIN candado de transferencia y nadie lo quitó desde la app.\n\nSi no fue a propósito, vuelve a ponerlo: sin candado, quien tenga el código de autorización se lleva el dominio.`,
  );
}
