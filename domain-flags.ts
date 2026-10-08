/**
 * Banderas `mxConfigured` y `verified` de un dominio: quién las escribe y cuánto valen.
 *
 * Existe por el 7-oct-2026: un agente le dijo a bliss que 5 de sus 6 dominios «no tenían
 * el MX configurado» y que ghosty.page «no estaba verificado». Era falso. `list_domains`
 * devolvía banderas guardadas que nadie revisaba: `mxConfigured` sólo se escribía al
 * comprar el dominio por MailMask (uno dado de alta a mano se quedaba en `false` para
 * siempre) y `verified` sólo cambiaba si alguien corría health o verify.
 *
 * Ahora health, verify y el arranque del servidor escriben las dos banderas con lo que
 * ven en vivo, más `healthCheckedAt`. La lista las expone con su fecha y, si la revisión
 * es vieja o nunca se hizo, como `unknown`: un dato viejo dicho con seguridad es peor
 * que un «no sé, confírmalo con domain_health».
 */
import * as dns from "node:dns/promises";
import { SES_INBOUND_HOST } from "./dns-setup.js";
import { checkDomainStatus } from "./ses.js";
import { updateDomain, type Domain } from "./db.js";

/** Pasado esto, la bandera guardada ya no se afirma: sale `unknown`. */
export const FLAGS_TTL_MS = 24 * 3600_000;

export type FlagStatus = "ok" | "missing" | "unknown";

export const FLAGS_STALE_NOTE = "Estado sin revisión reciente: confírmalo con domain_health antes de afirmar que algo falla.";

export interface MxCheck {
  ok: boolean;
  detail: string;
  /** false si no se pudo preguntar al DNS (timeout, SERVFAIL): no hay dato nuevo. */
  resolved: boolean;
}

/** Decide si un juego de MX entrega a SES. Puro, para poder probarlo sin red. */
export function evaluateInboundMx(records: { priority: number; exchange: string }[]): { ok: boolean; detail: string } {
  const sesRecord = records.find(r => r.exchange.toLowerCase().replace(/\.$/, "") === SES_INBOUND_HOST);
  if (!sesRecord) {
    return { ok: false, detail: `MX no apunta a MailMask. Registros actuales: ${records.map(r => `${r.priority} ${r.exchange}`).join(", ") || "ninguno"}` };
  }
  const higherPriority = records.filter(r => r.priority < sesRecord.priority && r.exchange.toLowerCase().replace(/\.$/, "") !== SES_INBOUND_HOST);
  if (higherPriority.length > 0) {
    return { ok: false, detail: `MX de SES tiene prioridad ${sesRecord.priority}, pero hay otros con mayor prioridad: ${higherPriority.map(r => `${r.priority} ${r.exchange}`).join(", ")}` };
  }
  return { ok: true, detail: `MX configurado correctamente (prioridad ${sesRecord.priority})` };
}

type MxResolver = (name: string) => Promise<{ priority: number; exchange: string }[]>;

export async function checkInboundMx(domain: string, resolveMx: MxResolver = dns.resolveMx): Promise<MxCheck> {
  try {
    return { ...evaluateInboundMx(await resolveMx(domain)), resolved: true };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    // NODATA/NOTFOUND es una respuesta: el dominio no tiene MX. Lo demás es no saber.
    if (code === "ENODATA" || code === "ENOTFOUND") {
      return { ok: false, detail: "No se encontraron registros MX", resolved: true };
    }
    return { ok: false, detail: `No se pudo consultar el MX (${code ?? "error"})`, resolved: false };
  }
}

/**
 * Guarda lo que se acaba de medir. `checkedAt` sólo avanza si las dos fuentes
 * respondieron: con una sola, la otra bandera seguiría vieja bajo una fecha nueva.
 */
export function saveDomainFlags(
  d: Domain,
  measured: { verified?: boolean | null; mxConfigured?: boolean | null },
): Domain | null {
  const updates: Partial<Pick<Domain, "verified" | "mxConfigured" | "healthCheckedAt">> = {};
  if (typeof measured.verified === "boolean") updates.verified = measured.verified;
  if (typeof measured.mxConfigured === "boolean") updates.mxConfigured = measured.mxConfigured;
  if (updates.verified !== undefined && updates.mxConfigured !== undefined) {
    updates.healthCheckedAt = new Date().toISOString();
  }
  return updateDomain(d.id, updates);
}

/** Corre la parte de health que alimenta las banderas (SES + MX) y las guarda. No toca DNS. */
export async function refreshDomainFlags(d: Domain): Promise<{ verified: boolean | null; mxConfigured: boolean | null }> {
  const [ses, mx] = await Promise.all([checkDomainStatus(d.domain), checkInboundMx(d.domain)]);
  const measured = {
    verified: ses.respondio ? ses.verified : null,
    mxConfigured: mx.resolved ? mx.ok : null,
  };
  saveDomainFlags(d, measured);
  return measured;
}

/** Lo que la lista dice de las banderas: su fecha y si todavía se pueden afirmar. */
export function domainFlagStatus(d: Domain, now = Date.now()): {
  checkedAt: string | null;
  mxStatus: FlagStatus;
  verifiedStatus: FlagStatus;
  statusNote?: string;
} {
  const checkedAt = d.healthCheckedAt ?? null;
  const fresh = checkedAt !== null && now - Date.parse(checkedAt) <= FLAGS_TTL_MS;
  if (!fresh) return { checkedAt, mxStatus: "unknown", verifiedStatus: "unknown", statusNote: FLAGS_STALE_NOTE };
  return {
    checkedAt,
    mxStatus: d.mxConfigured ? "ok" : "missing",
    verifiedStatus: d.verified ? "ok" : "missing",
  };
}
