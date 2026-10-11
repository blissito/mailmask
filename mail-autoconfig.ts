// Autodescubrimiento de buzones en el dominio del cliente.
//
// Stalwart ya contesta el XML de Outlook (`/autodiscover/autodiscover.xml`) y el autoconfig
// de Thunderbird en `IMAP_HOST`, pero los clientes los buscan bajo el dominio del CORREO.
// Sin estos registros Outlook le pregunta a la nube de Microsoft y adivina por lo que
// queda del proveedor anterior: con kandey.com.mx (9-oct-2026) proponía `imap.hostinger`.
//
// Va UNA vez por dominio, no por buzón. Un CNAME `autodiscover.<dominio>` no sirve: Outlook
// entra por HTTPS y nuestro certificado no cubre el dominio del cliente. El SRV sí, porque
// Outlook valida el certificado del destino (`IMAP_HOST`).
import { IMAP_HOST } from "./apple-profile.js";
import { log } from "./logger.js";
import type { RRSet } from "./route53.js";

export function autoconfigRRSets(domain: string): RRSet[] {
  const d = domain.toLowerCase();
  return [
    { name: `_autodiscover._tcp.${d}`, type: "SRV", ttl: 3600, values: [`0 0 443 ${IMAP_HOST}`] },
    { name: `autoconfig.${d}`, type: "CNAME", ttl: 3600, values: [IMAP_HOST] },
  ];
}

/**
 * Crea los registros que falten en la zona que gestionamos. Lo que ya exista con ese
 * nombre se respeta: puede ser el Microsoft 365 del cliente, y pisarlo le rompe Outlook.
 * Nunca lanza: el buzón funciona igual sin esto.
 */
export async function ensureMailAutoconfig(d: { domain: string; hostedZoneId?: string | null }): Promise<number> {
  if (!d.hostedZoneId) return 0;
  try {
    // Import dinámico, como el resto de main.ts con route53: las pruebas lo sustituyen.
    const { listRecordSets, applyRecordChanges } = await import("./route53.js");
    const taken = new Set((await listRecordSets(d.hostedZoneId)).map((r) => r.name));
    const missing = autoconfigRRSets(d.domain).filter((r) => !taken.has(r.name));
    if (!missing.length) return 0;
    await applyRecordChanges(
      d.hostedZoneId,
      missing.map((rrset) => ({ action: "UPSERT" as const, rrset })),
      `Autodescubrimiento de buzones para ${d.domain}`,
    );
    log("info", "route53", "Autodescubrimiento de buzones creado", { domain: d.domain, records: missing.map((r) => r.name) });
    return missing.length;
  } catch (err) {
    log("error", "route53", "No se pudo crear el autodescubrimiento de buzones", { domain: d.domain, error: String(err) });
    return 0;
  }
}
