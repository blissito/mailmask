// Auditoría de una zona DNS: mide qué sigue vivo y clasifica cada registro para podar sin adivinar.
// La usa el agente (`audit_dns_records`) para no inventarse qué sirve: antes le preguntaba al usuario
// lo que se podía medir y culpaba a la importación de nombres que ya venían así del proveedor anterior.
import * as nodeDns from "node:dns/promises";
import * as net from "node:net";
import type { RRSetAnotado } from "./dns-records.js";

export type AuditVerdict =
  | "takeover_risk"
  | "duplicated_name"
  | "not_responding"
  | "previous_provider"
  | "cert_validation"
  | "in_use"
  | "keep";

export interface AuditFinding {
  /** Nombre completo (FQDN): es el que hay que pasar para borrar. Nunca recortarlo: en un duplicado, recortado nombra al registro bueno. */
  name: string;
  type: string;
  values: string[];
  verdict: AuditVerdict;
  /** Lo que se midió, en español, para enseñárselo al usuario. */
  evidence: string;
  /** Qué conviene hacer, en español. */
  action: string;
}

export interface DnsAudit {
  domain: string;
  checkedAt: string;
  summary: Partial<Record<AuditVerdict, number>>;
  findings: AuditFinding[];
  /** true si se cortó por el tope de registros o de tiempo. */
  truncated: boolean;
  note: string;
}

export interface AuditDeps {
  resolve4(host: string): Promise<string[]>;
  resolveCname(host: string): Promise<string[]>;
  /** GET sin seguir redirects; devuelve estado y los primeros KB del cuerpo, o null si no respondió. */
  httpGet(url: string): Promise<{ status: number; body: string } | null>;
  /** true si el puerto acepta conexión. */
  tcpOpen(ip: string, port: number): Promise<boolean>;
}

const ORDER: AuditVerdict[] = ["takeover_risk", "duplicated_name", "not_responding", "previous_provider", "cert_validation", "in_use", "keep"];
const MAX_RECORDS = 120;
const BUDGET_MS = 30_000;
const CONCURRENCY = 6;

// Proveedores donde un destino abandonado lo puede reclamar otra persona. `body` = huella de «no existe»;
// `nxdomain` = el nombre del proveedor deja de existir y cualquiera lo vuelve a crear.
const TAKEOVER_PROVIDERS: { name: string; host: RegExp; body?: RegExp; nxdomain?: boolean }[] = [
  { name: "Heroku", host: /\.herokuapp\.com$|\.herokudns\.com$/, body: /no-such-app|There's nothing here, yet|no such app/i, nxdomain: true },
  { name: "GitHub Pages", host: /\.github\.io$/, body: /There isn't a GitHub Pages site here/i },
  { name: "Amazon S3", host: /\.s3[.-].*amazonaws\.com$|\.s3\.amazonaws\.com$/, body: /NoSuchBucket/i },
  { name: "Elastic Beanstalk", host: /\.elasticbeanstalk\.com$/, nxdomain: true },
  { name: "Netlify", host: /\.netlify\.(app|com)$/, body: /Not Found - Request ID/i },
  { name: "Vercel", host: /\.vercel\.app$|cname\.vercel-dns\.com$/, body: /DEPLOYMENT_NOT_FOUND/i },
  { name: "Firebase", host: /\.(web\.app|firebaseapp\.com)$/, body: /Site Not Found/i },
  { name: "Azure", host: /\.(azurewebsites\.net|cloudapp\.net|cloudapp\.azure\.com|trafficmanager\.net|blob\.core\.windows\.net)$/, nxdomain: true },
  { name: "Shopify", host: /\.myshopify\.com$/, body: /Sorry, this shop is currently unavailable/i },
];

// Alias que ponen los hostings compartidos (cPanel de GoDaddy, Hostinger…) y que dejan de servir al irse.
const HOSTING_ALIASES = new Set(["cpanel", "whm", "webdisk", "webmail", "cpcalendars", "cpcontacts"]);
const PREVIOUS_PROVIDERS: { name: string; ns: RegExp }[] = [
  { name: "GoDaddy", ns: /domaincontrol\.com$/ },
  { name: "Hostinger", ns: /dns-parking\.com$|hostinger\./ },
];

const stripDot = (s: string) => s.trim().toLowerCase().replace(/\.$/, "");

export function isPrivateIp(ip: string): boolean {
  if (net.isIPv6(ip)) return /^(::1$|fc|fd|fe80)/i.test(ip);
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return true;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 127 || a === 10 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
}

function isNxdomain(err: unknown): boolean {
  const code = (err as { code?: string })?.code;
  return code === "ENOTFOUND" || code === "ENODATA" || code === "NXDOMAIN";
}

/** Primer nombre que pertenece a la zona: con `x.dominio.dominio` el registro nunca se consulta así. */
function isDuplicatedName(name: string, apex: string): boolean {
  return name.endsWith(`.${apex}.${apex}`) || name === `${apex}.${apex}`;
}

function label(name: string, apex: string): string {
  return name === apex ? "@" : name.slice(0, -(apex.length + 1));
}

function isMailOrVerification(r: RRSetAnotado, apex: string): boolean {
  const sub = label(r.name, apex);
  if (["TXT", "MX", "SRV", "CAA"].includes(r.type)) return true;
  if (/(^|\.)_domainkey$|^_dmarc$|^_mta-sts$|^autodiscover$|^autoconfig$/.test(sub)) return true;
  // Marca de enlaces y rebotes de SendGrid, Mailgun y similares
  return r.values.some((v) => /sendgrid\.net\.?$|mailgun\.org\.?$|mandrillapp\.com\.?$|mcsv\.net\.?$|amazonses\.com\.?$/i.test(v));
}

async function pool<T, R>(items: T[], n: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (next < items.length) { const i = next++; out[i] = await fn(items[i]); }
  }));
  return out;
}

async function anyHostAlive(ips: string[], deps: AuditDeps): Promise<boolean> {
  for (const ip of ips) {
    if (isPrivateIp(ip)) continue;
    if (await deps.tcpOpen(ip, 443) || await deps.tcpOpen(ip, 80)) return true;
  }
  return false;
}

async function auditOne(r: RRSetAnotado, apex: string, previousProvider: string | null, names: Set<string>, deps: AuditDeps): Promise<AuditFinding> {
  const base = { name: r.name, type: r.type, values: r.values };
  const sub = label(r.name, apex);

  if (isDuplicatedName(r.name, apex)) {
    return { ...base, verdict: "duplicated_name", evidence: `El nombre repite el dominio (${r.name}); ya venía así de tu proveedor anterior y nadie lo consulta con ese nombre. El registro bueno, ${r.name.slice(0, -(apex.length + 1))}, es otro y no se toca.`, action: `Bórralo con su nombre completo, ${r.name}.` };
  }

  if (sub === "_domainconnect" && previousProvider) {
    return { ...base, verdict: "previous_provider", evidence: `Es de ${previousProvider} para configurar servicios en un clic; tus nameservers ya están en MailMask.`, action: "Bórralo." };
  }

  const isCertValidation = (r.type === "CNAME" && /^_[0-9a-f]{20,}\./.test(sub + "."))
    || r.values.some((v) => /acm-validations\.aws\.?$/i.test(v)) || sub.startsWith("_acme-challenge");
  if (isCertValidation) {
    const parent = r.name.split(".").slice(1).join(".");
    const parentExists = names.has(parent) || parent === apex;
    return parentExists
      ? { ...base, verdict: "cert_validation", evidence: `Valida el certificado de ${parent}.`, action: "Déjalo mientras uses ese certificado." }
      : { ...base, verdict: "cert_validation", evidence: `Valida el certificado de ${parent}, y ese nombre ya no existe en tu zona.`, action: "Bórralo." };
  }

  if (isMailOrVerification(r, apex)) {
    return { ...base, verdict: "keep", evidence: "Es de correo o de verificación de un servicio.", action: "No lo toques." };
  }

  if (r.type === "CNAME") {
    const target = stripDot(r.values[0] ?? "");
    const provider = TAKEOVER_PROVIDERS.find((p) => p.host.test(target));

    let targetIps: string[] = [];
    try {
      targetIps = await deps.resolve4(target);
    } catch (err) {
      if (isNxdomain(err)) {
        return provider
          ? { ...base, verdict: "takeover_risk", evidence: `Apunta a ${target} (${provider.name}) y ese nombre ya no existe: otra persona puede crearlo y servir su contenido en ${r.name}.`, action: "Bórralo ya." }
          : { ...base, verdict: "not_responding", evidence: `Apunta a ${target}, que ya no existe.`, action: "Bórralo." };
      }
    }

    if (sub === "ftp" || HOSTING_ALIASES.has(sub)) {
      if (previousProvider) return { ...base, verdict: "previous_provider", evidence: `Alias del hosting de ${previousProvider}.`, action: `Bórralo si ya no pagas el hosting de ${previousProvider}.` };
    }

    if (provider?.body && !targetIps.some(isPrivateIp)) {
      const res = await deps.httpGet(`https://${r.name}/`) ?? await deps.httpGet(`http://${r.name}/`);
      if (res && provider.body.test(res.body)) {
        return { ...base, verdict: "takeover_risk", evidence: `Apunta a ${target} y ${provider.name} contesta que esa app ya no existe (HTTP ${res.status}): otra persona puede reclamarla y servir su contenido en ${r.name}.`, action: "Bórralo ya." };
      }
      if (res) return { ...base, verdict: "in_use", evidence: `${provider.name} responde (HTTP ${res.status}).`, action: "Déjalo." };
    }

    if (targetIps.length && !(await anyHostAlive(targetIps, deps))) {
      return { ...base, verdict: "not_responding", evidence: `Apunta a ${target} y no contesta en los puertos 443 ni 80.`, action: "Revisa si todavía lo usas; si no, bórralo." };
    }
    return { ...base, verdict: "in_use", evidence: `Apunta a ${target} y responde.`, action: "Déjalo." };
  }

  if (r.type === "A" || r.type === "AAAA") {
    if (HOSTING_ALIASES.has(sub) && previousProvider) {
      return { ...base, verdict: "previous_provider", evidence: `Alias del hosting de ${previousProvider}.`, action: `Bórralo si ya no pagas el hosting de ${previousProvider}.` };
    }
    const ips = r.values.map(stripDot);
    if (ips.every(isPrivateIp)) {
      return { ...base, verdict: "not_responding", evidence: "Apunta a una IP privada que nadie fuera de tu red alcanza.", action: "Bórralo si no es a propósito." };
    }
    return await anyHostAlive(ips, deps)
      ? { ...base, verdict: "in_use", evidence: `${ips.join(", ")} responde.`, action: "Déjalo." }
      : { ...base, verdict: "not_responding", evidence: `${ips.join(", ")} no contesta en los puertos 443 ni 80. Si era un servidor de la nube y liberaste la IP, se la pueden asignar a otra persona.`, action: "Revisa si todavía lo usas; si no, bórralo." };
  }

  return { ...base, verdict: "keep", evidence: "Tipo de registro que no se audita.", action: "Déjalo." };
}

export async function auditDnsRecords(
  domain: { domain: string; dnsPreviousNs?: string[] | null },
  records: RRSetAnotado[],
  deps: AuditDeps = defaultDeps,
): Promise<DnsAudit> {
  const apex = stripDot(domain.domain);
  const previousProvider = PREVIOUS_PROVIDERS.find((p) => (domain.dnsPreviousNs ?? []).some((ns) => p.ns.test(stripDot(ns))))?.name ?? null;
  const candidates = records.filter((r) => !r.managed && !(r.name === apex && (r.type === "NS" || (r.type as string) === "SOA")));
  const names = new Set(records.map((r) => r.name));
  const truncatedByCount = candidates.length > MAX_RECORDS;
  const started = Date.now();
  let truncatedByTime = false;

  const results = await pool(candidates.slice(0, MAX_RECORDS), CONCURRENCY, async (r) => {
    if (Date.now() - started > BUDGET_MS) { truncatedByTime = true; return null; }
    try {
      return await auditOne(r, apex, previousProvider, names, deps);
    } catch {
      return { name: r.name, type: r.type, values: r.values, verdict: "keep" as const, evidence: "No se pudo medir.", action: "Déjalo." };
    }
  });

  const findings = results.filter((f): f is AuditFinding => !!f)
    .sort((a, b) => ORDER.indexOf(a.verdict) - ORDER.indexOf(b.verdict) || a.name.localeCompare(b.name));
  const summary: Partial<Record<AuditVerdict, number>> = {};
  for (const f of findings) summary[f.verdict] = (summary[f.verdict] ?? 0) + 1;

  return {
    domain: apex,
    checkedAt: new Date().toISOString(),
    summary,
    findings,
    truncated: truncatedByCount || truncatedByTime,
    note: "Todo lo importado se copió tal cual de tu proveedor anterior. «No contesta» es una medición de este momento, no una prueba: un servidor puede estar apagado a propósito. Los registros de correo de MailMask no se auditan porque no se pueden borrar.",
  };
}

// --- Dependencias reales ---

const defaultDeps: AuditDeps = {
  resolve4: (h) => nodeDns.resolve4(h),
  resolveCname: (h) => nodeDns.resolveCname(h),
  async httpGet(url) {
    try {
      const res = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(4000), headers: { "user-agent": "MailMask-DNS-Audit/1.0" } });
      const body = (await res.text()).slice(0, 64_000);
      return { status: res.status, body };
    } catch {
      return null;
    }
  },
  tcpOpen: (ip, port) => new Promise((resolve) => {
    const s = net.connect({ host: ip, port, timeout: 3000 });
    const done = (ok: boolean) => { s.destroy(); resolve(ok); };
    s.once("connect", () => done(true));
    s.once("timeout", () => done(false));
    s.once("error", () => done(false));
  }),
};

let activeDeps = defaultDeps;
/** Sólo pruebas: sin esto la ruta sondearía la red real. */
export function setDnsAuditDeps(deps: AuditDeps | null): void {
  activeDeps = deps ?? defaultDeps;
  cache.clear();
}

// Caché de 10 min por dominio y contenido de la zona: el agente suele llamarla dos veces en la misma
// charla, y si borró algo entre una y otra la zona cambió y se mide de nuevo.
const cache = new Map<string, { at: number; key: string; audit: DnsAudit }>();
export async function auditDnsRecordsCached(domainId: string, domain: { domain: string; dnsPreviousNs?: string[] | null }, records: RRSetAnotado[]): Promise<DnsAudit> {
  const key = JSON.stringify(records.map((r) => [r.name, r.type, r.values]));
  const hit = cache.get(domainId);
  if (hit && hit.key === key && Date.now() - hit.at < 10 * 60_000) return hit.audit;
  const audit = await auditDnsRecords(domain, records, activeDeps);
  cache.set(domainId, { at: Date.now(), key, audit });
  return audit;
}
