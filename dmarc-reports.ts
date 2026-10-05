// Reportes agregados de DMARC (rua) de nuestros propios dominios. Sólo uso interno:
// nada de UI, SDK ni MCP para clientes.
//
// Google, Microsoft y demás mandan cada día un XML (en .zip o .gz) a la dirección del
// `rua` diciendo qué IPs enviaron correo como nuestro dominio y si pasaron SPF/DKIM.
// Aquí se reciben, se guardan y cada lunes sale un resumen a admin. Sin ese dato no se
// puede subir `p=none` a `quarantine` sin riesgo de mandar a spam correo legítimo.

import { randomUUID } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { reverse } from "node:dns/promises";
import PostalMime from "postal-mime";
import { unzipSync } from "fflate";
import { XMLParser } from "fast-xml-parser";
import { and, gte, lt, inArray } from "drizzle-orm";
import { db } from "./pg.js";
import { dmarcReports, dmarcRecords } from "./schema.js";
import { log } from "./logger.js";

// Topes contra zip bombs y reportes absurdos. Un reporte diario de Google para un
// dominio chico pesa unos KB; estos márgenes sobran por mucho.
const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024;
const MAX_UNCOMPRESSED_BYTES = 20 * 1024 * 1024;
const MAX_RECORDS = 10_000;

/** Dirección completa del `rua`. Los clientes usan `dmarc@<su dominio>` y siguen el camino normal. */
export function dmarcReportAddress(): string {
  return (process.env.DMARC_REPORT_ADDRESS ?? "dmarc@mailmask.studio").toLowerCase();
}

export interface DmarcRecord {
  sourceIp: string;
  count: number;
  disposition: string | null;
  dkimPass: boolean;
  spfPass: boolean;
  headerFrom: string | null;
  dkimDomain: string | null;
  spfDomain: string | null;
}

export interface DmarcReport {
  orgName: string;
  reportId: string;
  domain: string;
  policy: string | null;
  dateBegin: string;
  dateEnd: string;
  records: DmarcRecord[];
}

const parser = new XMLParser({
  ignoreAttributes: true,
  // Sin esto `report_id` numérico pierde precisión y `count` llega como número o texto
  // según el reportero; se convierte a mano.
  parseTagValue: false,
  processEntities: false,
  isArray: (name, jpath) =>
    jpath === "feedback.record"
    || jpath === "feedback.record.auth_results.dkim"
    || jpath === "feedback.record.auth_results.spf",
});

function str(v: unknown): string | null {
  if (v === undefined || v === null) return null;
  const s = String(v).trim();
  return s ? s : null;
}

function epochToIso(v: unknown): string {
  const n = Number(str(v));
  if (!Number.isFinite(n) || n <= 0) throw new Error(`date_range inválido: ${String(v)}`);
  return new Date(n * 1000).toISOString();
}

export function parseDmarcXml(xml: string): DmarcReport {
  const doc = parser.parse(xml);
  const fb = doc?.feedback;
  if (!fb || typeof fb !== "object") throw new Error("No es un reporte DMARC: falta <feedback>");
  const meta = fb.report_metadata ?? {};
  const orgName = str(meta.org_name);
  const reportId = str(meta.report_id);
  const domain = str(fb.policy_published?.domain)?.toLowerCase();
  if (!orgName || !reportId || !domain) throw new Error("Reporte DMARC sin org_name, report_id o dominio");

  const rawRecords: any[] = fb.record ?? [];
  if (rawRecords.length > MAX_RECORDS) throw new Error(`Reporte DMARC con ${rawRecords.length} records (tope ${MAX_RECORDS})`);

  const records: DmarcRecord[] = rawRecords.map((r) => {
    const row = r?.row ?? {};
    const pe = row.policy_evaluated ?? {};
    const dkim: any[] = r?.auth_results?.dkim ?? [];
    const spf: any[] = r?.auth_results?.spf ?? [];
    // Del lado de auth_results interesa el dominio que firmó/pasó, si alguno pasó.
    const dkimHit = dkim.find((d) => str(d?.result) === "pass") ?? dkim[0];
    const spfHit = spf.find((s) => str(s?.result) === "pass") ?? spf[0];
    const count = Number(str(row.count) ?? "0");
    return {
      sourceIp: str(row.source_ip) ?? "desconocida",
      count: Number.isFinite(count) && count > 0 ? Math.floor(count) : 0,
      disposition: str(pe.disposition),
      // Lo evaluado por la política ya considera la alineación; eso decide DMARC.
      dkimPass: str(pe.dkim) === "pass",
      spfPass: str(pe.spf) === "pass",
      headerFrom: str(r?.identifiers?.header_from)?.toLowerCase() ?? null,
      dkimDomain: str(dkimHit?.domain)?.toLowerCase() ?? null,
      spfDomain: str(spfHit?.domain)?.toLowerCase() ?? null,
    };
  });

  return {
    orgName,
    reportId,
    domain,
    policy: str(fb.policy_published?.p),
    dateBegin: epochToIso(meta.date_range?.begin),
    dateEnd: epochToIso(meta.date_range?.end),
    records,
  };
}

function toBytes(content: ArrayBuffer | Uint8Array | string): Uint8Array {
  if (typeof content === "string") return new TextEncoder().encode(content);
  return content instanceof Uint8Array ? content : new Uint8Array(content);
}

/** Saca los XML de un adjunto .zip, .gz o .xml, con los topes de tamaño. */
export function extractXmlFromAttachment(filename: string, mimeType: string, content: ArrayBuffer | Uint8Array | string): string[] {
  const bytes = toBytes(content);
  if (bytes.byteLength > MAX_ATTACHMENT_BYTES) throw new Error(`Adjunto DMARC de ${bytes.byteLength} bytes (tope ${MAX_ATTACHMENT_BYTES})`);
  const name = filename.toLowerCase();
  const mime = mimeType.toLowerCase();
  const decoder = new TextDecoder();

  // Por la firma y no sólo por el nombre: hay reporteros que mandan `.zip` como
  // `application/octet-stream`.
  const isZip = bytes[0] === 0x50 && bytes[1] === 0x4b;
  const isGzip = bytes[0] === 0x1f && bytes[1] === 0x8b;

  if (isZip || name.endsWith(".zip") || mime.includes("zip") && !mime.includes("gzip")) {
    let total = 0;
    const files = unzipSync(bytes, {
      filter: (f) => {
        if (!f.name.toLowerCase().endsWith(".xml")) return false;
        total += f.originalSize;
        if (total > MAX_UNCOMPRESSED_BYTES) throw new Error(`Zip DMARC descomprime a más de ${MAX_UNCOMPRESSED_BYTES} bytes`);
        return true;
      },
    });
    return Object.values(files).map((f) => decoder.decode(f));
  }
  if (isGzip || name.endsWith(".gz") || mime.includes("gzip")) {
    // `maxOutputLength` corta la descompresión ahí mismo: una bomba no llega a la memoria.
    const out = gunzipSync(bytes, { maxOutputLength: MAX_UNCOMPRESSED_BYTES });
    return [decoder.decode(out)];
  }
  if (name.endsWith(".xml") || mime.includes("xml")) return [decoder.decode(bytes)];
  return [];
}

/** Guarda un reporte. Devuelve false si ya estaba (mismo reportero y mismo report_id). */
export function saveDmarcReport(report: DmarcReport, receivedAt = new Date().toISOString()): boolean {
  return db.transaction((tx) => {
    const id = randomUUID();
    const inserted = tx.insert(dmarcReports).values({
      id,
      orgName: report.orgName,
      reportId: report.reportId,
      domain: report.domain,
      policy: report.policy,
      dateBegin: report.dateBegin,
      dateEnd: report.dateEnd,
      receivedAt,
    }).onConflictDoNothing().returning({ id: dmarcReports.id }).all();
    if (inserted.length === 0) return false;
    // En lotes: SQLite tiene tope de variables por sentencia.
    for (let i = 0; i < report.records.length; i += 200) {
      const chunk = report.records.slice(i, i + 200).map((r) => ({ ...r, reportId: id }));
      tx.insert(dmarcRecords).values(chunk).run();
    }
    return true;
  });
}

/**
 * Procesa el correo crudo que llegó al `rua`. Lanza si no pudo sacar ningún reporte;
 * el que llama loguea y sigue: un XML basura no debe tumbar el resto del inbound.
 */
export async function ingestDmarcReport(raw: string): Promise<{ saved: number; duplicates: number; failed: number }> {
  const parsed = await PostalMime.parse(raw);
  const xmls: string[] = [];
  const errors: string[] = [];
  for (const att of parsed.attachments ?? []) {
    try {
      xmls.push(...extractXmlFromAttachment(att.filename ?? "", att.mimeType ?? "", att.content as ArrayBuffer | string));
    } catch (err) {
      errors.push(String(err));
    }
  }

  let saved = 0;
  let duplicates = 0;
  for (const xml of xmls) {
    try {
      const report = parseDmarcXml(xml);
      if (saveDmarcReport(report)) saved++;
      else duplicates++;
    } catch (err) {
      errors.push(String(err));
    }
  }

  if (saved + duplicates === 0) {
    throw new Error(errors.length ? errors.join("; ") : "El correo no trae ningún reporte DMARC");
  }
  if (errors.length) log("warn", "dmarc", "Reporte DMARC parcialmente ilegible", { errors });
  log("info", "dmarc", "Reporte DMARC recibido", { saved, duplicates, from: parsed.from?.address });
  return { saved, duplicates, failed: errors.length };
}

// --- Resumen semanal ---

export interface DmarcSource {
  sourceIp: string;
  hostname: string | null;
  /** Etiqueta de lo que reconocemos como nuestro o de un proveedor conocido. */
  known: string | null;
  total: number;
  passed: number;
  failed: number;
}

export interface DmarcDigest {
  weekStart: string;
  weekEnd: string;
  reports: number;
  reporters: string[];
  domains: string[];
  total: number;
  passed: number;
  /** Porcentaje alineado (0–100) o null si no hubo mensajes. */
  alignedPct: number | null;
  previousAlignedPct: number | null;
  sources: DmarcSource[];
  failing: DmarcSource[];
  /** Fuentes que reconocemos como legítimas y aun así fallan DMARC. */
  legitFailing: DmarcSource[];
  readyForQuarantine: boolean;
  verdict: string;
}

const KNOWN_HOSTS: [RegExp, string][] = [
  [/\.amazonses\.com$/, "SES (nosotros)"],
  [/\.(google\.com|googleusercontent\.com)$/, "Google"],
  [/\.(outlook\.com|protection\.outlook\.com|hotmail\.com)$/, "Microsoft"],
];

function knownLabel(hostname: string | null): string | null {
  if (!hostname) return null;
  for (const [re, label] of KNOWN_HOSTS) if (re.test(hostname)) return label;
  return null;
}

const rdnsCache = new Map<string, string | null>();

/** Reverse DNS con caché y tope de tiempo: un PTR que no contesta no debe colgar el resumen. */
async function reverseLookup(ip: string, timeoutMs = 3000): Promise<string | null> {
  if (rdnsCache.has(ip)) return rdnsCache.get(ip)!;
  let host: string | null = null;
  try {
    const timeout = new Promise<null>((resolve) => setTimeout(() => resolve(null), timeoutMs).unref());
    const names = await Promise.race([reverse(ip), timeout]);
    host = names?.[0]?.toLowerCase() ?? null;
  } catch {
    host = null;
  }
  rdnsCache.set(ip, host);
  return host;
}

type Totals = { reports: number; reporters: Set<string>; domains: Set<string>; byIp: Map<string, { total: number; passed: number }> };

function aggregate(since: Date, until: Date): Totals {
  const reports = db.select().from(dmarcReports)
    .where(and(gte(dmarcReports.receivedAt, since.toISOString()), lt(dmarcReports.receivedAt, until.toISOString())))
    .all();
  const byIp = new Map<string, { total: number; passed: number }>();
  if (reports.length) {
    const ids = reports.map((r) => r.id);
    for (let i = 0; i < ids.length; i += 500) {
      const rows = db.select().from(dmarcRecords).where(inArray(dmarcRecords.reportId, ids.slice(i, i + 500))).all();
      for (const r of rows) {
        const agg = byIp.get(r.sourceIp) ?? { total: 0, passed: 0 };
        agg.total += r.count;
        if (r.dkimPass || r.spfPass) agg.passed += r.count;
        byIp.set(r.sourceIp, agg);
      }
    }
  }
  return {
    reports: reports.length,
    reporters: new Set(reports.map((r) => r.orgName)),
    domains: new Set(reports.map((r) => r.domain)),
    byIp,
  };
}

function pct(passed: number, total: number): number | null {
  return total > 0 ? Math.round((passed / total) * 1000) / 10 : null;
}

const READY_PCT = 99;

/**
 * Arma el resumen de los 7 días previos a `now` (por fecha de recepción del reporte).
 * `lookup` se inyecta en las pruebas para no depender del DNS real.
 */
export async function computeDmarcDigest(
  now = new Date(),
  lookup: (ip: string) => Promise<string | null> = reverseLookup,
): Promise<DmarcDigest> {
  const weekEnd = now;
  const weekStart = new Date(now.getTime() - 7 * 86400_000);
  const prevStart = new Date(now.getTime() - 14 * 86400_000);
  const cur = aggregate(weekStart, weekEnd);
  const prev = aggregate(prevStart, weekStart);

  const sources: DmarcSource[] = [];
  for (const [ip, agg] of cur.byIp) {
    const hostname = await lookup(ip);
    sources.push({ sourceIp: ip, hostname, known: knownLabel(hostname), total: agg.total, passed: agg.passed, failed: agg.total - agg.passed });
  }
  sources.sort((a, b) => b.total - a.total);

  const total = sources.reduce((s, x) => s + x.total, 0);
  const passed = sources.reduce((s, x) => s + x.passed, 0);
  let prevTotal = 0, prevPassed = 0;
  for (const a of prev.byIp.values()) { prevTotal += a.total; prevPassed += a.passed; }

  const alignedPct = pct(passed, total);
  const previousAlignedPct = pct(prevPassed, prevTotal);
  const failing = sources.filter((s) => s.failed > 0).sort((a, b) => b.failed - a.failed);
  const legitFailing = failing.filter((s) => s.known === "SES (nosotros)");

  const readyForQuarantine = alignedPct !== null && previousAlignedPct !== null
    && alignedPct >= READY_PCT && previousAlignedPct >= READY_PCT && legitFailing.length === 0;

  let verdict: string;
  if (cur.reports === 0) {
    verdict = "No llegó ningún reporte DMARC esta semana. Revisa que el registro _dmarc siga teniendo el rua y que el correo a la dirección llegue.";
  } else if (readyForQuarantine) {
    verdict = `Listo para quarantine: dos semanas seguidas con ${READY_PCT}% o más alineado y ninguna fuente nuestra fallando.`;
  } else {
    const missing: string[] = [];
    if (alignedPct === null || alignedPct < READY_PCT) missing.push(`esta semana va ${alignedPct ?? 0}% alineado (hace falta ${READY_PCT}%)`);
    if (previousAlignedPct === null) missing.push("falta una semana previa con datos para comparar");
    else if (previousAlignedPct < READY_PCT) missing.push(`la semana pasada fue ${previousAlignedPct}%`);
    if (legitFailing.length) missing.push(`${legitFailing.length} fuente(s) nuestra(s) fallan DMARC`);
    verdict = `Todavía no para quarantine: ${missing.join("; ")}.`;
  }

  return {
    weekStart: weekStart.toISOString(),
    weekEnd: weekEnd.toISOString(),
    reports: cur.reports,
    reporters: [...cur.reporters].sort(),
    domains: [...cur.domains].sort(),
    total,
    passed,
    alignedPct,
    previousAlignedPct,
    sources,
    failing,
    legitFailing,
    readyForQuarantine,
    verdict,
  };
}

/** Lo llama el cron de los lunes. */
export async function sendDmarcWeeklyDigest(now = new Date()): Promise<void> {
  const digest = await computeDmarcDigest(now);
  const { sendTemplate, dmarcWeeklyDigest } = await import("./emails.js");
  await sendTemplate(process.env.ALERT_EMAIL ?? "admin@mailmask.studio", dmarcWeeklyDigest(digest));
  log("info", "dmarc", "Resumen DMARC semanal enviado", { reports: digest.reports, total: digest.total, alignedPct: digest.alignedPct });
}
