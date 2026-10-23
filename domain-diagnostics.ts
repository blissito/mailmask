// Diagnóstico de dominio para el agente: lo que la comunidad revisa con dig, DNSChecker, MXToolbox
// y un navegador, medido desde el servidor. Sin esto Mascarito decía «no tengo dig» o improvisaba en
// su caja; así cualquier cliente del MCP (dock, Claude, ChatGPT) mide lo mismo.
import * as nodeDns from "node:dns/promises";
import * as tls from "node:tls";
import { isIP } from "node:net";
import { isPrivateIp } from "./dns-audit.js";
import { fetchRdap, type RdapInfo } from "./rdap.js";

export const LOOKUP_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "CAA"] as const;
export type LookupType = (typeof LOOKUP_TYPES)[number];

export const PUBLIC_RESOLVERS: { name: string; ip: string }[] = [
  { name: "Google", ip: "8.8.8.8" },
  { name: "Cloudflare", ip: "1.1.1.1" },
  { name: "Quad9", ip: "9.9.9.9" },
];

export interface DiagnosticsDeps {
  /** Pregunta a un servidor concreto (ip) o al del sistema (null). Lanza con `code` si no hay respuesta. */
  resolve(server: string | null, name: string, type: LookupType | "A"): Promise<string[]>;
  tlsPeer(host: string, ip: string): Promise<{ issuer: string; validTo: string; altNames: string[] } | null>;
  httpHead(url: string): Promise<{ status: number; location: string | null } | null>;
  rdap(domain: string): Promise<RdapInfo | null>;
}

// --- 1. Consulta y propagación ---

export interface LookupResult {
  name: string;
  type: LookupType;
  answers: { server: string; values: string[] | null; error?: string }[];
  /** Todos los que contestaron dicen lo mismo. */
  propagated: boolean;
  /** Si la zona es de MailMask: lo público coincide con lo guardado. null si no hay zona nuestra. */
  matchesZone: boolean | null;
  summary: string;
}

const norm = (vs: string[]) => vs.map((v) => v.toLowerCase().replace(/\.$/, "").replace(/^"|"$/g, "")).sort().join("|");

export async function lookupDns(name: string, type: LookupType, opts: { zoneValues?: string[] | null; authoritative?: string[] } = {}, deps: DiagnosticsDeps = activeDeps): Promise<LookupResult> {
  const servers = [
    ...PUBLIC_RESOLVERS.map((r) => ({ label: `${r.name} (${r.ip})`, ip: r.ip })),
    ...(opts.authoritative ?? []).slice(0, 2).map((ns) => ({ label: `autoritativo ${ns}`, ip: ns })),
  ];
  const answers = await Promise.all(servers.map(async (s) => {
    try {
      return { server: s.label, values: await deps.resolve(s.ip, name, type) };
    } catch (err) {
      const code = (err as { code?: string })?.code ?? "ERROR";
      // NXDOMAIN/NODATA es una respuesta («no existe»), no una falla del servidor
      return code === "ENOTFOUND" || code === "ENODATA"
        ? { server: s.label, values: [] as string[] }
        : { server: s.label, values: null, error: code };
    }
  }));
  const answered = answers.filter((a) => a.values);
  const keys = new Set(answered.map((a) => norm(a.values!)));
  const propagated = answered.length > 0 && keys.size === 1;
  const publicValues = answered[0]?.values ?? [];
  const matchesZone = opts.zoneValues === undefined || opts.zoneValues === null ? null
    : propagated && norm(publicValues) === norm(opts.zoneValues);
  const summary = !answered.length ? "Ningún servidor contestó; intenta de nuevo en un momento."
    : !propagated ? "Los servidores no coinciden todavía: el cambio sigue propagándose (o hay cachés viejas). Suele tardar lo que dice el TTL."
    : !publicValues.length ? `Internet dice que ${name} no tiene registro ${type}.`
    : matchesZone === false ? "Internet ya coincide entre sí, pero no con lo guardado en MailMask: tus nameservers todavía no son los nuestros o el cambio es muy reciente."
    : `Internet ve lo mismo en todos los servidores: ${publicValues.join(", ")}.`;
  return { name, type, answers, propagated, matchesZone, summary };
}

// --- 2. HTTPS ---

export interface HttpsResult {
  host: string;
  ip: string | null;
  certificate: { issuer: string; validTo: string; daysLeft: number; coversHost: boolean } | null;
  redirects: { url: string; status: number }[];
  finalStatus: number | null;
  ok: boolean;
  summary: string;
}

function coversHost(host: string, altNames: string[]): boolean {
  return altNames.some((n) => n === host || (n.startsWith("*.") && host.endsWith(n.slice(1)) && host.split(".").length === n.split(".").length));
}

export async function checkHttps(host: string, deps: DiagnosticsDeps = activeDeps): Promise<HttpsResult> {
  const base = { host, ip: null as string | null, certificate: null, redirects: [] as { url: string; status: number }[], finalStatus: null as number | null };
  let ips: string[] = [];
  try { ips = await deps.resolve(null, host, "A"); } catch { /* sin A */ }
  const ip = ips.find((x) => !isPrivateIp(x)) ?? null;
  if (!ip) {
    return { ...base, ok: false, summary: ips.length ? `${host} apunta a una IP privada; no se revisa desde fuera.` : `${host} no tiene dirección IP: no hay web que revisar.` };
  }
  const peer = await deps.tlsPeer(host, ip);
  const certificate = peer ? {
    issuer: peer.issuer,
    validTo: new Date(peer.validTo).toISOString(),
    daysLeft: Math.floor((Date.parse(peer.validTo) - Date.now()) / 864e5),
    coversHost: coversHost(host, peer.altNames),
  } : null;

  // Redirecciones a mano: cada salto se reporta y nunca se sigue a una IP privada
  const redirects: { url: string; status: number }[] = [];
  let url = `https://${host}/`;
  let finalStatus: number | null = null;
  for (let i = 0; i < 5; i++) {
    const res = await deps.httpHead(url);
    if (!res) break;
    redirects.push({ url, status: res.status });
    finalStatus = res.status;
    if (res.status < 300 || res.status >= 400 || !res.location) break;
    const next = new URL(res.location, url);
    // un salto a una IP literal privada no se sigue (isPrivateIp trata un nombre como privado)
    if (isIP(next.hostname) && isPrivateIp(next.hostname)) break;
    url = next.toString();
  }

  const ok = !!certificate && certificate.daysLeft > 0 && certificate.coversHost && !!finalStatus && finalStatus < 400;
  const summary = !certificate ? `${host} no responde por HTTPS (no hay servidor en el 443 o no da certificado).`
    : certificate.daysLeft <= 0 ? `El certificado de ${host} venció el ${certificate.validTo.slice(0, 10)}.`
    : !certificate.coversHost ? `${host} responde con un certificado que no es suyo (de otro nombre): el navegador muestra «no es seguro». Pasa cuando el destino ya no sirve ese subdominio.`
    : finalStatus && finalStatus >= 400 ? `HTTPS válido (vence en ${certificate.daysLeft} días), pero la página responde ${finalStatus}.`
    : `HTTPS válido, de ${certificate.issuer}, vence en ${certificate.daysLeft} días${redirects.length > 1 ? `; redirige a ${redirects.at(-1)!.url}` : ""}.`;
  return { ...base, ip, certificate, redirects, finalStatus, ok, summary };
}

// --- 3. DMARC ---

export interface DmarcResult { ok: boolean; policy: string | null; rua: string | null; record: string | null; detail: string }

export async function checkDmarc(domain: string, deps: DiagnosticsDeps = activeDeps): Promise<DmarcResult> {
  let records: string[] = [];
  try { records = await deps.resolve(null, `_dmarc.${domain}`, "TXT"); } catch { /* sin registro */ }
  const record = records.map((r) => r.replace(/^"|"$/g, "")).find((r) => /^v=DMARC1/i.test(r)) ?? null;
  if (!record) return { ok: false, policy: null, rua: null, record: null, detail: "Sin DMARC: Gmail y Yahoo lo piden para entregar bien. Basta con «v=DMARC1; p=none» para empezar." };
  const policy = record.match(/;\s*p=([a-z]+)/i)?.[1]?.toLowerCase() ?? null;
  const rua = record.match(/rua=([^;]+)/i)?.[1]?.trim() ?? null;
  const detail = policy === "none" ? `DMARC en modo observación (p=none)${rua ? "" : ", sin reportes (rua)"}: protege poco contra suplantación, pero cumple lo que piden Gmail y Yahoo.`
    : policy === "quarantine" || policy === "reject" ? `DMARC con p=${policy}: los correos que suplanten tu dominio se ${policy === "reject" ? "rechazan" : "mandan a spam"}.`
    : "DMARC sin política válida (p=): revísalo.";
  return { ok: policy === "none" || policy === "quarantine" || policy === "reject", policy, rua, record, detail };
}

// --- 4. Listas negras de dominio ---

export interface BlocklistResult { ok: boolean; lists: { name: string; listed: boolean | null; detail: string }[]; detail: string }

const DOMAIN_BLOCKLISTS = [
  { name: "Spamhaus DBL", zone: "dbl.spamhaus.org" },
  { name: "SURBL", zone: "multi.surbl.org" },
];

export async function checkDomainBlocklists(domain: string, deps: DiagnosticsDeps = activeDeps): Promise<BlocklistResult> {
  const lists = await Promise.all(DOMAIN_BLOCKLISTS.map(async (l) => {
    try {
      const ans = await deps.resolve(null, `${domain}.${l.zone}`, "A");
      // 127.255.255.x = la lista rechazó la consulta (resolver público o sin cuota), no «listado»
      if (ans.some((a) => a.startsWith("127.255.255."))) return { name: l.name, listed: null, detail: "La lista no aceptó la consulta desde nuestro servidor." };
      const listed = ans.some((a) => a.startsWith("127."));
      return { name: l.name, listed, detail: listed ? `Listado (${ans.join(", ")})` : "Limpio" };
    } catch (err) {
      const code = (err as { code?: string })?.code;
      return code === "ENOTFOUND" || code === "ENODATA"
        ? { name: l.name, listed: false, detail: "Limpio" }
        : { name: l.name, listed: null, detail: "No se pudo consultar." };
    }
  }));
  const listedIn = lists.filter((l) => l.listed).map((l) => l.name);
  const unknown = lists.filter((l) => l.listed === null).map((l) => l.name);
  const detail = listedIn.length ? `En lista negra: ${listedIn.join(", ")}. Los correos con tu dominio pueden ir a spam; hay que pedir la baja en esa lista.`
    : unknown.length === lists.length ? "No se pudieron consultar las listas negras."
    : `Limpio en ${lists.filter((l) => l.listed === false).map((l) => l.name).join(" y ")}${unknown.length ? ` (sin respuesta de ${unknown.join(", ")})` : ""}.`;
  return { ok: !listedIn.length, lists, detail };
}

// --- 5. Registro (RDAP) ---

export interface RegistrationResult extends RdapInfo { domain: string; daysToExpire: number | null; transferLocked: boolean | null; summary: string }

export async function registrationInfo(domain: string, deps: DiagnosticsDeps = activeDeps): Promise<RegistrationResult> {
  const info = await deps.rdap(domain).catch(() => null);
  if (!info) {
    return { domain, registrar: null, createdAt: null, expiresAt: null, statuses: [], nameservers: [], daysToExpire: null, transferLocked: null, summary: "El registro del dominio no respondió (algunos TLD como .mx no publican RDAP)." };
  }
  const daysToExpire = info.expiresAt ? Math.floor((Date.parse(info.expiresAt) - Date.now()) / 864e5) : null;
  const transferLocked = info.statuses.length ? info.statuses.some((s) => /transfer prohibited/i.test(s)) : null;
  const summary = [
    info.registrar ? `Registrador: ${info.registrar}.` : null,
    daysToExpire !== null ? (daysToExpire < 0 ? `Venció hace ${-daysToExpire} días.` : `Vence el ${info.expiresAt!.slice(0, 10)} (en ${daysToExpire} días).`) : null,
    transferLocked === null ? null : transferLocked ? "Candado de transferencia puesto." : "Sin candado de transferencia.",
  ].filter(Boolean).join(" ");
  return { domain, ...info, daysToExpire, transferLocked, summary };
}

// --- Dependencias reales ---

async function resolveWith(server: string | null, name: string, type: LookupType): Promise<string[]> {
  const r = new nodeDns.Resolver({ timeout: 3000, tries: 2 });
  if (server) {
    // un NS autoritativo llega por nombre: se resuelve su IP con el sistema
    const ip = /^[\d.]+$/.test(server) || server.includes(":") ? server : (await nodeDns.resolve4(server))[0];
    r.setServers([ip]);
  }
  switch (type) {
    case "A": return r.resolve4(name);
    case "AAAA": return r.resolve6(name);
    case "CNAME": return r.resolveCname(name);
    case "NS": return r.resolveNs(name);
    case "MX": return (await r.resolveMx(name)).map((m) => `${m.priority} ${m.exchange}`);
    case "TXT": return (await r.resolveTxt(name)).map((parts) => parts.join(""));
    case "CAA": return (await r.resolveCaa(name)).map((c: any) => `${c.critical} ${Object.keys(c).find((k) => k !== "critical")} "${Object.values(c).find((v) => typeof v === "string")}"`);
  }
}

const defaultDeps: DiagnosticsDeps = {
  resolve: resolveWith,
  tlsPeer: (host, ip) => new Promise((resolve) => {
    const s = tls.connect({ host: ip, port: 443, servername: host, rejectUnauthorized: false, timeout: 5000 }, () => {
      const c = s.getPeerCertificate();
      s.end();
      if (!c || !c.valid_to) return resolve(null);
      const altNames = String(c.subjectaltname ?? "").split(",").map((x) => x.trim().replace(/^DNS:/, "").toLowerCase()).filter(Boolean);
      resolve({ issuer: String(c.issuer?.O ?? c.issuer?.CN ?? "desconocido"), validTo: c.valid_to, altNames });
    });
    s.once("timeout", () => { s.destroy(); resolve(null); });
    s.once("error", () => resolve(null));
  }),
  async httpHead(url) {
    try {
      const res = await fetch(url, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(5000), headers: { "user-agent": "MailMask-Diagnostics/1.0" } });
      await res.body?.cancel();
      return { status: res.status, location: res.headers.get("location") };
    } catch {
      return null;
    }
  },
  rdap: (d) => fetchRdap(d),
};

let activeDeps = defaultDeps;
/** Sólo pruebas: sin esto las rutas tocarían la red real. */
export function setDiagnosticsDeps(deps: DiagnosticsDeps | null): void {
  activeDeps = deps ?? defaultDeps;
}
