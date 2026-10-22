// Vigía de las 48 h siguientes a mudar los NS a MailMask («conectar sin mudarte»). Compara lo que el mundo
// resuelve hoy para el correo y la web (MX del apex, A/CNAME del apex y de www) contra el inventario que el
// cliente aprobó antes de mudarse. Si algo cambió, avisa una sola vez por registro. Lo que importa no es la zona
// de Route 53 (es la nuestra) sino lo que contestan los resolutores públicos: es lo que ven sus clientes.

import { Resolver } from "node:dns/promises";
import type { RRSet } from "./dns-records.js";

export const WATCH_HOURS = 48;

export type LiveResolver = {
  mx(name: string): Promise<string[]>;
  a(name: string): Promise<string[]>;
  cname(name: string): Promise<string[]>;
};

/** Resolutores públicos (Google y Cloudflare), no el del sistema: la red local puede interceptar DNS. */
export function publicResolver(): LiveResolver {
  const r = new Resolver({ timeout: 4000, tries: 2 });
  r.setServers(["8.8.8.8", "1.1.1.1"]);
  const safe = async <T>(p: Promise<T[]>, map: (x: T) => string) => { try { return (await p).map(map); } catch { return []; } };
  return {
    mx: (n) => safe(r.resolveMx(n), (x) => `${x.priority} ${x.exchange}`),
    a: (n) => safe(r.resolve4(n), (x) => x),
    cname: (n) => safe(r.resolveCname(n), (x) => x),
  };
}

const canon = (v: string) => v.trim().toLowerCase().replace(/\.$/, "").replace(/\s+/g, " ");
const sameSet = (a: string[], b: string[]) => {
  const x = new Set(a.map(canon)), y = new Set(b.map(canon));
  return x.size === y.size && [...x].every((v) => y.has(v));
};

export type WatchFinding = { name: string; type: "MX" | "A" | "CNAME"; expected: string[]; observed: string[] };

/**
 * Lo que cambió respecto al inventario aprobado. Sólo mira registros que existían antes: un registro nuevo
 * (el DKIM de SES que agregamos) no es una falla. Un CNAME del inventario se compara como CNAME, no como A.
 */
export async function checkDomain(domain: string, preSnapshot: RRSet[], live: LiveResolver): Promise<WatchFinding[]> {
  const apex = domain.toLowerCase();
  const findings: WatchFinding[] = [];
  const pre = (name: string, type: string) => preSnapshot.find((r) => r.name === name && r.type === type)?.values;
  const targets: { name: string; type: WatchFinding["type"]; get: () => Promise<string[]> }[] = [
    { name: apex, type: "MX", get: () => live.mx(apex) },
    { name: apex, type: "A", get: () => live.a(apex) },
    { name: `www.${apex}`, type: "CNAME", get: () => live.cname(`www.${apex}`) },
    { name: `www.${apex}`, type: "A", get: () => live.a(`www.${apex}`) },
  ];
  for (const t of targets) {
    const expected = pre(t.name, t.type);
    if (!expected?.length) continue;
    // www con CNAME en el inventario: su A la decide el destino, no se compara
    if (t.type === "A" && t.name.startsWith("www.") && pre(t.name, "CNAME")) continue;
    const observed = await t.get();
    if (!sameSet(expected, observed)) findings.push({ name: t.name, type: t.type, expected, observed });
  }
  return findings;
}

/** Texto del aviso, en palabras del cliente. */
export function describeFinding(f: WatchFinding): string {
  const what = f.type === "MX" ? "el correo (MX)" : f.name.startsWith("www.") ? "tu web en www" : "tu web";
  const obs = f.observed.length ? f.observed.join(", ") : "nada";
  return `Cambió ${what} de ${f.name}: antes ${f.expected.join(", ")}, ahora ${obs}.`;
}
