// Lector mínimo de archivos de zona exportados (GoDaddy, Cloudflare, Namecheap, Hostinger) y su comparación contra
// la zona de Route 53, para «conectar sin mudarte»: antes de cambiar los NS, lo que el cliente tiene en su proveedor
// y nosotros no, sale en rojo. No es un BIND completo: sólo lo que esos paneles exportan (una línea por registro,
// $ORIGIN, $TTL, `@`, nombres relativos, comentarios con `;` y el SOA entre paréntesis, que se ignora).

import type { RRSet, RRSetTipo } from "./dns-records.js";

const TYPES: RRSetTipo[] = ["A", "AAAA", "CNAME", "TXT", "MX", "NS", "CAA", "SRV"];
const DEFAULT_TTL = 3600;

/** Quita el comentario `;` que no esté dentro de comillas. */
function stripComment(line: string): string {
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"' && line[i - 1] !== "\\") quoted = !quoted;
    if (c === ";" && !quoted) return line.slice(0, i);
  }
  return line;
}

/** Separa en palabras respetando lo que va entre comillas (TXT con espacios). */
function tokenize(line: string): string[] {
  return line.match(/"(?:[^"\\]|\\.)*"|\S+/g) ?? [];
}

function absolute(name: string, origin: string): string {
  if (name === "@") return origin;
  if (name.endsWith(".")) return name.slice(0, -1).toLowerCase();
  return `${name}.${origin}`.toLowerCase();
}

/** Un valor como lo guarda Route 53: nombres de destino con punto final, TXT entre comillas. */
function normalizeValue(type: RRSetTipo, parts: string[], origin: string): string {
  const fqdn = (n: string) => (n === "@" ? `${origin}.` : n.endsWith(".") ? n : `${n}.${origin}.`);
  switch (type) {
    case "CNAME": case "NS": return fqdn(parts[0]).toLowerCase();
    case "MX": return `${parts[0]} ${fqdn(parts[1]).toLowerCase()}`;
    case "SRV": return `${parts[0]} ${parts[1]} ${parts[2]} ${fqdn(parts[3]).toLowerCase()}`;
    case "TXT": return parts.map((p) => (p.startsWith('"') ? p : `"${p}"`)).join(" ");
    default: return parts.join(" ");
  }
}

/** Lee un archivo de zona y regresa RRSets agrupados por (nombre, tipo). Sin SOA y sin el NS del apex. */
export function parseZoneFile(text: string, domain: string): RRSet[] {
  let origin = domain.toLowerCase().replace(/\.$/, "");
  let ttlDefault = DEFAULT_TTL;
  let lastName = origin;
  let inParens = false;
  const sets = new Map<string, RRSet>();

  for (const raw of text.split(/\r?\n/)) {
    const line = stripComment(raw);
    if (inParens) { if (line.includes(")")) inParens = false; continue; }
    if (!line.trim()) continue;
    const startsWithSpace = /^\s/.test(line);
    const tokens = tokenize(line.trim());
    if (tokens[0] === "$ORIGIN") { origin = tokens[1].replace(/\.$/, "").toLowerCase(); continue; }
    if (tokens[0] === "$TTL") { ttlDefault = Number(tokens[1]) || ttlDefault; continue; }

    // dueño: si la línea empieza con espacio hereda el anterior (estilo BIND)
    let i = 0;
    let name = lastName;
    if (!startsWithSpace) { name = absolute(tokens[0], origin); i = 1; }
    let ttl = ttlDefault;
    // TTL y clase en cualquier orden antes del tipo
    for (let k = 0; k < 2 && i < tokens.length; k++) {
      if (/^\d+$/.test(tokens[i])) { ttl = Number(tokens[i]); i++; }
      else if (/^(IN|CH|HS)$/i.test(tokens[i])) i++;
    }
    const type = (tokens[i] ?? "").toUpperCase();
    lastName = name;
    if (type === "SOA") { if (line.includes("(") && !line.includes(")")) inParens = true; continue; }
    if (!TYPES.includes(type as RRSetTipo)) continue;
    if (type === "NS" && name === origin) continue; // los NS del apex son los del proveedor viejo
    const value = normalizeValue(type as RRSetTipo, tokens.slice(i + 1), origin);
    const key = `${name}|${type}`;
    const set = sets.get(key) ?? { name, type: type as RRSetTipo, ttl, values: [] };
    if (!set.values.includes(value)) set.values.push(value);
    sets.set(key, set);
  }
  return [...sets.values()];
}

/** Para comparar: sin punto final, minúsculas (salvo TXT) y espacios colapsados. */
function canon(type: RRSetTipo, v: string): string {
  const s = v.trim().replace(/\s+/g, " ");
  return type === "TXT" ? s : s.replace(/\.$/, "").replace(/\. /g, " ").toLowerCase();
}

export type ZoneDiff = {
  missing: RRSet[];
  different: { name: string; type: RRSetTipo; exported: string[]; current: string[] }[];
};

/** Qué tiene la exportación del proveedor que la zona de MailMask no tiene, o tiene distinto. */
export function compareZones(exported: RRSet[], current: RRSet[]): ZoneDiff {
  const byKey = new Map(current.map((r) => [`${r.name}|${r.type}`, r]));
  const missing: RRSet[] = [];
  const different: ZoneDiff["different"] = [];
  for (const e of exported) {
    const c = byKey.get(`${e.name}|${e.type}`);
    if (!c) { missing.push(e); continue; }
    const have = new Set(c.values.map((v) => canon(e.type, v)));
    if (e.values.some((v) => !have.has(canon(e.type, v)))) {
      different.push({ name: e.name, type: e.type, exported: e.values, current: c.values });
    }
  }
  return { missing, different };
}
