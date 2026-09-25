// Inventario del DNS de un dominio que todavía vive en otro proveedor, y detección de
// cuándo la delegación a nuestros nameservers ya surtió efecto.
//
// Existe por una razón concreta: si el cliente cambia los nameservers con nuestra zona
// vacía, su web y su correo mueren en el acto. Hay que copiar lo que tenía **antes** de que
// el mundo empiece a preguntarnos a nosotros.
import { Resolver } from "node:dns/promises";
import { log } from "./logger.js";
import type { RRSet, RRSetTipo } from "./dns-records.js";
import { dropCnameConflicts } from "./dns-records.js";

/** Resolvers públicos, para no depender del caché del sistema. */
const PUBLICOS = ["8.8.8.8", "1.1.1.1"];

/**
 * Sin AXFR no se puede enumerar la zona de otro: sólo se puede *preguntar por nombres*. Esta
 * lista es una heurística de lo que la gente tiene de verdad, y por eso el resultado se le
 * enseña al cliente con la advertencia de que puede faltar algo.
 */
const NOMBRES = [
  "www", "mail", "smtp", "imap", "pop", "ftp", "blog", "api", "app", "admin", "shop",
  "tienda", "dev", "staging", "test", "cdn", "static", "m", "webmail", "portal", "docs",
  "autodiscover", "autoconfig", "_dmarc", "_domainkey", "default._domainkey",
  "google._domainkey", "k1._domainkey", "k2._domainkey", "s1._domainkey", "s2._domainkey",
  "selector1._domainkey", "selector2._domainkey", "mandrill._domainkey", "zoho._domainkey",
  "_acme-challenge", "_github-pages-challenge",
];

const TIPOS_APEX: RRSetTipo[] = ["A", "AAAA", "MX", "TXT", "CAA"];
const TIPOS_SUB: RRSetTipo[] = ["A", "AAAA", "CNAME", "TXT"];

const TIEMPO_CONSULTA_MS = 4000;
const TIEMPO_TOTAL_MS = 45_000;
/**
 * Consultas simultáneas. Sin freno se disparaban ~150 de golpe contra el servidor
 * autoritativo del cliente: parece un abuso, empieza a descartar y el inventario sale
 * incompleto — y con distinto contenido en cada corrida. Es lo peor que puede pasar aquí,
 * porque de esta lista depende que no se le caiga el sitio al mover el dominio.
 */
const CONCURRENCIA = 6;

function resolver(servidores: string[]): Resolver {
  // `tries: 2` porque un UDP perdido no es "no existe": con 1 intento, un paquete caído
  // borra un registro del inventario sin que nadie se entere.
  const r = new Resolver({ timeout: TIEMPO_CONSULTA_MS, tries: 2 });
  r.setServers(servidores);
  return r;
}

/** Ejecuta con un tope de simultáneas, en vez de soltarlo todo a la vez. */
export async function enTandas<T>(tareas: (() => Promise<T>)[], limite: number): Promise<T[]> {
  const salida: T[] = [];
  let i = 0;
  const obreros = Array.from({ length: Math.min(limite, tareas.length) }, async () => {
    while (i < tareas.length) {
      const mio = i++;
      salida[mio] = await tareas[mio]();
    }
  });
  await Promise.all(obreros);
  return salida;
}

async function consultar(r: Resolver, nombre: string, tipo: RRSetTipo): Promise<RRSet | null> {
  try {
    switch (tipo) {
      case "A": {
        const v = await r.resolve4(nombre, { ttl: true });
        return v.length ? { name: nombre, type: "A", ttl: v[0].ttl || 300, values: v.map((x) => x.address) } : null;
      }
      case "AAAA": {
        const v = await r.resolve6(nombre, { ttl: true });
        return v.length ? { name: nombre, type: "AAAA", ttl: v[0].ttl || 300, values: v.map((x) => x.address) } : null;
      }
      case "CNAME": {
        const v = await r.resolveCname(nombre);
        return v.length ? { name: nombre, type: "CNAME", ttl: 300, values: [v[0]] } : null;
      }
      case "MX": {
        const v = await r.resolveMx(nombre);
        return v.length ? { name: nombre, type: "MX", ttl: 300, values: v.map((x) => `${x.priority} ${x.exchange}`) } : null;
      }
      case "TXT": {
        const v = await r.resolveTxt(nombre);
        // Cada respuesta viene ya partida en cadenas: se rejunta y se vuelve a entrecomillar.
        return v.length ? { name: nombre, type: "TXT", ttl: 300, values: v.map((t) => `"${t.join("").replace(/"/g, '\\"')}"`) } : null;
      }
      case "CAA": {
        const v: any[] = await (r as any).resolveCaa(nombre);
        const valores = v.map((c) => {
          const tag = c.issue !== undefined ? "issue" : c.issuewild !== undefined ? "issuewild" : "iodef";
          return `${c.critical ?? 0} ${tag} "${c.issue ?? c.issuewild ?? c.iodef}"`;
        });
        return valores.length ? { name: nombre, type: "CAA", ttl: 300, values: valores } : null;
      }
      default:
        return null;
    }
  } catch {
    // NXDOMAIN, timeout, SERVFAIL: para el inventario significan "no hay", no un fallo.
    return null;
  }
}

/** Los nameservers autoritativos del dominio hoy, según los resolvers públicos. */
export async function nameserversActuales(domain: string): Promise<string[]> {
  try {
    const ns = await resolver(PUBLICOS).resolveNs(domain);
    return ns.map((n) => n.toLowerCase().replace(/\.$/, "")).sort();
  } catch {
    return [];
  }
}

export interface Inventario {
  found: RRSet[];
  nameservers: string[];
  warning: string;
  /** true si la consulta se cortó por tiempo: el inventario está incompleto de seguro. */
  truncado?: boolean;
}

/**
 * Sondea el DNS vivo del dominio. **No escribe nada.**
 *
 * Pregunta a los nameservers autoritativos actuales y no al resolver del sistema: así se lee
 * la zona tal como está, sin la copia con TTL que tenga en medio cualquier caché.
 */
export async function snapshotDns(domain: string, nombresExtra: string[] = []): Promise<Inventario> {
  const apex = domain.toLowerCase().replace(/\.$/, "");
  const ns = await nameserversActuales(apex);

  // Si los NS no resuelven a una IP utilizable, se cae a los públicos.
  let servidores = PUBLICOS;
  if (ns.length) {
    const ips = await Promise.all(ns.slice(0, 3).map((n) => resolver(PUBLICOS).resolve4(n).catch(() => [])));
    const planas = ips.flat();
    if (planas.length) servidores = planas;
  }
  const r = resolver(servidores);

  const tareas: (() => Promise<RRSet | null>)[] = [];
  for (const t of TIPOS_APEX) tareas.push(() => consultar(r, apex, t));
  // Los nombres que ya conocemos por la base valen más que la heurística: los CNAME de DKIM
  // de SES llevan un token aleatorio (`fj4k2…._domainkey`) que ninguna lista puede adivinar.
  // Sin esto, el inventario de un dominio nuestro perdía su propia firma DKIM.
  for (const sub of [...new Set([...NOMBRES, ...nombresExtra])]) {
    for (const t of TIPOS_SUB) tareas.push(() => consultar(r, `${sub}.${apex}`, t));
  }

  // Un corte a medias devolvía el inventario VACÍO, que es peor que uno incompleto: el
  // cliente lo aprobaría creyendo que su zona no tenía nada. Ahora se conserva lo que sí
  // alcanzó a responder y se avisa.
  let truncado = false;
  const corte = new Promise<"corte">((res) => setTimeout(() => { truncado = true; res("corte"); }, TIEMPO_TOTAL_MS));
  const resultados = await Promise.race([enTandas(tareas, CONCURRENCIA), corte]);

  const found: RRSet[] = Array.isArray(resultados)
    ? (resultados as (RRSet | null)[]).filter((x): x is RRSet => !!x)
    : [];

  // Los NS y el SOA del apex son del proveedor viejo: no se copian.
  const limpio = dropCnameConflicts(found.filter((x) => !(x.name === apex && (x.type === "NS" || (x.type as string) === "SOA"))));

  log("info", "route53", "DNS snapshot", { domain: apex, encontrados: limpio.length, ns: ns.length, extra: nombresExtra.length });

  return {
    found: limpio,
    nameservers: ns,
    warning: truncado
      ? `La consulta a tu DNS actual tardó demasiado y quedó a medias: encontramos ${limpio.length} registro(s), pero seguro faltan. Vuelve a intentarlo y compara con tu proveedor actual antes de cambiar los nameservers.`
      : `Encontramos ${limpio.length} registro(s). No podemos garantizar que sean todos: revisa en tu proveedor actual si falta alguno antes de cambiar los nameservers, porque lo que no esté aquí dejará de funcionar.`,
    truncado,
  };
}

export interface EstadoDelegacion {
  delegated: boolean;
  observed: string[];
  expected: string[];
}

/**
 * Durante la propagación se mezclan los viejos y los nuevos, así que basta con ver **uno**
 * de los nuestros para decir que ya empezó a delegar.
 */
export async function delegacionActiva(domain: string, esperados: string[]): Promise<EstadoDelegacion> {
  const observed = await nameserversActuales(domain);
  const expected = esperados.map((n) => n.toLowerCase().replace(/\.$/, "")).sort();
  return {
    delegated: expected.length > 0 && observed.some((o) => expected.includes(o)),
    observed,
    expected,
  };
}

