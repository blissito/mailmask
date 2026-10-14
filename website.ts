// Estado del sitio web de un dominio: a dónde apunta cada host (raíz, www y subdominios),
// qué plataforma es, qué está mal y si contesta por HTTPS.
//
// Es la pestaña «Sitio web» y la herramienta `website_status`. El patrón es el de Vercel y
// Render (oct-2026): por host, el valor que hay contra el que debería haber, en vez de una
// tabla de DNS cruda que el cliente tiene que interpretar.
import { Resolver } from "node:dns/promises";
import { connect as tlsConnect } from "node:tls";
import type { RRSet } from "./dns-records.js";

/** Sondeos con tope de simultáneas (no se importa el de dns-import: las pruebas lo mockean entero). */
async function inBatches<T>(tasks: (() => Promise<T>)[], limit: number): Promise<T[]> {
  const out: T[] = [];
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, async () => {
    while (i < tasks.length) { const mine = i++; out[mine] = await tasks[mine](); }
  }));
  return out;
}

/** Qué se reconoce por su valor. Son datos: una IP nueva de una plataforma se agrega aquí. */
export const PLATFORMS: { id: string; label: string; ips?: string[]; hosts?: RegExp }[] = [
  // Antes que Fly: EasyBits Sitios vive en Fly y su destino también termina en `.fly.dev`.
  { id: "easybits-sites", label: "EasyBits (borde viejo de Fly: ya no existe)", ips: ["66.241.125.82"], hosts: /^easybits\.fly\.dev$/ },
  // 216.198.79.x es el pool nuevo de Vercel (2025); 76.76.21.21 sigue sirviendo.
  { id: "vercel", label: "Vercel", ips: ["76.76.21.21", "216.198.79.1", "216.198.79.65"], hosts: /(\.vercel-dns\.com|\.vercel\.app)$/ },
  { id: "netlify", label: "Netlify", ips: ["75.2.60.5"], hosts: /(\.netlify\.app|\.netlify\.com)$/ },
  { id: "github-pages", label: "GitHub Pages", ips: ["185.199.108.153", "185.199.109.153", "185.199.110.153", "185.199.111.153"], hosts: /\.github\.io$/ },
  { id: "cloudflare-pages", label: "Cloudflare Pages", hosts: /\.pages\.dev$/ },
  { id: "render", label: "Render", ips: ["216.24.57.1"], hosts: /\.onrender\.com$/ },
  { id: "fly", label: "Fly.io", hosts: /\.fly\.dev$/ },
  { id: "railway", label: "Railway", hosts: /\.up\.railway\.app$/ },
  { id: "easybits", label: "EasyBits", ips: ["54.38.94.14"], hosts: /(^|\.)sandboxes\.easybits\.cloud$/ },
  { id: "shopify", label: "Shopify", ips: ["23.227.38.65"], hosts: /\.myshopify\.com$/ },
  { id: "wix", label: "Wix", ips: ["185.230.63.107", "185.230.63.171", "185.230.63.186"], hosts: /\.wixdns\.net$/ },
];

export type HttpsCheck = {
  ok: boolean;
  status?: number;
  location?: string;
  certValidTo?: string;
  error?: string;
};

export type WebsiteHost = {
  name: string;
  /** `@` para la raíz, o el subdominio (`www`, `app`…). */
  label: string;
  records: { type: "A" | "AAAA" | "CNAME"; values: string[] }[];
  platform: { id: string; label: string } | null;
  issues: string[];
  https: HttpsCheck | null;
};

const strip = (v: string) => v.trim().toLowerCase().replace(/\.$/, "");

export function detectPlatform(records: WebsiteHost["records"]): WebsiteHost["platform"] {
  for (const r of records) {
    for (const raw of r.values) {
      const v = strip(raw);
      const p = r.type === "CNAME"
        ? PLATFORMS.find((x) => x.hosts?.test(v))
        : PLATFORMS.find((x) => x.ips?.includes(v));
      if (p) return { id: p.id, label: p.label };
    }
  }
  return null;
}

/** Lo que una plataforma reporta como «Invalid Configuration», dicho en claro. */
export function hostIssues(records: WebsiteHost["records"], platform: WebsiteHost["platform"]): string[] {
  const out: string[] = [];
  if (platform?.id === "easybits-sites") out.push("Apunta al borde viejo de EasyBits en Fly, que ya no existe: vuelve a publicar el sitio desde «EasyBits» para moverlo.");
  const a = records.find((r) => r.type === "A");
  const aaaa = records.find((r) => r.type === "AAAA");
  // Fly (y EasyBits Sitios, que vive en Fly) sí publican IPv6: ahí el AAAA es correcto.
  if (platform && a && aaaa && platform.id !== "fly" && platform.id !== "easybits-sites") {
    // Vercel, Netlify y Render no publican IPv6: un AAAA viejo manda a parte de las visitas a otro lado.
    out.push(`Hay un AAAA (${aaaa.values.join(", ")}) que no es de ${platform.label}: bórralo o parte de las visitas irá a otro servidor.`);
  }
  if (a && a.values.length > 1 && platform) {
    const plat = PLATFORMS.find((p) => p.id === platform.id);
    const ajenas = a.values.filter((v) => !plat?.ips?.includes(strip(v)));
    if (ajenas.length) out.push(`El A mezcla IPs de ${platform.label} con otras (${ajenas.join(", ")}): cada visita cae en una al azar.`);
  }
  return out;
}

/** HEAD por HTTPS sin seguir redirecciones, más la caducidad del certificado. */
export async function probeHttps(host: string, timeoutMs = 10_000): Promise<HttpsCheck> {
  const cert = new Promise<{ validTo?: string; error?: string }>((resolve) => {
    const sock = tlsConnect({ host, port: 443, servername: host, timeout: timeoutMs }, () => {
      const c = sock.getPeerCertificate();
      const error = sock.authorized ? undefined : String(sock.authorizationError ?? "certificado no válido");
      sock.end();
      resolve({ validTo: c?.valid_to ? new Date(c.valid_to).toISOString() : undefined, error });
    });
    // Sin `rejectUnauthorized: false` el handshake falla con un certificado ajeno, y justo eso es lo que queremos ver.
    sock.on("error", (e) => resolve({ error: /ENOTFOUND|EAI_AGAIN/.test(e.message) ? "todavía no resuelve (si lo acabas de crear, espera un par de minutos)" : e.message }));
    sock.on("timeout", () => { sock.destroy(); resolve({ error: "sin respuesta en el puerto 443" }); });
  });
  let http: { status?: number; location?: string; error?: string } = {};
  try {
    const res = await fetch(`https://${host}/`, { method: "HEAD", redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
    http = { status: res.status, location: res.headers.get("location") ?? undefined };
  } catch (e) {
    http = { error: (e as Error).cause ? String((e as { cause?: { message?: string } }).cause?.message ?? e) : (e as Error).message };
    // Un registro recién escrito tarda en verse: «ENOTFOUND» asusta y casi siempre es eso.
    if (/ENOTFOUND|EAI_AGAIN/.test(http.error ?? "")) http.error = "todavía no resuelve (si lo acabas de crear, espera un par de minutos)";
    // En el borde de EasyBits (y cualquier TLS bajo demanda) la primera visita emite el
    // certificado y puede pasar del tope: no es una caída.
    else if (/abort|timeout/i.test(http.error ?? "")) http.error = "tardó en responder; si es nuevo, puede estar emitiendo su certificado: vuelve a revisar en un minuto";
  }
  const c = await cert;
  const error = c.error ?? http.error;
  return {
    ok: !error && !!http.status && http.status < 500,
    status: http.status,
    location: http.location,
    certValidTo: c.validTo,
    error,
  };
}

/** Nombres que son infraestructura de correo o de verificación, no sitios. */
const NOT_A_SITE = /(^|\.)_|^(autoconfig|autodiscover|mail|smtp|imap|pop|webmail)\./;

/** Los hosts web de una zona nuestra: raíz, www y todo subdominio con A/AAAA/CNAME. */
export function hostsFromZone(domain: string, zone: RRSet[], managedNames: Set<string>): Map<string, WebsiteHost["records"]> {
  const d = domain.toLowerCase();
  const out = new Map<string, WebsiteHost["records"]>([[d, []], [`www.${d}`, []]]);
  for (const r of zone) {
    if (r.type !== "A" && r.type !== "AAAA" && r.type !== "CNAME") continue;
    const name = strip(r.name);
    if (name !== d && !name.endsWith(`.${d}`)) continue;
    const rel = name === d ? "" : name.slice(0, -d.length - 1);
    if (rel && (NOT_A_SITE.test(`${rel}.`) || managedNames.has(name))) continue;
    if (!out.has(name)) out.set(name, []);
    out.get(name)!.push({ type: r.type, values: r.values.map(strip) });
  }
  return out;
}

/** Sin zona nuestra sólo se puede preguntar al DNS público por la raíz y www. */
export async function hostsFromPublicDns(domain: string, r?: Pick<Resolver, "resolve4" | "resolve6" | "resolveCname">): Promise<Map<string, WebsiteHost["records"]>> {
  const res = r ?? (() => { const x = new Resolver({ timeout: 4000, tries: 2 }); x.setServers(["8.8.8.8", "1.1.1.1"]); return x; })();
  const d = domain.toLowerCase();
  const out = new Map<string, WebsiteHost["records"]>();
  for (const name of [d, `www.${d}`]) {
    const recs: WebsiteHost["records"] = [];
    const cn = name === d ? [] : await res.resolveCname(name).catch(() => [] as string[]);
    if (cn.length) recs.push({ type: "CNAME", values: cn.map(strip) });
    else {
      const a = await res.resolve4(name).catch(() => [] as string[]);
      const aaaa = await res.resolve6(name).catch(() => [] as string[]);
      if (a.length) recs.push({ type: "A", values: a });
      if (aaaa.length) recs.push({ type: "AAAA", values: aaaa });
    }
    out.set(name, recs);
  }
  return out;
}

export async function getWebsiteStatus(
  domain: string,
  hosts: Map<string, WebsiteHost["records"]>,
  probe: (host: string) => Promise<HttpsCheck> = probeHttps,
): Promise<{ hosts: WebsiteHost[] }> {
  const d = domain.toLowerCase();
  const entries = [...hosts.entries()].slice(0, 25);
  const out = await inBatches(entries.map(([name, records]) => async (): Promise<WebsiteHost> => {
    const platform = detectPlatform(records);
    const issues = hostIssues(records, platform);
    if (name === `www.${d}` && !records.length && hosts.get(d)?.length) {
      issues.push(`www.${d} no apunta a ningún lado: quien escriba «www» no verá tu sitio.`);
    }
    return {
      name,
      label: name === d ? "@" : name.slice(0, -d.length - 1),
      records,
      platform,
      issues,
      // Un comodín no es un host al que se pueda llamar.
      https: records.length && !name.startsWith("*.") ? await probe(name) : null,
    };
  }), 6);
  return { hosts: out };
}
