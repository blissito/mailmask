// Los registros que el cliente pega en el panel de su registrador para conectar un dominio.
//
// Vivían en el front (`renderDnsRecords` de app.js) y un agente no tenía cómo leerlos: el
// alta de insightslab.com.mx y kandey.com.mx necesitó a una persona por WhatsApp para dictar
// los cinco registros. Ahora la fuente es esta, la consume `/app` y el MCP (`domain_dns_setup`).
//
// Las pistas (`hints`) van en texto con `**negritas**` estilo markdown: el front las convierte
// a <strong> escapando todo lo demás, y un modelo las lee tal cual.
import { Resolver } from "node:dns/promises";
import { IMAP_HOST } from "./apple-profile.js";

export const SES_INBOUND_HOST = "inbound-smtp.us-east-1.amazonaws.com";

export type DnsSetupLevel = "requerido" | "recomendado" | "opcional";

export interface DnsSetupRecord {
  id: string;
  type: "MX" | "TXT" | "CNAME" | "SRV";
  /** Como se escribe en casi todos los paneles: relativo al dominio ('@', '_amazonses'). */
  name: string;
  /** Nombre completo, para los paneles que lo piden así. */
  fqdn: string;
  value: string;
  /** Sólo MX: para los paneles con campo de prioridad aparte (entonces `value` va sin el 10). */
  priority?: number;
  host?: string;
  level: DnsSetupLevel;
  purpose: string;
  benefit?: string;
  hints: string[];
  /** Con `live`: si el DNS público ya lo tiene. `null` = no se pudo consultar. */
  ok?: boolean | null;
  observed?: string[];
  /** SPF: si ya hay uno sin amazonses, el valor fusionado que debe quedar (no crear otro). */
  suggestedValue?: string;
}

export interface RegistrarHint {
  provider: "hostinger" | "godaddy" | "cloudflare" | "namecheap" | "route53" | "mailmask";
  label: string;
  note: string;
}

export interface DnsSetup {
  domain: string;
  records: DnsSetupRecord[];
  live: boolean;
  nameservers?: string[];
  registrarHint?: RegistrarHint | null;
  /** Con `live`: cuántos de los requeridos ya se ven en el DNS público. */
  summary?: string;
}

interface DomainLike {
  domain: string;
  verificationToken: string;
  dkimTokens: string[];
  hostedZoneId?: string | null;
  /** Si el dominio tiene al menos un buzón: entonces van los registros de autodescubrimiento. */
  mailboxes?: boolean;
}

export function dnsSetupRecords(dom: DomainLike): DnsSetupRecord[] {
  const d = dom.domain;
  const tok = dom.verificationToken;
  const records: DnsSetupRecord[] = [
    {
      id: "mx",
      type: "MX",
      name: "@",
      fqdn: d,
      value: `10 ${SES_INBOUND_HOST}`,
      priority: 10,
      host: SES_INBOUND_HOST,
      level: "requerido",
      purpose: "Recibir correo: hace que el correo de tu dominio llegue a MailMask.",
      hints: [
        `**@** significa el dominio raíz (**${d}**). La mayoría de proveedores usan **@**.`,
        `Si tu proveedor tiene un campo separado de **Prioridad**, pon **10** ahí y solo la dirección como valor.`,
      ],
    },
    {
      id: "verification",
      type: "TXT",
      name: "_amazonses",
      fqdn: `_amazonses.${d}`,
      value: tok,
      level: "requerido",
      purpose: "Verificación: demuestra que el dominio es tuyo.",
      hints: [
        `Pon solo **_amazonses** como nombre — tu proveedor agrega **.${d}** automáticamente.`,
        `Si tu proveedor pide comillas alrededor del valor, agrégalas: **"${tok}"**.`,
      ],
    },
    ...dom.dkimTokens.map((token, i): DnsSetupRecord => ({
      id: `dkim${i + 1}`,
      type: "CNAME",
      name: `${token}._domainkey`,
      fqdn: `${token}._domainkey.${d}`,
      value: `${token}.dkim.amazonses.com`,
      level: "requerido",
      purpose: "DKIM: la firma digital que evita que tus correos caigan en spam.",
      hints: [
        `Pon solo **${token}._domainkey** como nombre — tu proveedor agrega **.${d}** automáticamente.`,
      ],
    })),
    {
      id: "spf",
      type: "TXT",
      name: "@",
      fqdn: d,
      value: "v=spf1 include:amazonses.com ~all",
      level: "recomendado",
      purpose: "SPF: autoriza a MailMask a enviar en nombre de tu dominio.",
      benefit: "Algunos receptores revisan SPF además de DKIM. Con este registro, tus correos llegan a más bandejas y menos a spam.",
      hints: [
        `Este registro **SPF** autoriza a Amazon SES a enviar emails en nombre de tu dominio.`,
        `Si ya tienes un registro SPF, agrega **include:amazonses.com** antes del **~all** existente en vez de crear uno nuevo.`,
      ],
    },
    {
      id: "dmarc",
      type: "TXT",
      name: "_dmarc",
      fqdn: `_dmarc.${d}`,
      value: `v=DMARC1; p=none; rua=mailto:dmarc@${d}`,
      level: "opcional",
      purpose: "DMARC: política anti-suplantación y reportes.",
      benefit: "Gmail y Yahoo tratan mejor a los dominios con política DMARC, y te llegan reportes de quién envía en tu nombre. Tu firma DKIM ya cumple, así que se activa sin riesgo.",
      hints: [
        `**p=none** solo observa: nada se bloquea. Cuando veas que todo pasa, súbelo a **p=quarantine** para que los receptores rechacen a quien se haga pasar por ti.`,
        `Los reportes llegan a **dmarc@${d}**. Crea ese alias en MailMask, o cambia la dirección por otra tuya.`,
      ],
    },
  ];
  if (dom.mailboxes) {
    records.push(
      {
        id: "autodiscover",
        type: "SRV",
        name: "_autodiscover._tcp",
        fqdn: `_autodiscover._tcp.${d}`,
        value: `0 0 443 ${IMAP_HOST}`,
        level: "recomendado",
        purpose: "Outlook: configura los buzones solo, sin escribir el servidor a mano.",
        benefit: "Sin él, Outlook adivina el servidor y puede proponer el de tu proveedor anterior.",
        hints: [
          `Si tu proveedor pide los campos por separado: prioridad **0**, peso **0**, puerto **443**, destino **${IMAP_HOST}**.`,
          `Si ya usas Microsoft 365 o Exchange en este dominio, **no lo agregues**: le quitarías el autodescubrimiento a esas cuentas.`,
        ],
      },
      {
        id: "autoconfig",
        type: "CNAME",
        name: "autoconfig",
        fqdn: `autoconfig.${d}`,
        value: IMAP_HOST,
        level: "opcional",
        purpose: "Thunderbird y otros clientes: configuran los buzones solos.",
        hints: [`Pon solo **autoconfig** como nombre — tu proveedor agrega **.${d}** automáticamente.`],
      },
    );
  }
  // La explicación común de los tres CNAME va en el primero, como siempre la tuvo la tabla.
  const firstDkim = records.find((r) => r.id === "dkim1");
  firstDkim?.hints.unshift(`Los 3 registros CNAME son para **DKIM** — la firma digital que evita que tus emails caigan en spam.`);
  return records;
}

/** Inserta `include:amazonses.com` en un SPF existente, antes del `all` final. */
export function mergeSpf(existing: string): string {
  if (/include:amazonses\.com/i.test(existing)) return existing;
  const m = existing.match(/\s([~?+-]?all)\s*$/i);
  if (!m) return `${existing.trim()} include:amazonses.com`;
  return `${existing.slice(0, m.index).trimEnd()} include:amazonses.com ${m[1]}`;
}

const REGISTRARS: { re: RegExp; hint: RegistrarHint }[] = [
  {
    re: /dns-parking\.com|hostinger/i,
    hint: {
      provider: "hostinger",
      label: "Hostinger",
      note: "En hPanel: Dominios → tu dominio → DNS / Nameservers → Administrar registros DNS. Agrega cada registro con «Agregar registro»; en el MX pon 10 en Prioridad y solo la dirección en «Apunta a». Si ya hay un MX de Hostinger, bórralo o tu correo seguirá llegando allá.",
    },
  },
  {
    re: /domaincontrol\.com/i,
    hint: {
      provider: "godaddy",
      label: "GoDaddy",
      note: "En GoDaddy: Mi cuenta → Mis productos → Dominios → tu dominio → DNS → Agregar nuevo registro. En el nombre pon solo la parte antes del dominio (GoDaddy agrega el resto) y quita los MX que traiga de fábrica.",
    },
  },
  {
    re: /ns\.cloudflare\.com/i,
    hint: {
      provider: "cloudflare",
      label: "Cloudflare",
      note: "En Cloudflare: tu sitio → DNS → Records → Add record. Los tres CNAME de DKIM deben ir con la nube gris («DNS only»), no naranja: con proxy DKIM no verifica.",
    },
  },
  {
    re: /registrar-servers\.com/i,
    hint: {
      provider: "namecheap",
      label: "Namecheap",
      note: "En Namecheap: Domain List → Manage → Advanced DNS. Los TXT y CNAME van en «Host Records» → Add new record; el MX va en «Mail Settings» → Custom MX.",
    },
  },
  {
    re: /awsdns/i,
    hint: {
      provider: "route53",
      label: "Amazon Route 53",
      note: "En la consola de AWS: Route 53 → Hosted zones → tu dominio → Create record. En MX el valor va con la prioridad delante: «10 inbound-smtp.us-east-1.amazonaws.com».",
    },
  },
];

export function registrarFromNameservers(ns: string[], managedByMailMask: boolean): RegistrarHint | null {
  const joined = ns.join(" ");
  const hit = REGISTRARS.find((r) => r.re.test(joined));
  if (hit?.hint.provider === "route53" && managedByMailMask) {
    return {
      provider: "mailmask",
      label: "MailMask",
      note: "El DNS de este dominio ya lo administra MailMask: los registros de correo se ponen solos. Para lo demás usa el editor de DNS (list_dns_records / set_dns_record).",
    };
  }
  return hit?.hint ?? null;
}

type Resolve = Pick<Resolver, "resolveMx" | "resolveTxt" | "resolveCname" | "resolveNs">;

function makeResolver(): Resolve {
  // Tope corto: esto lo espera un chat, y un DNS que no contesta en 2.5 s es "no se pudo".
  return new Resolver({ timeout: 2500, tries: 1 });
}

// Distingue "no existe" (ok: false) de "no se pudo consultar" (ok: null).
async function attempt<T>(fn: () => Promise<T>): Promise<{ value: T | null; failed: boolean }> {
  try {
    return { value: await fn(), failed: false };
  } catch (err) {
    const code = (err as { code?: string }).code;
    return { value: null, failed: !(code === "ENOTFOUND" || code === "ENODATA") };
  }
}

async function nameserversOf(domain: string, r: Resolve): Promise<string[]> {
  // Un subdominio no tiene NS propios: se sube hasta encontrar la zona.
  const labels = domain.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const res = await attempt(() => r.resolveNs(labels.slice(i).join(".")));
    if (res.value?.length) return res.value.map((n) => n.toLowerCase());
    if (res.failed) return [];
  }
  return [];
}

/** Registros a pegar; con `live` además compara contra el DNS público y adivina el registrador. */
export async function buildDnsSetup(dom: DomainLike, opts: { live?: boolean; resolver?: Resolve } = {}): Promise<DnsSetup> {
  const records = dnsSetupRecords(dom);
  if (!opts.live) return { domain: dom.domain, records, live: false };

  const r = opts.resolver ?? makeResolver();
  const d = dom.domain;
  const flat = (txt: string[][] | null) => (txt ?? []).map((parts) => parts.join(""));

  const [mx, verif, apexTxt, dmarc, ns, ...dkims] = await Promise.all([
    attempt(() => r.resolveMx(d)),
    attempt(() => r.resolveTxt(`_amazonses.${d}`)),
    attempt(() => r.resolveTxt(d)),
    attempt(() => r.resolveTxt(`_dmarc.${d}`)),
    nameserversOf(d, r),
    ...dom.dkimTokens.map((t) => attempt(() => r.resolveCname(`${t}._domainkey.${d}`))),
  ]);

  for (const rec of records) {
    if (rec.id === "mx") {
      rec.observed = (mx.value ?? []).map((m) => `${m.priority} ${m.exchange}`);
      if (mx.failed) rec.ok = null;
      else {
        const ses = (mx.value ?? []).find((m) => m.exchange.toLowerCase() === SES_INBOUND_HOST);
        const before = (mx.value ?? []).filter((m) => ses && m.priority < ses.priority && m.exchange.toLowerCase() !== SES_INBOUND_HOST);
        rec.ok = !!ses && before.length === 0;
      }
    } else if (rec.id === "verification") {
      rec.observed = flat(verif.value);
      rec.ok = verif.failed ? null : rec.observed.includes(dom.verificationToken);
    } else if (rec.id.startsWith("dkim")) {
      const res = dkims[Number(rec.id.slice(4)) - 1];
      rec.observed = res.value ?? [];
      rec.ok = res.failed ? null : rec.observed.some((v) => v.toLowerCase().replace(/\.$/, "") === rec.value);
    } else if (rec.id === "spf") {
      const spfs = flat(apexTxt.value).filter((v) => /^v=spf1\b/i.test(v));
      rec.observed = spfs;
      if (apexTxt.failed) rec.ok = null;
      else if (spfs.length === 0) rec.ok = false;
      else {
        rec.ok = spfs.length === 1 && /include:amazonses\.com/i.test(spfs[0]);
        if (!rec.ok) {
          // Dos SPF en el mismo nombre invalidan los dos: la respuesta es fusionarlos, no sumar.
          rec.suggestedValue = mergeSpf(spfs[0]);
          rec.hints = [
            spfs.length > 1
              ? `Tu dominio tiene **${spfs.length}** registros SPF y eso invalida todos. Deja uno solo con este valor: **${rec.suggestedValue}**.`
              : `Ya tienes un SPF. No crees otro: edítalo para que quede **${rec.suggestedValue}**.`,
            ...rec.hints,
          ];
        }
      }
    } else if (rec.id === "dmarc") {
      rec.observed = flat(dmarc.value);
      rec.ok = dmarc.failed ? null : rec.observed.some((v) => /^v=DMARC1/i.test(v));
    }
  }

  const required = records.filter((x) => x.level === "requerido");
  const done = required.filter((x) => x.ok === true).length;
  return {
    domain: d,
    records,
    live: true,
    nameservers: ns,
    registrarHint: registrarFromNameservers(ns, !!dom.hostedZoneId),
    summary: done === required.length
      ? "Los registros requeridos ya se ven en el DNS público. Si el dominio aún no está verificado, llama a verify_domain."
      : `Faltan ${required.length - done} de ${required.length} registros requeridos en el DNS público (puede tardar de minutos a unas horas en propagarse).`,
  };
}
