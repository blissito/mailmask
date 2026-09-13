// Validación y guardián de los registros DNS. Capa pura: sin AWS, sin base de datos.
//
// El modelo es el **RRSet**, no el registro suelto. `ChangeResourceRecordSets` es atómico
// por `(name, type)` y no existe "borrar un valor": exponer valores individuales obligaría a
// leer-modificar-escribir con una carrera invisible entre dos pestañas o dos llamadas de un
// agente. Con RRSets la operación natural es un UPSERT idempotente, que además es lo que un
// LLM usa sin romper nada.
import { AWS_REGION } from "./ses.js";

export type RRSetTipo = "A" | "AAAA" | "CNAME" | "TXT" | "MX" | "NS" | "CAA" | "SRV";

export const TIPOS_PERMITIDOS: RRSetTipo[] = ["A", "AAAA", "CNAME", "TXT", "MX", "NS", "CAA", "SRV"];

export interface RRSet {
  name: string;
  type: RRSetTipo;
  ttl: number;
  values: string[];
}

export interface RRSetAnotado extends RRSet {
  managed: boolean;
  editable: boolean;
  managedReason?: string;
  protectedValues?: string[];
}

export const TTL_MIN = 60;
export const TTL_MAX = 172800;
export const SPF_MAILMASK = "include:amazonses.com";

// --- Nombres ---

/**
 * Acepta `@`, `""`, `www`, `www.dominio.com` y `www.dominio.com.`; devuelve siempre el FQDN
 * en minúsculas y sin punto final. Lanza si el nombre no pertenece a la zona.
 */
export function normalizarNombre(input: string, domain: string): string {
  const zona = domain.trim().toLowerCase().replace(/\.$/, "");
  let n = (input ?? "").trim().toLowerCase().replace(/\.$/, "");

  if (n === "" || n === "@") return zona;
  if (n !== zona && !n.endsWith(`.${zona}`)) n = `${n}.${zona}`;

  if (n.length > 253) throw new ErrorDns(`El nombre "${input}" es demasiado largo (máximo 253 caracteres).`);

  const etiquetas = n.split(".");
  for (const [i, e] of etiquetas.entries()) {
    if (!e.length) throw new ErrorDns(`El nombre "${input}" tiene un punto de más.`);
    if (e.length > 63) throw new ErrorDns(`La parte "${e}" del nombre pasa de 63 caracteres.`);
    // El comodín sólo vale en la etiqueta más a la izquierda.
    if (e === "*") {
      if (i !== 0) throw new ErrorDns(`El comodín "*" sólo puede ir al principio del nombre.`);
      continue;
    }
    if (!/^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$/.test(e)) {
      throw new ErrorDns(`La parte "${e}" del nombre tiene caracteres que no se permiten en DNS.`);
    }
  }

  if (n !== zona && !n.endsWith(`.${zona}`)) {
    throw new ErrorDns(`El nombre "${input}" no pertenece a ${zona}.`);
  }
  return n;
}

export class ErrorDns extends Error {
  constructor(message: string, public readonly suggestedValues?: string[]) {
    super(message);
    this.name = "ErrorDns";
  }
}

// --- Valores ---

function esIpv4(v: string): boolean {
  const p = v.split(".");
  return p.length === 4 && p.every((o) => /^\d{1,3}$/.test(o) && Number(o) <= 255);
}

function esIpv6(v: string): boolean {
  if (!/^[0-9a-f:]+$/i.test(v)) return false;
  if ((v.match(/::/g) ?? []).length > 1) return false;
  const grupos = v.split(":").filter(Boolean);
  return grupos.length <= 8 && grupos.every((g) => /^[0-9a-f]{1,4}$/i.test(g));
}

function esHost(v: string): boolean {
  const n = v.replace(/\.$/, "");
  return n.length > 0 && n.length <= 253 &&
    n.split(".").every((e) => /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$/i.test(e));
}

/**
 * Route 53 exige que cada cadena de un TXT quepa en 255 caracteres; lo que pasa de ahí va en
 * varias cadenas entrecomilladas seguidas. Es donde se atora todo el mundo al pegar una
 * clave DKIM de otro proveedor, así que se parte solo.
 */
export function normalizarTxt(valor: string): string {
  const crudo = /^".*"$/s.test(valor.trim())
    ? valor.trim().slice(1, -1).replace(/"\s+"/g, "")
    : valor.trim();
  const escapado = crudo.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

  const trozos: string[] = [];
  for (let i = 0; i < escapado.length; i += 255) trozos.push(escapado.slice(i, i + 255));
  if (!trozos.length) trozos.push("");
  return trozos.map((t) => `"${t}"`).join(" ");
}

/** Valida y normaliza. Devuelve el RRSet listo para AWS, o lanza `ErrorDns` en español. */
export function validarRRSet(entrada: RRSet, domain: string): RRSet {
  const tipo = String(entrada.type ?? "").toUpperCase() as RRSetTipo;
  if (!TIPOS_PERMITIDOS.includes(tipo)) {
    throw new ErrorDns(`El tipo "${entrada.type}" no está soportado. Usa uno de: ${TIPOS_PERMITIDOS.join(", ")}.`);
  }

  const name = normalizarNombre(entrada.name, domain);
  const zona = domain.toLowerCase().replace(/\.$/, "");
  const ttl = Number(entrada.ttl ?? 300);

  if (!Number.isInteger(ttl) || ttl < TTL_MIN || ttl > TTL_MAX) {
    throw new ErrorDns(`El TTL debe ser un número entero entre ${TTL_MIN} y ${TTL_MAX} segundos. Si no sabes cuál poner, usa 300.`);
  }

  const brutos = (entrada.values ?? []).map((v) => String(v).trim()).filter(Boolean);
  if (!brutos.length) throw new ErrorDns("El registro necesita al menos un valor.");
  if (brutos.length > 100) throw new ErrorDns("Un registro no puede tener más de 100 valores.");

  let values: string[];
  switch (tipo) {
    case "A":
      for (const v of brutos) if (!esIpv4(v)) throw new ErrorDns(`"${v}" no es una dirección IPv4 válida (ejemplo: 76.76.21.21).`);
      values = brutos;
      break;
    case "AAAA":
      for (const v of brutos) if (!esIpv6(v)) throw new ErrorDns(`"${v}" no es una dirección IPv6 válida.`);
      values = brutos;
      break;
    case "CNAME": {
      if (brutos.length !== 1) throw new ErrorDns("Un CNAME sólo puede tener un valor.");
      if (name === zona) {
        throw new ErrorDns("Un CNAME no puede estar en la raíz del dominio. Usa un registro A con la IP del servicio, o pon el CNAME en 'www' y redirige la raíz.");
      }
      if (!esHost(brutos[0])) throw new ErrorDns(`"${brutos[0]}" no parece un nombre de host válido.`);
      values = [brutos[0].replace(/\.$/, "")];
      break;
    }
    case "MX":
      values = brutos.map((v) => {
        const m = v.match(/^(\d{1,5})\s+(\S+)$/);
        if (!m) throw new ErrorDns(`Al valor MX "${v}" le falta la prioridad. El valor completo se escribe así: "10 mail.ejemplo.com".`);
        if (Number(m[1]) > 65535) throw new ErrorDns(`La prioridad "${m[1]}" pasa del máximo (65535).`);
        if (!esHost(m[2])) throw new ErrorDns(`"${m[2]}" no parece un nombre de host válido.`);
        return `${Number(m[1])} ${m[2].replace(/\.$/, "")}`;
      });
      break;
    case "TXT":
      values = brutos.map(normalizarTxt);
      break;
    case "NS":
      if (name === zona) {
        throw new ErrorDns("Los NS de la raíz los pone Route 53 y no se pueden cambiar desde aquí. Para mover el dominio a otro DNS, cámbialos en tu registrador.");
      }
      for (const v of brutos) if (!esHost(v)) throw new ErrorDns(`"${v}" no parece un nombre de servidor válido.`);
      values = brutos.map((v) => v.replace(/\.$/, ""));
      break;
    case "CAA":
      values = brutos.map((v) => {
        const m = v.match(/^(\d{1,3})\s+(issue|issuewild|iodef)\s+"?([^"]*)"?$/i);
        if (!m) throw new ErrorDns(`El valor CAA "${v}" debe verse así: 0 issue "letsencrypt.org".`);
        if (Number(m[1]) > 255) throw new ErrorDns(`El flag "${m[1]}" del CAA pasa del máximo (255).`);
        return `${Number(m[1])} ${m[2].toLowerCase()} "${m[3]}"`;
      });
      break;
    case "SRV": {
      if (!/^_[^.]+\._[^.]+\./.test(name)) {
        throw new ErrorDns('Un registro SRV necesita un nombre con la forma "_servicio._protocolo" (ejemplo: _sip._tcp).');
      }
      values = brutos.map((v) => {
        const m = v.match(/^(\d{1,5})\s+(\d{1,5})\s+(\d{1,5})\s+(\S+)$/);
        if (!m) throw new ErrorDns(`El valor SRV "${v}" debe verse así: 10 5 5060 sip.ejemplo.com.`);
        return `${Number(m[1])} ${Number(m[2])} ${Number(m[3])} ${m[4].replace(/\.$/, "")}`;
      });
      break;
    }
  }

  if (new Set(values).size !== values.length) throw new ErrorDns("El registro tiene valores repetidos.");
  const bytes = values.reduce((n, v) => n + v.length, 0);
  if (bytes > 32000) throw new ErrorDns("El registro es demasiado grande. Divídelo en varios nombres.");

  return { name, type: tipo, ttl, values };
}

/**
 * Un CNAME no puede convivir con ningún otro tipo en el mismo nombre: es la regla que más
 * gente rompe, y el DNS resultante se comporta de forma impredecible en vez de fallar claro.
 */
export function conflictoDeConvivencia(nuevo: RRSet, existentes: RRSet[]): string | null {
  const mismos = existentes.filter((r) => r.name === nuevo.name && r.type !== nuevo.type);
  if (!mismos.length) return null;

  if (nuevo.type === "CNAME") {
    return `Ya existe un registro ${mismos[0].type} en ${nuevo.name}. Un CNAME no puede convivir con otros registros: bórralos primero, o usa otro subdominio.`;
  }
  if (mismos.some((r) => r.type === "CNAME")) {
    return `Ya existe un CNAME en ${nuevo.name}. Un CNAME no puede convivir con otros registros: bórralo primero, o usa otro subdominio.`;
  }
  return null;
}

// --- Guardián de los registros de MailMask ---

export interface DominioGestionado {
  domain: string;
  verificationToken: string;
  dkimTokens: string[];
}

interface Gestionado {
  name: string;
  type: RRSetTipo;
  /** `total` no se toca; `parcial` deja editar mientras conserve `debeContener`. */
  modo: "total" | "parcial";
  razon: string;
  debeContener?: string;
}

/**
 * Se **deriva** de la fila de `domains`, no de una lista guardada aparte que pueda quedar
 * desincronizada del DNS real.
 */
export function registrosGestionados(d: DominioGestionado): Gestionado[] {
  const apex = d.domain.toLowerCase();
  const lista: Gestionado[] = [
    { name: apex, type: "MX", modo: "total", razon: "Recepción de correo de MailMask" },
    { name: `_amazonses.${apex}`, type: "TXT", modo: "total", razon: "Verificación del dominio en SES" },
    // El TXT de la raíz es parcial a propósito: ahí conviven nuestro SPF y las
    // verificaciones de Google, Stripe o Facebook. Bloquearlo entero impediría al cliente
    // verificar su dominio en cualquier otro servicio.
    {
      name: apex,
      type: "TXT",
      modo: "parcial",
      razon: "Contiene el SPF de MailMask: puedes añadir valores, pero no quitarlo",
      debeContener: SPF_MAILMASK,
    },
  ];
  for (const t of d.dkimTokens ?? []) {
    lista.push({ name: `${t}._domainkey.${apex}`, type: "CNAME", modo: "total", razon: "Firma DKIM de tu dominio" });
  }
  return lista;
}

/**
 * Un CNAME de DKIM de SES, aunque no esté en `dkimTokens`. La lista de tokens puede venir
 * vacía o desfasada (un dominio a medio verificar, una fila restaurada de un respaldo), y
 * entonces la firma del cliente quedaba editable: cualquiera podía borrarla.
 */
function esDkimDeSes(r: RRSet, apex: string): boolean {
  // Sólo se mira lo que vive bajo `_domainkey`: un CNAME cualquiera que apunte a Amazon no
  // es nuestra firma y bloquearlo sería frenar al cliente por parecido.
  if (r.type !== "CNAME" || !r.name.endsWith(`._domainkey.${apex}`)) return false;
  // Por el nombre (el token de SES son 32 caracteres) o por el destino. Lo primero atrapa
  // también el intento de *sustituir* la firma por otro valor; lo segundo, un token que no
  // conocíamos. Un `k1._domainkey` de Mailchimp o un `google._domainkey` siguen siendo del
  // cliente: sólo se protege lo que es de SES.
  const nombreDeSes = new RegExp(`^[a-z0-9]{32}\\._domainkey\\.${apex.replace(/\./g, "\\.")}$`).test(r.name);
  const destinoDeSes = r.values.some((v) => v.toLowerCase().replace(/\.$/, "").endsWith(".dkim.amazonses.com"));
  return nombreDeSes || destinoDeSes;
}

const DKIM_GESTIONADO: Omit<Gestionado, "name" | "type"> = {
  modo: "total",
  razon: "Firma DKIM de tu dominio",
};

/** El gestionado que le toca a un RRSet, si es que le toca alguno. */
function gestionadoDe(r: RRSet, gestionados: Gestionado[], apex: string): Gestionado | undefined {
  return gestionados.find((x) => x.name === r.name && x.type === r.type)
    ?? (esDkimDeSes(r, apex) ? { ...DKIM_GESTIONADO, name: r.name, type: r.type } : undefined);
}

/** Anota una lista de RRSets para la UI y para el agente. */
export function anotarRegistros(registros: RRSet[], d: DominioGestionado): RRSetAnotado[] {
  const gestionados = registrosGestionados(d);
  const apex = d.domain.toLowerCase();

  return registros.map((r) => {
    const g = gestionadoDe(r, gestionados, apex);
    if (!g) {
      // Los NS y el SOA de la raíz son de Route 53; se ven, no se tocan.
      if (r.name === apex && (r.type === "NS" || (r.type as string) === "SOA")) {
        return { ...r, managed: true, editable: false, managedReason: "Lo gestiona Route 53" };
      }
      return { ...r, managed: false, editable: true };
    }
    return {
      ...r,
      managed: true,
      editable: g.modo === "parcial",
      managedReason: g.razon,
      protectedValues: g.debeContener
        ? r.values.filter((v) => v.toLowerCase().includes(g.debeContener!))
        : undefined,
    };
  });
}

/**
 * Deja pasar o no un cambio. Devuelve `null` si se permite.
 *
 * **No lleva escotilla de forzado.** Si existiera un `?force=true`, un agente lo pondría a la
 * primera negativa: es literalmente lo que hace un LLM ante un 409. La salida legítima
 * —mover el correo a otro proveedor— ya existe y es borrar el dominio de MailMask.
 */
export function aplicarGuardian(
  accion: "upsert" | "delete",
  rrset: RRSet,
  d: DominioGestionado,
): ErrorDns | null {
  const apex = d.domain.toLowerCase();
  const g = gestionadoDe(rrset, registrosGestionados(d), apex);

  if (!g) {
    if (rrset.name === apex && (rrset.type === "NS" || (rrset.type as string) === "SOA")) {
      return new ErrorDns(`Los registros ${rrset.type} de la raíz los gestiona Route 53 y no se pueden cambiar desde aquí.`);
    }
    return null;
  }

  if (g.modo === "total" || accion === "delete") {
    return new ErrorDns(
      `El registro ${rrset.type} de ${rrset.name} lo gestiona MailMask para que tu correo funcione. Si lo cambias dejas de recibir correo, así que no se puede editar desde aquí. Si quieres mover el correo a otro proveedor, elimina el dominio de MailMask.`,
    );
  }

  // Parcial: puede editarse mientras conserve lo nuestro.
  if (g.debeContener && !rrset.values.some((v) => v.toLowerCase().includes(g.debeContener!))) {
    const sugeridos = fusionarSpfValores(rrset.values);
    return new ErrorDns(
      `Tienes que conservar el SPF de MailMask ("${SPF_MAILMASK}") en el TXT de la raíz, o tus correos empezarán a caer en spam. Añade tu valor como una cadena más, no lo sustituyas.`,
      sugeridos,
    );
  }
  return null;
}

/** La misma fusión que usa `configureDnsRecords`, para poder sugerir el arreglo en el 409. */
export function fusionarSpfValores(existentes: string[]): string[] {
  const spfPrevio = existentes.find((v) => v.replace(/"/g, "").trim().toLowerCase().startsWith("v=spf1"));
  const resto = existentes.filter((v) => v !== spfPrevio);

  if (!spfPrevio) return [...resto, `"v=spf1 ${SPF_MAILMASK} ~all"`];

  const crudo = spfPrevio.replace(/"/g, "").trim();
  if (crudo.toLowerCase().includes(SPF_MAILMASK)) return existentes;

  const partes = crudo.split(/\s+/);
  const iAll = partes.findIndex((p) => /^[-~?+]?all$/i.test(p));
  if (iAll === -1) partes.push(SPF_MAILMASK);
  else partes.splice(iAll, 0, SPF_MAILMASK);

  return [...resto, `"${partes.join(" ")}"`];
}

// --- Plantillas ---

export type Preset =
  | "vercel" | "netlify" | "github-pages" | "cloudflare-pages" | "render" | "fly"
  | "redirect-a-www" | "dmarc";

export interface DefinicionPreset {
  label: string;
  /** Qué hay que pasar en `target`, o `null` si no necesita nada. */
  pide: string | null;
  expandir(domain: string, target: string, subdominio?: string): RRSet[];
}

const cname = (name: string, valor: string): RRSet => ({ name, type: "CNAME", ttl: 300, values: [valor] });

/**
 * Los presets son **datos**, no código: cada uno expande a RRSets que pasan por la misma
 * validación y el mismo guardián que un cambio a mano.
 */
export const PRESETS: Record<Preset, DefinicionPreset> = {
  "vercel": {
    label: "Vercel",
    pide: "El dominio que te dio Vercel, por ejemplo mi-proyecto.vercel.app",
    expandir: (d, t, sub) => sub && sub !== "@"
      ? [cname(`${sub}.${d}`, t)]
      : [{ name: d, type: "A", ttl: 300, values: ["76.76.21.21"] }, cname(`www.${d}`, t)],
  },
  "netlify": {
    label: "Netlify",
    pide: "El dominio que te dio Netlify, por ejemplo mi-sitio.netlify.app",
    expandir: (d, t, sub) => sub && sub !== "@"
      ? [cname(`${sub}.${d}`, t)]
      : [{ name: d, type: "A", ttl: 300, values: ["75.2.60.5"] }, cname(`www.${d}`, t)],
  },
  "github-pages": {
    label: "GitHub Pages",
    pide: "Tu dominio de GitHub Pages, por ejemplo usuario.github.io",
    expandir: (d, t, sub) => sub && sub !== "@"
      ? [cname(`${sub}.${d}`, t)]
      : [
        { name: d, type: "A", ttl: 300, values: ["185.199.108.153", "185.199.109.153", "185.199.110.153", "185.199.111.153"] },
        cname(`www.${d}`, t),
      ],
  },
  "cloudflare-pages": {
    label: "Cloudflare Pages",
    pide: "El dominio que te dio Cloudflare, por ejemplo mi-sitio.pages.dev",
    expandir: (d, t, sub) => [cname(`${sub && sub !== "@" ? sub : "www"}.${d}`, t)],
  },
  "render": {
    label: "Render",
    pide: "El dominio que te dio Render, por ejemplo mi-app.onrender.com",
    expandir: (d, t, sub) => [cname(`${sub && sub !== "@" ? sub : "www"}.${d}`, t)],
  },
  "fly": {
    label: "Fly.io",
    pide: "El dominio que te dio Fly, por ejemplo mi-app.fly.dev",
    expandir: (d, t, sub) => [cname(`${sub && sub !== "@" ? sub : "www"}.${d}`, t)],
  },
  "redirect-a-www": {
    label: "Mandar la raíz a www",
    pide: "El destino de www, por ejemplo mi-proyecto.vercel.app",
    expandir: (d, t) => [cname(`www.${d}`, t)],
  },
  "dmarc": {
    label: "Política DMARC",
    // Se ofrece, no se gestiona: hacerlo gestionado rompería a quien ya tenga una política
    // estricta propia.
    pide: "Un correo donde recibir los informes, por ejemplo tu@correo.com",
    expandir: (d, t) => [{
      name: `_dmarc.${d}`,
      type: "TXT",
      ttl: 300,
      values: [normalizarTxt(`v=DMARC1; p=none; rua=mailto:${t}`)],
    }],
  },
};

export function expandirPreset(preset: Preset, domain: string, target?: string, subdominio?: string): RRSet[] {
  const def = PRESETS[preset];
  if (!def) throw new ErrorDns(`No conozco la plantilla "${preset}". Las que hay: ${Object.keys(PRESETS).join(", ")}.`);
  if (def.pide && !target) throw new ErrorDns(`Falta el destino. ${def.pide}`);
  return def.expandir(domain.toLowerCase(), (target ?? "").trim().replace(/\.$/, ""), subdominio);
}

/** El MX de MailMask, para poder compararlo sin importar `route53.ts`. */
export const MX_MAILMASK = `10 inbound-smtp.${AWS_REGION}.amazonaws.com`;
