import { log } from "./logger.js";
import { AWS_REGION } from "./ses.js";

// Lazy-loaded AWS SDK clients (same pattern as ses.ts)
let _route53Domains: any;
let _route53: any;

async function getRoute53Domains() {
  if (!_route53Domains) {
    const { Route53DomainsClient } = await import("@aws-sdk/client-route-53-domains");
    // Route 53 Domains API is only available in us-east-1
    _route53Domains = new Route53DomainsClient({ region: "us-east-1" });
  }
  return _route53Domains;
}

async function getRoute53() {
  if (!_route53) {
    const { Route53Client } = await import("@aws-sdk/client-route-53");
    _route53 = new Route53Client({ region: "us-east-1" });
  }
  return _route53;
}

// --- WHOIS contact from env vars ---

export interface WhoisContact {
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
  address: string;
  city: string;
  state: string;
  country: string;
  zip: string;
  organization?: string;
}

/**
 * Contacto WHOIS. Sin argumento devuelve el de MailMask (los `REGISTRANT_*` del entorno),
 * que es lo que se usaba para todo hasta sep-2026. Con argumento, los datos del cliente:
 * en un transfer-in el dominio ya era suyo y ponerlo a nuestro nombre le quitaría algo que
 * ya tenía. No hace falta cuenta de AWS del cliente, sólo estos datos.
 */
function whoisContact(c?: WhoisContact) {
  if (c) {
    return {
      FirstName: c.firstName,
      LastName: c.lastName,
      Email: c.email,
      PhoneNumber: c.phone,
      AddressLine1: c.address,
      City: c.city,
      State: c.state,
      CountryCode: c.country as any,
      ZipCode: c.zip,
      ContactType: (c.organization ? "COMPANY" : "PERSON") as any,
      ...(c.organization ? { OrganizationName: c.organization } : {}),
    };
  }
  return {
    FirstName: process.env.REGISTRANT_FIRST_NAME ?? "MailMask",
    LastName: process.env.REGISTRANT_LAST_NAME ?? "Inc",
    Email: process.env.REGISTRANT_EMAIL ?? "admin@mailmask.studio",
    PhoneNumber: process.env.REGISTRANT_PHONE ?? "+52.5555555555",
    AddressLine1: process.env.REGISTRANT_ADDRESS ?? "Av. Reforma 222",
    City: process.env.REGISTRANT_CITY ?? "CDMX",
    State: process.env.REGISTRANT_STATE ?? "CDMX",
    CountryCode: (process.env.REGISTRANT_COUNTRY ?? "MX") as any,
    ZipCode: process.env.REGISTRANT_ZIP ?? "06600",
    ContactType: "COMPANY" as const,
    OrganizationName: "MailMask",
  };
}

// --- Check domain availability ---

export async function checkAvailability(domain: string): Promise<{ available: boolean; domain: string }> {
  const client = await getRoute53Domains();
  const { CheckDomainAvailabilityCommand } = await import("@aws-sdk/client-route-53-domains");

  const res = await client.send(new CheckDomainAvailabilityCommand({
    DomainName: domain,
  }));

  return {
    available: res.Availability === "AVAILABLE",
    domain,
  };
}

// --- Register domain ---

export async function registerDomain(domain: string, contacto?: WhoisContact): Promise<string> {
  const client = await getRoute53Domains();
  const { RegisterDomainCommand } = await import("@aws-sdk/client-route-53-domains");
  const contact = whoisContact(contacto);

  const res = await client.send(new RegisterDomainCommand({
    DomainName: domain,
    DurationInYears: 1,
    // Se queda encendido a propósito, y ningún cron lo apaga. Sin AutoRenew, cualquier
    // bug o caída el día del vencimiento pierde el dominio del cliente: rescatarlo en
    // redención cuesta ~$90 USD más el correo caído, contra los ~$13 que cuesta renovar
    // uno que quizá no nos pague. El impago se cobra e insiste; no se deja caer.
    AutoRenew: true,
    AdminContact: contact,
    RegistrantContact: contact,
    TechContact: contact,
    PrivacyProtectAdminContact: true,
    PrivacyProtectRegistrantContact: true,
    PrivacyProtectTechContact: true,
  }));

  const operationId = res.OperationId ?? "";
  log("info", "route53", "Domain registration submitted", { domain, operationId });
  return operationId;
}

// --- Get operation status ---

export async function getOperationStatus(operationId: string): Promise<"SUBMITTED" | "IN_PROGRESS" | "SUCCESSFUL" | "FAILED" | "ERROR"> {
  const client = await getRoute53Domains();
  const { GetOperationDetailCommand } = await import("@aws-sdk/client-route-53-domains");

  const res = await client.send(new GetOperationDetailCommand({
    OperationId: operationId,
  }));

  return (res.Status as any) ?? "ERROR";
}

// --- Domain detail: la fuente de verdad de la fecha de expiración ---

export interface DomainDetail {
  expirationDate: string | null;
  autoRenew: boolean;
  nameservers: string[];
  statusList: string[];
  transferLock: boolean;
}

/**
 * `expiresAt` tiene que salir de aquí y no de `Date.now() + 365 días`: AWS renueva sola
 * ~45 días antes en varios TLDs, y toda la ventana de cobro se calcula contra esta fecha.
 */
export async function getDomainDetail(domain: string): Promise<DomainDetail> {
  const client = await getRoute53Domains();
  const { GetDomainDetailCommand } = await import("@aws-sdk/client-route-53-domains");

  const res = await client.send(new GetDomainDetailCommand({ DomainName: domain }));
  const statusList: string[] = res.StatusList ?? [];

  return {
    expirationDate: res.ExpirationDate ? new Date(res.ExpirationDate).toISOString() : null,
    autoRenew: res.AutoRenew === true,
    nameservers: (res.Nameservers ?? []).map((n: any) => String(n.Name ?? "")).filter(Boolean),
    statusList,
    transferLock: statusList.includes("clientTransferProhibited"),
  };
}

/** Todos los dominios registrados en la cuenta, paginado. Para reconciliar contra la base. */
export async function listRegisteredDomains(): Promise<{ domainName: string; expirationDate: string | null; autoRenew: boolean }[]> {
  const client = await getRoute53Domains();
  const { ListDomainsCommand } = await import("@aws-sdk/client-route-53-domains");

  const salida: { domainName: string; expirationDate: string | null; autoRenew: boolean }[] = [];
  let marker: string | undefined;
  do {
    const res: any = await client.send(new ListDomainsCommand({ Marker: marker, MaxItems: 100 }));
    for (const d of res.Domains ?? []) {
      salida.push({
        domainName: String(d.DomainName ?? ""),
        expirationDate: d.Expiry ? new Date(d.Expiry).toISOString() : null,
        autoRenew: d.AutoRenew === true,
      });
    }
    marker = res.NextPageMarker;
  } while (marker);

  return salida;
}

/** Renovación explícita. Rescate manual: no la llama ningún cron. */
export async function renewDomain(domain: string, currentExpiryYear: number): Promise<string> {
  const client = await getRoute53Domains();
  const { RenewDomainCommand } = await import("@aws-sdk/client-route-53-domains");

  const res = await client.send(new RenewDomainCommand({
    DomainName: domain,
    DurationInYears: 1,
    CurrentExpiryYear: currentExpiryYear,
  }));

  log("warn", "route53", "Domain renewed explicitly", { domain, operationId: res.OperationId });
  return res.OperationId ?? "";
}

export async function enableAutoRenew(domain: string): Promise<void> {
  const client = await getRoute53Domains();
  const { EnableDomainAutoRenewCommand } = await import("@aws-sdk/client-route-53-domains");
  await client.send(new EnableDomainAutoRenewCommand({ DomainName: domain }));
  log("info", "route53", "AutoRenew enabled", { domain });
}

/**
 * ⚠️ Apagar AutoRenew es el único camino por el que se pierde un dominio de un cliente, y
 * es irreversible pasada la redención. NINGÚN cron debe llamar a esto: sólo el transfer-out
 * confirmado, cuando el dominio ya se va a otro registrador.
 */
export async function disableAutoRenew(domain: string): Promise<void> {
  const client = await getRoute53Domains();
  const { DisableDomainAutoRenewCommand } = await import("@aws-sdk/client-route-53-domains");
  await client.send(new DisableDomainAutoRenewCommand({ DomainName: domain }));
  log("warn", "route53", "AutoRenew DISABLED", { domain });
}

// --- Hosted zones ---

/** Escapes octales de Route 53 (`\052` = `*`) a texto normal. */
export function desescaparNombre(nombre: string): string {
  return nombre.replace(/\\(\d{3})/g, (_, oct) => String.fromCharCode(parseInt(oct, 8)));
}

function normalizarZona(nombre: string): string {
  return desescaparNombre(nombre).replace(/\.$/, "").toLowerCase();
}

/** Busca una hosted zone pública por nombre. Evita crear una segunda para el mismo dominio. */
export async function findHostedZoneByName(domain: string): Promise<string | null> {
  const client = await getRoute53();
  const { ListHostedZonesByNameCommand } = await import("@aws-sdk/client-route-53");

  const res: any = await client.send(new ListHostedZonesByNameCommand({ DNSName: domain, MaxItems: 10 }));
  for (const z of res.HostedZones ?? []) {
    if (z.Config?.PrivateZone) continue;
    if (normalizarZona(z.Name ?? "") === domain.toLowerCase()) {
      return String(z.Id ?? "").replace("/hostedzone/", "");
    }
  }
  return null;
}

export async function getHostedZoneNameservers(hostedZoneId: string): Promise<string[]> {
  const client = await getRoute53();
  const { GetHostedZoneCommand } = await import("@aws-sdk/client-route-53");
  const res: any = await client.send(new GetHostedZoneCommand({ Id: hostedZoneId }));
  return res.DelegationSet?.NameServers ?? [];
}

/**
 * Crea la hosted zone, o adopta la que ya exista. Es idempotente a propósito: el
 * `CallerReference` llevaba `Date.now()`, así que cada reintento del cron creaba OTRA zona
 * para el mismo dominio — se pagan las dos ($0.50/mes cada una) y la mitad de las
 * respuestas salen de la equivocada.
 */
export async function ensureHostedZone(domain: string): Promise<{ hostedZoneId: string; nameservers: string[]; created: boolean }> {
  const existente = await findHostedZoneByName(domain);
  if (existente) {
    log("info", "route53", "Hosted zone adopted", { domain, hostedZoneId: existente });
    return { hostedZoneId: existente, nameservers: await getHostedZoneNameservers(existente), created: false };
  }

  const client = await getRoute53();
  const { CreateHostedZoneCommand } = await import("@aws-sdk/client-route-53");

  try {
    const res = await client.send(new CreateHostedZoneCommand({
      Name: domain,
      CallerReference: `mailmask-${domain}`,
      HostedZoneConfig: { Comment: `Managed by MailMask for ${domain}` },
    }));

    const hostedZoneId = res.HostedZone?.Id?.replace("/hostedzone/", "") ?? "";
    const nameservers = res.DelegationSet?.NameServers ?? [];
    log("info", "route53", "Hosted zone created", { domain, hostedZoneId, nameservers });
    return { hostedZoneId, nameservers, created: true };
  } catch (err: any) {
    // Carrera con otra petición, o un CallerReference ya usado: la zona existe, se adopta.
    if (err?.name === "HostedZoneAlreadyExists" || err?.name === "ConflictingDomainExists") {
      const id = await findHostedZoneByName(domain);
      if (id) {
        return { hostedZoneId: id, nameservers: await getHostedZoneNameservers(id), created: false };
      }
    }
    throw err;
  }
}

/** @deprecated Usa `ensureHostedZone`, que no duplica zonas. */
export async function createHostedZone(domain: string): Promise<{ hostedZoneId: string; nameservers: string[] }> {
  const { hostedZoneId, nameservers } = await ensureHostedZone(domain);
  return { hostedZoneId, nameservers };
}

/** Sólo para deshacer una creación fallida en la misma petición. Nunca se expone por API. */
export async function deleteHostedZone(hostedZoneId: string): Promise<void> {
  const client = await getRoute53();
  const { DeleteHostedZoneCommand } = await import("@aws-sdk/client-route-53");
  await client.send(new DeleteHostedZoneCommand({ Id: hostedZoneId }));
  log("warn", "route53", "Hosted zone deleted", { hostedZoneId });
}

// --- Registros ---

export interface RRSet {
  name: string;
  type: string;
  ttl: number;
  values: string[];
}

/** Todos los RRSets de la zona, paginado y con los nombres ya des-escapados. */
export async function listRecordSets(hostedZoneId: string): Promise<RRSet[]> {
  const client = await getRoute53();
  const { ListResourceRecordSetsCommand } = await import("@aws-sdk/client-route-53");

  const salida: RRSet[] = [];
  let startName: string | undefined;
  let startType: string | undefined;
  for (;;) {
    const res: any = await client.send(new ListResourceRecordSetsCommand({
      HostedZoneId: hostedZoneId,
      StartRecordName: startName,
      StartRecordType: startType,
      MaxItems: 300,
    } as any));

    for (const r of res.ResourceRecordSets ?? []) {
      // Los ALIAS no tienen ResourceRecords; se ignoran (fuera del alcance de la v1).
      if (!r.ResourceRecords?.length) continue;
      salida.push({
        name: normalizarZona(r.Name ?? ""),
        type: String(r.Type ?? ""),
        ttl: Number(r.TTL ?? 300),
        values: r.ResourceRecords.map((v: any) => String(v.Value ?? "")),
      });
    }

    if (!res.IsTruncated) break;
    startName = res.NextRecordName;
    startType = res.NextRecordType;
  }

  return salida;
}

export type CambioDns = { action: "UPSERT" | "DELETE"; rrset: RRSet };

export async function applyRecordChanges(
  hostedZoneId: string,
  cambios: CambioDns[],
  comment = "MailMask DNS change",
): Promise<{ changeId: string }> {
  const client = await getRoute53();
  const { ChangeResourceRecordSetsCommand } = await import("@aws-sdk/client-route-53");

  const res: any = await client.send(new ChangeResourceRecordSetsCommand({
    HostedZoneId: hostedZoneId,
    ChangeBatch: {
      Comment: comment.slice(0, 256),
      Changes: cambios.map((c) => ({
        Action: c.action,
        ResourceRecordSet: {
          Name: c.rrset.name,
          Type: c.rrset.type,
          TTL: c.rrset.ttl,
          ResourceRecords: c.rrset.values.map((v) => ({ Value: v })),
        },
      })),
    },
  } as any));

  return { changeId: String(res.ChangeInfo?.Id ?? "").replace("/change/", "") };
}

// --- Configure DNS records (MX, TXT, DKIM CNAMEs, SPF) ---

export class MxAjenoError extends Error {
  constructor(public readonly existentes: string[]) {
    super("El dominio ya tiene registros MX de otro proveedor");
    this.name = "MxAjenoError";
  }
}

const SPF_MAILMASK = "include:amazonses.com";

/** Fusiona nuestro SPF con el que ya tuviera el apex, en un solo registro. */
export function fusionarSpf(existentes: string[]): string[] {
  const spfPrevio = existentes.find((v) => v.replace(/"/g, "").trim().toLowerCase().startsWith("v=spf1"));
  const resto = existentes.filter((v) => v !== spfPrevio);

  if (!spfPrevio) {
    return [...resto, `"v=spf1 ${SPF_MAILMASK} ~all"`];
  }

  const crudo = spfPrevio.replace(/"/g, "").trim();
  if (crudo.toLowerCase().includes(SPF_MAILMASK)) return existentes;

  // El `all` va al final por definición: se le mete el include justo antes.
  const partes = crudo.split(/\s+/);
  const iAll = partes.findIndex((p) => /^[-~?+]?all$/i.test(p));
  if (iAll === -1) partes.push(SPF_MAILMASK);
  else partes.splice(iAll, 0, SPF_MAILMASK);

  return [...resto, `"${partes.join(" ")}"`];
}

/**
 * Escribe los registros de correo de MailMask **sin pisar lo que el cliente ya tenía**.
 *
 * Antes esto hacía un UPSERT ciego: el UPSERT reemplaza el RRSet completo, así que el TXT
 * del apex se llevaba por delante la verificación de Google y el SPF ajeno, y el MX borraba
 * el correo en producción del cliente. En un dominio recién registrado la zona está vacía y
 * no se notaba; en uno conectado o migrado es una caída silenciosa.
 */
export async function configureDnsRecords(
  hostedZoneId: string,
  domain: string,
  verificationToken: string,
  dkimTokens: string[],
  opts: { preserveMx?: boolean } = {},
): Promise<void> {
  const existentes = await listRecordSets(hostedZoneId);
  const apex = domain.toLowerCase();
  const buscar = (name: string, type: string) => existentes.find((r) => r.name === name && r.type === type);

  const mxNuestro = `10 inbound-smtp.${AWS_REGION}.amazonaws.com`;
  const mxPrevio = buscar(apex, "MX");
  const mxAjenos = (mxPrevio?.values ?? []).filter((v) => !v.includes("inbound-smtp."));

  if (mxAjenos.length && !opts.preserveMx) {
    // Pisar el MX de alguien es tumbarle el correo. Que lo decida quien llama.
    throw new MxAjenoError(mxAjenos);
  }

  const mxValores = opts.preserveMx && mxAjenos.length
    // Los del cliente quedan como respaldo, con prioridad más alta (= menos preferida).
    ? [mxNuestro, ...mxAjenos.map((v) => {
        const m = v.match(/^(\d+)\s+(.*)$/);
        return m ? `${Math.min(65535, Number(m[1]) + 100)} ${m[2]}` : v;
      })]
    : [mxNuestro];

  const txtApexPrevio = buscar(apex, "TXT")?.values ?? [];

  const cambios: CambioDns[] = [
    { action: "UPSERT", rrset: { name: apex, type: "MX", ttl: 300, values: mxValores } },
    { action: "UPSERT", rrset: { name: `_amazonses.${apex}`, type: "TXT", ttl: 300, values: [`"${verificationToken}"`] } },
    { action: "UPSERT", rrset: { name: apex, type: "TXT", ttl: 300, values: fusionarSpf(txtApexPrevio) } },
  ];

  for (const token of dkimTokens) {
    cambios.push({
      action: "UPSERT",
      rrset: { name: `${token}._domainkey.${apex}`, type: "CNAME", ttl: 300, values: [`${token}.dkim.amazonses.com`] },
    });
  }

  await applyRecordChanges(hostedZoneId, cambios, `MailMask email setup for ${domain}`);
  log("info", "route53", "DNS records configured", {
    domain, hostedZoneId, records: cambios.length, mxPreservados: mxAjenos.length,
  });
}

// --- Update nameservers (point registered domain to hosted zone NS) ---

export async function updateNameservers(domain: string, nameservers: string[]): Promise<void> {
  const client = await getRoute53Domains();
  const { UpdateDomainNameserversCommand } = await import("@aws-sdk/client-route-53-domains");

  await client.send(new UpdateDomainNameserversCommand({
    DomainName: domain,
    Nameservers: nameservers.map((ns) => ({ Name: ns })),
  }));

  log("info", "route53", "Nameservers updated", { domain, nameservers });
}

// --- Transferencias ---

export class TransferNoPosible extends Error {
  constructor(message: string, public readonly detalle?: string) {
    super(message);
    this.name = "TransferNoPosible";
  }
}

/** Se pregunta ANTES de cobrar: un transfer que AWS va a rechazar no se cobra. */
export async function checkTransferability(domain: string): Promise<{ transferable: boolean; motivo: string | null }> {
  const client = await getRoute53Domains();
  const { CheckDomainTransferabilityCommand } = await import("@aws-sdk/client-route-53-domains");

  const res: any = await client.send(new CheckDomainTransferabilityCommand({ DomainName: domain }));
  const t = res.Transferability?.Transferable ?? "DONT_KNOW";

  const motivos: Record<string, string> = {
    UNTRANSFERRABLE: "El registrador actual no permite transferirlo todavía. Suele ser porque se registró o se transfirió hace menos de 60 días.",
    DOESNT_HAVE_AUTHORIZATION_CODE: "Falta el código de autorización (EPP). Pídeselo a tu registrador actual.",
    DONT_KNOW: "No pudimos confirmarlo con el registrador. Puedes intentarlo de todos modos.",
    PREMIUM_DOMAIN: "Es un dominio premium y su transferencia se cotiza aparte. Escríbenos.",
  };

  return { transferable: t === "TRANSFERABLE", motivo: t === "TRANSFERABLE" ? null : (motivos[t] ?? t) };
}

/**
 * Inicia el transfer-in. Tarda de 5 a 7 días y depende de que el cliente conteste el correo
 * de aprobación que manda su registrador actual.
 *
 * `nameservers` son los **actuales del cliente**, a propósito: si no se mandan, AWS pone los
 * suyos al completarse y el dominio se queda sin su DNS de un momento a otro. Pasándolos, el
 * transfer no cambia nada y la migración a nuestra zona la hacemos después, ya con la zona
 * poblada. Eso convierte el momento más peligroso en un no-evento.
 */
export async function transferDomain(
  domain: string,
  authCode: string,
  nameservers: string[] = [],
  contacto?: WhoisContact,
): Promise<string> {
  const client = await getRoute53Domains();
  const { TransferDomainCommand } = await import("@aws-sdk/client-route-53-domains");
  const contact = whoisContact(contacto);

  const res = await client.send(new TransferDomainCommand({
    DomainName: domain,
    DurationInYears: 1,
    AuthCode: authCode,
    // El transfer-in de AWS ya incluye un año, y el AutoRenew se queda encendido por lo
    // mismo que en el alta: perder el dominio de un cliente es irreversible.
    AutoRenew: true,
    ...(nameservers.length ? { Nameservers: nameservers.map((n) => ({ Name: n })) } : {}),
    AdminContact: contact,
    RegistrantContact: contact,
    TechContact: contact,
    PrivacyProtectAdminContact: true,
    PrivacyProtectRegistrantContact: true,
    PrivacyProtectTechContact: true,
  }));

  log("info", "route53", "Domain transfer submitted", { domain, operationId: res.OperationId });
  return res.OperationId ?? "";
}

/** Cuando el cliente no encuentra el correo de aprobación. */
export async function resendTransferEmail(domain: string): Promise<void> {
  const client = await getRoute53Domains();
  const { ResendContactReachabilityEmailCommand } = await import("@aws-sdk/client-route-53-domains");
  await client.send(new ResendContactReachabilityEmailCommand({ domainName: domain }));
  log("info", "route53", "Transfer approval email resent", { domain });
}

// --- Transfer-out ---
//
// No es opcional. Sin esto, ofrecer migración entrante es asimétrico: el cliente puede
// meter su dominio y no sacarlo, que es la definición de un secuestro.

export async function disableDomainTransferLock(domain: string): Promise<void> {
  const client = await getRoute53Domains();
  const { DisableDomainTransferLockCommand } = await import("@aws-sdk/client-route-53-domains");
  await client.send(new DisableDomainTransferLockCommand({ DomainName: domain }));
  log("warn", "route53", "Transfer lock disabled", { domain });
}

export async function enableDomainTransferLock(domain: string): Promise<void> {
  const client = await getRoute53Domains();
  const { EnableDomainTransferLockCommand } = await import("@aws-sdk/client-route-53-domains");
  await client.send(new EnableDomainTransferLockCommand({ DomainName: domain }));
  log("info", "route53", "Transfer lock enabled", { domain });
}

/** ⚠️ Devolver este código es devolver el dominio: nunca se guarda ni se registra en logs. */
export async function retrieveDomainAuthCode(domain: string): Promise<string> {
  const client = await getRoute53Domains();
  const { RetrieveDomainAuthCodeCommand } = await import("@aws-sdk/client-route-53-domains");
  const res: any = await client.send(new RetrieveDomainAuthCodeCommand({ DomainName: domain }));
  log("warn", "route53", "Auth code retrieved", { domain });
  return res.AuthCode ?? "";
}

export async function updateDomainContact(domain: string, contacto: WhoisContact): Promise<void> {
  const client = await getRoute53Domains();
  const { UpdateDomainContactCommand } = await import("@aws-sdk/client-route-53-domains");
  const contact = whoisContact(contacto);
  await client.send(new UpdateDomainContactCommand({
    DomainName: domain,
    AdminContact: contact,
    RegistrantContact: contact,
    TechContact: contact,
  } as any));
  log("info", "route53", "WHOIS contact updated", { domain });
}

/** Precio vivo de un TLD en AWS, en centavos de USD. `null` si AWS no lo maneja. */
export async function listTldPrice(tld: string): Promise<{ transferUsdCents: number; renewUsdCents: number } | null> {
  const client = await getRoute53Domains();
  const { ListPricesCommand } = await import("@aws-sdk/client-route-53-domains");

  const res: any = await client.send(new ListPricesCommand({ Tld: tld.replace(/^\./, "") }));
  const p = res.Prices?.[0];
  if (!p) return null;

  // Sólo se confía en USD: convertir desde otra moneda a ciegas es como se vende bajo costo.
  const usd = (x: any) => (x?.Currency === "USD" && typeof x.Price === "number" ? Math.round(x.Price * 100) : 0);
  const transferUsdCents = usd(p.TransferPrice);
  if (!transferUsdCents) return null;

  return { transferUsdCents, renewUsdCents: usd(p.RenewalPrice) };
}
