// `domain-provision.ts` leído contra un AWS FALSO con estado. Lo que se fija son los caminos
// que cobran o dejan sin dominio a alguien: el alta idempotente (no crea una segunda zona ni
// una segunda fila en `domains`), el transfer que no toca nada sin inventario de DNS
// aprobado, el dominio que ya es de otra cuenta, las transferencias en curso (aceptada,
// rechazada, sin auth code) y el sondeo que avanza sólo lo que AWS terminó.
//
// Se doblan los TRES clientes del SDK con el módulo real esparcido (ver pruebas-mocks.md):
// Route53Client, Route53DomainsClient y SESClient. Los comandos son los reales, así que
// `constructor.name` trae el nombre verdadero y el despacho es un `switch` por ese nombre.
// Lo que AWS "sabe" vive en las variables de abajo y se reinicia antes de cada caso. La base
// de datos sí es compartida con el resto de la suite, así que cada caso usa dominios y
// correos con sufijo único y filtra sus filas y alertas por id o por dominio.

import { describe, it, before, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";

const HORA = 3600_000;
const sufijo = `${Date.now()}`;
let contador = 0;
const dominioNuevo = () => `prov-${sufijo}-${++contador}.com.mx`;

type Registro = { name: string; type: string; ttl: number; values: string[] };
type Zona = { id: string; name: string; nameservers: string[]; records: Registro[] };
type DominioAws = { expiry: Date; nameservers: string[]; autoRenew: boolean };
type Alerta = { subject: string; destinos: string[]; raw: string };

/** Zonas hospedadas que existen "en AWS". Cada una guarda sus registros. */
let zonas: Zona[] = [];
/** Dominios registrados "en AWS" de esta cuenta. */
let dominiosAws = new Map<string, DominioAws>();
/** Estado de cada operación de transferencia. Lo que no esté aquí contesta IN_PROGRESS. */
let operaciones = new Map<string, string>();
/** Si está puesto, TransferDomain falla con este error (rechazo del registrador). */
let rechazoTransferencia: { name: string; message: string } | null = null;
/** Si es true, la siguiente VerifyDomainIdentity falla una vez (simula un corte a mitad). */
let fallarVerificacionUnaVez = false;
/** Cuántas veces se cambiaron los nameservers del dominio. */
let actualizacionesNs = 0;
/** Cada comando que recibió cualquier cliente falso, como `Route53:ListHostedZonesByNameCommand`. */
let comandosAws: string[] = [];
let alertas: Alerta[] = [];
let correos: { to: string; subject: string }[] = [];
let transferencias: { domain: string; authCode: string; contacto: string }[] = [];
let seq = 0;

function reiniciarAws() {
  zonas = [];
  dominiosAws = new Map();
  operaciones = new Map();
  rechazoTransferencia = null;
  fallarVerificacionUnaVez = false;
  actualizacionesNs = 0;
  comandosAws = [];
  alertas = [];
  correos = [];
  transferencias = [];
}

/** Lo que AWS sabe de una zona por su id, con o sin "/hostedzone/". */
const zonaPorId = (id: string) => zonas.find((z) => z.id === String(id).replace("/hostedzone/", ""));

/** Route 53 (zonas). Fiel en lo que `route53.ts` lee: `Id` con prefijo, `Name` con punto final. */
class Route53Falso {
  // deno-lint-ignore no-explicit-any
  constructor(_config?: any) {}

  // deno-lint-ignore no-explicit-any
  async send(cmd: any): Promise<any> {
    const nombre = cmd.constructor.name;
    comandosAws.push(`Route53:${nombre}`);
    const input = cmd.input;
    switch (nombre) {
      case "ListHostedZonesByNameCommand": {
        return {
          HostedZones: zonas
            .filter((z) => z.name === `${String(input.DNSName).toLowerCase()}.`)
            .map((z) => ({ Id: `/hostedzone/${z.id}`, Name: z.name, Config: { PrivateZone: false } })),
        };
      }
      case "CreateHostedZoneCommand": {
        const n = ++seq;
        const zona: Zona = {
          id: `Z${sufijo}${n}`,
          name: `${input.Name}.`,
          nameservers: [`ns${n}-a.awsdns.test`, `ns${n}-b.awsdns.test`],
          records: [],
        };
        zonas.push(zona);
        return { HostedZone: { Id: `/hostedzone/${zona.id}`, Name: zona.name }, DelegationSet: { NameServers: zona.nameservers } };
      }
      case "GetHostedZoneCommand": {
        return { DelegationSet: { NameServers: zonaPorId(input.Id)?.nameservers ?? [] } };
      }
      case "ListResourceRecordSetsCommand": {
        const zona = zonaPorId(input.HostedZoneId);
        return {
          ResourceRecordSets: (zona?.records ?? []).map((r) => ({
            Name: r.name, Type: r.type, TTL: r.ttl, ResourceRecords: r.values.map((Value) => ({ Value })),
          })),
          IsTruncated: false,
        };
      }
      case "ChangeResourceRecordSetsCommand": {
        const zona = zonaPorId(input.HostedZoneId);
        if (!zona) throw Object.assign(new Error("zona inexistente"), { name: "NoSuchHostedZone" });
        for (const c of input.ChangeBatch.Changes) {
          const rs = c.ResourceRecordSet;
          zona.records = zona.records.filter((r) => !(r.name === rs.Name && r.type === rs.Type));
          if (c.Action === "UPSERT") {
            zona.records.push({ name: rs.Name, type: rs.Type, ttl: rs.TTL, values: rs.ResourceRecords.map((v: { Value: string }) => v.Value) });
          }
        }
        return { ChangeInfo: { Id: `/change/C${++seq}` } };
      }
      default:
        throw new Error(`comando de Route 53 no esperado en la prueba: ${nombre}`);
    }
  }
}

/** Route 53 Domains (el registrador). El estado de la cuenta vive en `dominiosAws`. */
class RegistradorFalso {
  // deno-lint-ignore no-explicit-any
  constructor(_config?: any) {}

  // deno-lint-ignore no-explicit-any
  async send(cmd: any): Promise<any> {
    const nombre = cmd.constructor.name;
    comandosAws.push(`Domains:${nombre}`);
    const input = cmd.input;
    switch (nombre) {
      case "GetDomainDetailCommand": {
        const d = dominiosAws.get(input.DomainName);
        if (!d) throw Object.assign(new Error(`no está en la cuenta: ${input.DomainName}`), { name: "DomainNotFound" });
        return {
          ExpirationDate: d.expiry,
          AutoRenew: d.autoRenew,
          Nameservers: d.nameservers.map((Name) => ({ Name })),
          StatusList: [],
        };
      }
      case "UpdateDomainNameserversCommand": {
        const d = dominiosAws.get(input.DomainName);
        if (!d) throw Object.assign(new Error("no está en la cuenta"), { name: "DomainNotFound" });
        d.nameservers = input.Nameservers.map((n: { Name: string }) => n.Name);
        actualizacionesNs++;
        return {};
      }
      case "GetOperationDetailCommand": {
        return { Status: operaciones.get(input.OperationId) ?? "IN_PROGRESS" };
      }
      case "TransferDomainCommand": {
        if (rechazoTransferencia) {
          throw Object.assign(new Error(rechazoTransferencia.message), { name: rechazoTransferencia.name });
        }
        transferencias.push({
          domain: input.DomainName,
          authCode: input.AuthCode,
          contacto: input.RegistrantContact?.Email ?? "",
        });
        const operationId = `op-${sufijo}-${++seq}`;
        operaciones.set(operationId, "IN_PROGRESS");
        return { OperationId: operationId };
      }
      default:
        throw new Error(`comando de Route 53 Domains no esperado en la prueba: ${nombre}`);
    }
  }
}

/** SES: verificación de identidad, DKIM y alertas. Las alertas salen por `SendRawEmail`. */
class SesFalso {
  // deno-lint-ignore no-explicit-any
  constructor(_config?: any) {}

  // deno-lint-ignore no-explicit-any
  async send(cmd: any): Promise<any> {
    const nombre = cmd.constructor.name;
    comandosAws.push(`SES:${nombre}`);
    const input = cmd.input;
    switch (nombre) {
      case "VerifyDomainIdentityCommand": {
        if (fallarVerificacionUnaVez) {
          fallarVerificacionUnaVez = false;
          throw new Error("SES no contestó (prueba)");
        }
        return { VerificationToken: `vt-${input.Domain}` };
      }
      case "VerifyDomainDkimCommand": {
        return { DkimTokens: [`d1${input.Domain}`, `d2${input.Domain}`, `d3${input.Domain}`] };
      }
      case "SendRawEmailCommand": {
        const raw = new TextDecoder().decode(input.RawMessage.Data);
        const subject = raw.match(/^Subject: (.*)$/m)?.[1] ?? "";
        alertas.push({ subject, destinos: input.Destinations, raw });
        return { MessageId: `m-${++seq}` };
      }
      default:
        // `createConfigurationSet` lo tolera (es best-effort); cualquier otro comando es un error.
        throw new Error(`comando de SES no esperado en la prueba: ${nombre}`);
    }
  }
}

describe("aprovisionamiento de dominios (domain-provision.ts)", () => {
  // deno-lint-ignore no-explicit-any
  let DB: any;
  // deno-lint-ignore no-explicit-any
  let dp: any;
  // deno-lint-ignore no-explicit-any
  let transfer: any;

  before(async () => {
    // Los dobles van ANTES de que nadie importe el SDK o los módulos que lo usan.
    const r53 = await import("@aws-sdk/client-route-53");
    mock.module("@aws-sdk/client-route-53", {
      namedExports: { ...r53, Route53Client: Route53Falso as any },
    });
    const r53d = await import("@aws-sdk/client-route-53-domains");
    mock.module("@aws-sdk/client-route-53-domains", {
      namedExports: { ...r53d, Route53DomainsClient: RegistradorFalso as any },
    });
    const sesReal = await import("@aws-sdk/client-ses");
    mock.module("@aws-sdk/client-ses", {
      namedExports: { ...sesReal, SESClient: SesFalso as any },
    });

    // Correos: sólo se cuentan. El real manda por SES y no aporta nada a estas afirmaciones.
    const emailsReal = await import("./emails.ts");
    mock.module("./emails.ts", {
      namedExports: {
        ...emailsReal,
        sendTemplate: async (to: string, email: { subject: string }) => {
          correos.push({ to, subject: email.subject });
          return "id-falso";
        },
      },
    });

    // Nameservers del cliente fijos: la búsqueda real pregunta a DNS públicos.
    const dnsReal = await import("./dns-import.ts");
    mock.module("./dns-import.ts", {
      namedExports: {
        ...dnsReal,
        currentNameservers: async () => ["ns1.cliente.test", "ns2.cliente.test"],
      },
    });

    // Sin red: cualquier fetch en esta prueba es un error.
    (globalThis as any).fetch = async (url: unknown) => {
      throw new Error(`fetch inesperado en la prueba: ${String(url)}`);
    };

    DB = await import("./db.ts");
    dp = await import("./domain-provision.ts");
    transfer = await import("./domain-transfer.ts");
  });

  beforeEach(async () => {
    reiniciarAws();
    // Sin esto, un caso anterior en la misma hora silencia la alerta de este caso (throttle de 1 h).
    const { like } = await import("drizzle-orm");
    const { tokens } = await import("./schema.ts");
    DB.db.delete(tokens).where(like(tokens.token, "alert-throttle:%")).run();
  });

  /** Una alta de registro lista para aprovisionar, con su dueño dado de alta. */
  // deno-lint-ignore no-explicit-any
  function nuevaAlta(extra: Record<string, any> = {}) {
    const domainName = dominioNuevo();
    const ownerEmail = `dueno-${domainName}`;
    DB.createUser(ownerEmail, "x");
    const reg = DB.createDomainRegistration({
      domainName, ownerEmail, tld: "mx", priceCents: 100, awsCostCents: 50, kind: "register", ...extra,
    });
    DB.updateDomainRegistration(reg.id, { status: "registering" });
    return { domainName, ownerEmail, reg: DB.getDomainRegistration(reg.id) };
  }

  /** Un transfer-in pagado, con contacto WHOIS del cliente. */
  // deno-lint-ignore no-explicit-any
  function nuevaTransferencia(conInventario: boolean, estado = "registering") {
    const domainName = dominioNuevo();
    const ownerEmail = `dueno-${domainName}`;
    DB.createUser(ownerEmail, "x");
    const reg = DB.createDomainRegistration({
      domainName, ownerEmail, tld: "mx", priceCents: 100, awsCostCents: 50, kind: "transfer",
      whoisContact: {
        firstName: "Ana", lastName: "Cliente", email: `whois-${domainName}`, phone: "+525555555555",
        address: "Av. Reforma 1", city: "CDMX", state: "CDMX", country: "MX", zip: "06600",
      },
      ...(conInventario ? { dnsSnapshot: [{ name: domainName, type: "A", ttl: 300, values: ["192.0.2.10"] }] } : {}),
    });
    DB.updateDomainRegistration(reg.id, { status: estado });
    return { domainName, ownerEmail, reg: DB.getDomainRegistration(reg.id) };
  }

  describe("finalizeDomainRegistration", () => {
    it("un registro nuevo termina en `registered`, con zona, fecha de AWS y su fila en `domains`", async () => {
      const { domainName, ownerEmail, reg } = nuevaAlta();
      const expiry = new Date("2027-08-01T00:00:00.000Z");
      dominiosAws.set(domainName, { expiry, nameservers: ["ns-viejo.test"], autoRenew: true });

      await dp.finalizeDomainRegistration(reg);

      const fila = DB.getDomainRegistration(reg.id);
      assert.equal(fila.status, "registered");
      assert.equal(fila.expiresAt, expiry.toISOString(), "la fecha de expiración sale de AWS, no de un cálculo");
      assert.ok(fila.hostedZoneId, "la zona queda guardada en la registración");

      const zona = zonas.find((z) => z.name === `${domainName}.`);
      assert.ok(zona, "se creó la hosted zone");
      assert.equal(zona.id, fila.hostedZoneId);
      assert.deepEqual(dominiosAws.get(domainName)!.nameservers, zona.nameservers, "el dominio apunta a nuestra zona");

      const dominio = DB.getDomainByName(domainName);
      assert.ok(dominio, "hay fila en domains");
      assert.equal(dominio.ownerEmail, ownerEmail);
      assert.equal(dominio.verified, true);
      assert.equal(dominio.dnsZoneStatus, "active");
      assert.equal(dominio.hostedZoneId, zona.id);
      assert.equal(fila.domainId, dominio.id);

      assert.ok(correos.some((c) => c.to === ownerEmail), "el dueño recibe el aviso del alta");
    });

    it("reintentar el alta adopta la zona existente: no crea una segunda ni cambia de nuevo los nameservers", async () => {
      const { domainName, reg } = nuevaAlta();
      dominiosAws.set(domainName, { expiry: new Date("2027-08-01T00:00:00.000Z"), nameservers: ["ns-viejo.test"], autoRenew: true });

      // Primer intento: la zona se crea y los nameservers se cambian, y luego SES falla.
      fallarVerificacionUnaVez = true;
      await assert.rejects(() => dp.finalizeDomainRegistration(reg), /SES no contestó/);
      const tras1 = DB.getDomainRegistration(reg.id);
      assert.ok(tras1.hostedZoneId, "la zona quedó guardada antes del fallo");
      assert.equal(actualizacionesNs, 1);

      // Reintento: el mismo flujo, sin fallo.
      await dp.finalizeDomainRegistration(tras1);

      assert.equal(zonas.filter((z) => z.name === `${domainName}.`).length, 1, "no hay una segunda zona");
      assert.equal(comandosAws.filter((c) => c === "Route53:CreateHostedZoneCommand").length, 1);
      assert.equal(actualizacionesNs, 1, "el reintento no vuelve a cambiar los nameservers");
      assert.equal(DB.getDomainRegistration(reg.id).status, "registered");
      assert.ok(DB.getDomainByName(domainName), "la fila de domains existe una sola vez y se reusó");
    });

    it("un transfer sin inventario de DNS aprobado no toca AWS y deja su motivo", async () => {
      const { domainName, reg } = nuevaTransferencia(true, "registering");
      assert.equal(reg.dnsImportStatus, "discovered", "el inventario existe pero no está aprobado");

      await dp.finalizeDomainRegistration(reg);

      assert.deepEqual(comandosAws, [], "cero comandos de AWS de cualquier tipo");
      const fila = DB.getDomainRegistration(reg.id);
      assert.equal(fila.lastError, "dns_snapshot_no_aprobado");
      assert.equal(fila.status, "registering", "sigue esperando, no avanza");
      assert.equal(DB.getDomainByName(domainName), null, "no se creó fila en domains");
    });

    it("un dominio que ya es de otra cuenta no toca AWS y sólo avisa", async () => {
      const { domainName, reg } = nuevaAlta();
      const otro = `otro-${domainName}`;
      DB.createUser(otro, "x");
      DB.createDomain(otro, domainName, [], "vt-previo");

      await dp.finalizeDomainRegistration(reg);

      assert.equal(DB.getDomainRegistration(reg.id).lastError, "dominio_en_otra_cuenta");
      assert.equal(DB.getDomainByName(domainName).ownerEmail, otro, "la fila sigue siendo de la otra cuenta");
      // Lo único permitido es la alerta: el `SendRawEmail` de SES, nada de Route 53.
      assert.equal(comandosAws.length, 1);
      assert.equal(comandosAws[0], "SES:SendRawEmailCommand");
      const alerta = alertas.find((a) => a.subject.endsWith("dominio-en-otra-cuenta") && a.raw.includes(domainName));
      assert.ok(alerta, "avisa al equipo del dominio en otra cuenta");
    });
  });

  describe("marcarFalloDeAprovisionamiento", () => {
    it("un fallo reciente guarda el mensaje, sigue reintentable y no alerta", async () => {
      const { domainName, reg } = nuevaAlta();

      await dp.marcarFalloDeAprovisionamiento(reg, "error de prueba reciente");

      const fila = DB.getDomainRegistration(reg.id);
      assert.equal(fila.lastError, "error de prueba reciente");
      assert.equal(fila.status, "registering", "sigue en registering: el cron lo vuelve a intentar");
      assert.equal(alertas.filter((a) => a.raw.includes(domainName)).length, 0);
    });

    it("pasadas 2 h queda en `failed` y avisa", async () => {
      const { domainName, reg } = nuevaAlta();
      DB.updateDomainRegistration(reg.id, { registeredAt: new Date(Date.now() - 3 * HORA).toISOString() });
      const viejo = DB.getDomainRegistration(reg.id);

      await dp.marcarFalloDeAprovisionamiento(viejo, "error de prueba viejo");

      const fila = DB.getDomainRegistration(reg.id);
      assert.equal(fila.status, "failed");
      assert.equal(fila.lastError, "error de prueba viejo");
      const alerta = alertas.find((a) => a.subject.endsWith("dominio-aprovisionamiento") && a.raw.includes(domainName));
      assert.ok(alerta, "avisa de que se detuvo");
      assert.ok(alerta.raw.includes("error de prueba viejo"), "el aviso lleva el error");
    });
  });

  describe("iniciarTransferencia", () => {
    it("con el auth code guardado, AWS acepta: queda `transfer_submitted` y el código se consume", async () => {
      const { domainName, reg } = nuevaTransferencia(true, "transfer_paid");
      transfer.saveAuthCode(reg.id, "EPP-ABCD-1234");

      await dp.iniciarTransferencia(reg);

      assert.equal(transferencias.length, 1);
      assert.equal(transferencias[0].domain, domainName);
      assert.equal(transferencias[0].authCode, "EPP-ABCD-1234", "se manda el auth code real");
      assert.equal(transferencias[0].contacto, `whois-${domainName}`, "el contacto es el del cliente");
      const fila = DB.getDomainRegistration(reg.id);
      assert.equal(fila.status, "transfer_submitted");
      assert.ok(fila.route53OperationId, "queda la operación de AWS");
      assert.equal(transfer.takeAuthCode(reg.id), null, "el código no se queda guardado");
    });

    it("AWS rechaza: queda `transfer_failed` con el error de AWS y avisa", async () => {
      const { domainName, reg } = nuevaTransferencia(true, "transfer_paid");
      transfer.saveAuthCode(reg.id, "EPP-RECHAZO-9999");
      rechazoTransferencia = { name: "InvalidInput", message: "El registrador rechazó el código EPP" };

      await dp.iniciarTransferencia(reg);

      const fila = DB.getDomainRegistration(reg.id);
      assert.equal(fila.status, "transfer_failed");
      assert.equal(fila.lastError, "InvalidInput: El registrador rechazó el código EPP", "guarda el error de AWS, no uno genérico");
      const alerta = alertas.find((a) => a.subject.endsWith("transferencia-fallida") && a.raw.includes(domainName));
      assert.ok(alerta, "avisa para reembolsar");
    });

    it("sin auth code no manda nada a AWS y pide el código otra vez", async () => {
      const { domainName, ownerEmail, reg } = nuevaTransferencia(true, "transfer_paid");

      await dp.iniciarTransferencia(reg);

      assert.equal(transferencias.filter((t) => t.domain === domainName).length, 0, "no hubo TransferDomain");
      assert.equal(comandosAws.filter((c) => c.startsWith("Domains:")).length, 0);
      assert.equal(DB.getDomainRegistration(reg.id).status, "transfer_paid", "sigue pagada, sin mandar");
      assert.ok(correos.some((c) => c.to === ownerEmail), "el dueño recibe el aviso de que vuelva a mandar el código");
    });
  });

  describe("sondearTransferencias", () => {
    it("deja pendiente la que sigue en curso y avanza la que AWS completó o falló", async () => {
      const enCurso = nuevaTransferencia(true, "transfer_submitted");
      const completada = nuevaTransferencia(true, "transfer_submitted");
      const fallida = nuevaTransferencia(true, "transfer_submitted");
      const opEnCurso = `op-curso-${sufijo}`;
      const opOk = `op-ok-${sufijo}`;
      const opFallo = `op-fallo-${sufijo}`;
      operaciones.set(opEnCurso, "IN_PROGRESS");
      operaciones.set(opOk, "SUCCESSFUL");
      operaciones.set(opFallo, "FAILED");
      DB.updateDomainRegistration(enCurso.reg.id, { route53OperationId: opEnCurso });
      DB.updateDomainRegistration(completada.reg.id, { route53OperationId: opOk });
      DB.updateDomainRegistration(fallida.reg.id, { route53OperationId: opFallo });
      dominiosAws.set(completada.domainName, { expiry: new Date("2028-01-01T00:00:00.000Z"), nameservers: [], autoRenew: true });

      await dp.sondearTransferencias();

      assert.equal(DB.getDomainRegistration(enCurso.reg.id).status, "transfer_awaiting_approval");

      const ok = DB.getDomainRegistration(completada.reg.id);
      assert.equal(ok.status, "registering", "AWS completó: entra al aprovisionamiento");
      assert.ok(ok.transferApprovedAt);
      assert.ok(alertas.some((a) => a.subject.endsWith(`transferencia-completada:${completada.domainName}`)));

      const mal = DB.getDomainRegistration(fallida.reg.id);
      assert.equal(mal.status, "transfer_failed");
      assert.equal(mal.lastError, "Route 53 operation FAILED");
      assert.ok(alertas.some((a) => a.subject.endsWith("transferencia-fallida") && a.raw.includes(fallida.domainName)));
    });
  });
});
