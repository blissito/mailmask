// `syncDomainExpirations` leído contra la respuesta REAL de AWS.
//
// `domain-renewal.test.ts` y `transfer-lock.test.ts` doblan `./route53.ts` entero, así que
// nunca pasan por la forma en que AWS contesta: `ListDomains` paginado con
// `NextPageMarker`, `ExpirationDate` que llega como `Date` y no como texto, `StatusList`
// como la única fuente del candado. Aquí `route53.ts` corre de verdad: lo único falso es
// el SDK, un `Route53DomainsClient` que despacha por `cmd.constructor.name` contra una
// tabla en memoria y registra cada llamada.
//
// Lo que se fija son las cinco reglas del cron que deciden si a un cliente se le sigue
// cobrando: la fecha sale de AWS, una lista vacía no cierra nada, ausente con detalle
// sigue cobrándose, ausente sin detalle es transfer-out, y el candado se repone o alerta.

import { describe, it, before, beforeEach, after, mock } from "node:test";
import assert from "node:assert/strict";

const DAY = 864e5;
const suffix = Date.now();
/** El reloj real, para devolverlo al final: el proceso es de este archivo y nadie más. */
const fetchReal = globalThis.fetch;

/** Lo que "dice AWS" de los dominios de ESTE archivo. */
const aws = new Map<string, { expiry: Date; autoRenew: boolean; locked: boolean; nameservers: string[] }>();
/** Dominios que ya no aparecen en `ListDomains` (salieron de la cuenta). */
const fueraDeLaCuenta = new Set<string>();
/** Dominios cuyo `GetDomainDetail` falla con algo que NO es `DomainNotFound`. */
const detalleConError = new Map<string, string>();
/** `ListDomains` contesta `Domains: []`, como unas credenciales apuntando a otra cuenta. */
let listaVacia = false;
/** Si tiene un dominio, ése llega en la SEGUNDA página (el resto, en la primera). */
let enLaSegundaPagina: string | null = null;
/** Cada comando que recibió el cliente falso, como `ListDomainsCommand:ejemplo.com`. */
const llamadas: string[] = [];
const candadosPuestos: string[] = [];
const alertas: { tipo: string; mensaje: string }[] = [];
const correos: { to: string; subject: string }[] = [];
const llamadasFetch: { url: string; metodo: string; status?: string }[] = [];

// deno-lint-ignore no-explicit-any
const nombresRegistrados = (dbmod: any): string[] =>
  dbmod.getDomainRegistrationsByStatus("registered")
    .map((r: { domainName: string }) => r.domainName as string)
    .filter((n: string) => !fueraDeLaCuenta.has(n));

/** La vista de `ListDomains`: sólo nombre, `Expiry` y `AutoRenew`. */
const filaListDomains = (domainName: string) => {
  const d = aws.get(domainName);
  return {
    DomainName: domainName,
    Expiry: d?.expiry ?? new Date(Date.now() + 200 * DAY),
    AutoRenew: d?.autoRenew ?? true,
  };
};

/**
 * El cliente doblado. Sólo se sustituye `Route53DomainsClient`: los comandos son los
 * REALES (el módulo va esparcido), así que `constructor.name` es el nombre verdadero y
 * `route53.ts` recibe de vuelta algo con la forma que espera.
 */
class ClienteRoute53DomainsFalso {
  // deno-lint-ignore no-explicit-any
  constructor(_config?: any) {}

  // deno-lint-ignore no-explicit-any
  async send(cmd: any): Promise<any> {
    const comando = cmd?.constructor?.name ?? "?";
    const dominio: string | undefined = cmd?.input?.DomainName;
    llamadas.push(dominio ? `${comando}:${dominio}` : comando);

    switch (comando) {
      case "ListDomainsCommand": {
        if (listaVacia) return { Domains: [] };
        // `dbmod` todavía no existe cuando se construye el cliente: se resuelve aquí.
        const nombres = nombresRegistrados(DB);
        // Un dominio en la segunda página: si `listRegisteredDomains` no siguiera el
        // `NextPageMarker`, lo daría por ausente y le cerraría el cobro.
        if (enLaSegundaPagina && cmd?.input?.Marker !== "p2") {
          return {
            Domains: nombres.filter((n: string) => n !== enLaSegundaPagina).map(filaListDomains),
            NextPageMarker: "p2",
          };
        }
        if (enLaSegundaPagina && cmd?.input?.Marker === "p2") {
          return { Domains: nombres.filter((n: string) => n === enLaSegundaPagina).map(filaListDomains) };
        }
        return { Domains: nombres.map(filaListDomains) };
      }

      case "GetDomainDetailCommand": {
        const error = detalleConError.get(dominio!);
        if (error) throw errorConNombre(error, `no se pudo leer ${dominio}: ${error}`);
        const d = aws.get(dominio!);
        // Igual que AWS: un dominio que no está en la cuenta no tiene detalle.
        if (!d) throw errorConNombre("DomainNotFound", `No such domain: ${dominio}`);
        return {
          ExpirationDate: d.expiry,
          AutoRenew: d.autoRenew,
          Nameservers: d.nameservers.map((Name) => ({ Name })),
          StatusList: d.locked ? ["clientTransferProhibited"] : [],
        };
      }

      case "EnableDomainTransferLockCommand": {
        candadosPuestos.push(dominio!);
        const d = aws.get(dominio!);
        if (d) d.locked = true;
        return {};
      }

      case "DisableDomainTransferLockCommand": {
        const d = aws.get(dominio!);
        if (d) d.locked = false;
        return {};
      }

      default:
        throw new Error(`comando sin doblar en la prueba: ${comando}`);
    }
  }
}

const errorConNombre = (name: string, message: string) => Object.assign(new Error(message), { name });

// deno-lint-ignore no-explicit-any
let DB: any;
// deno-lint-ignore no-explicit-any
let sync: any;

describe("sincronización de la fecha de expiración con AWS", () => {
  const email = `domain-sync-${suffix}@example.com`;

  before(async () => {
    // El doble va ANTES de que nadie importe el SDK: `route53.ts` cachea el cliente en
    // `_route53Domains` y lo pide con import() en caliente, así que llegaría tarde.
    const awsSdkReal = await import("@aws-sdk/client-route-53-domains");
    mock.module("@aws-sdk/client-route-53-domains", {
      namedExports: { ...awsSdkReal, Route53DomainsClient: ClienteRoute53DomainsFalso as any },
    });

    const sesReal = await import("./ses.ts");
    mock.module("./ses.ts", {
      namedExports: {
        ...sesReal,
        sendAlert: async (tipo: string, mensaje: string) => { alertas.push({ tipo, mensaje }); return true; },
        sendFromDomain: async (_from: string, to: string, subject: string) => {
          correos.push({ to, subject });
          return { messageId: "<x@test>", sesMessageId: "ses-x" };
        },
      },
    });

    DB = await import("./db.ts");
    sync = await import("./domain-sync.ts");

    // Sólo MercadoPago: cualquier otra salida a la red en esta prueba es un error.
    (globalThis as any).fetch = async (url: any, init: any = {}) => {
      const destino = String(url);
      const metodo = String(init?.method ?? "GET").toUpperCase();
      if (!destino.startsWith("https://api.mercadopago.com/preapproval/")) {
        throw new Error(`fetch inesperado en la prueba: ${metodo} ${destino}`);
      }
      llamadasFetch.push({
        url: destino,
        metodo,
        status: init?.body ? JSON.parse(String(init.body)).status : undefined,
      });
      return { ok: true, status: 200, text: async () => "{}", json: async () => ({}) };
    };

    const { hashPassword } = await import("./auth.ts");
    DB.createUser(email, await hashPassword("password123"));
  });

  after(() => { (globalThis as any).fetch = fetchReal; });

  beforeEach(() => {
    alertas.length = 0;
    correos.length = 0;
    llamadas.length = 0;
    candadosPuestos.length = 0;
    llamadasFetch.length = 0;
    detalleConError.clear();
    fueraDeLaCuenta.clear();
    listaVacia = false;
    enLaSegundaPagina = null;
  });

  /** Un dominio registrado y cobrándose. La base es compartida: el nombre lo hace único. */
  const registrar = (nombre: string, extra: Record<string, unknown> = {}) => {
    const domainName = `${nombre}-${suffix}.com`;
    const reg = DB.createDomainRegistration({
      domainName, ownerEmail: email, tld: ".com", priceCents: 59900, awsCostCents: 1300,
    });
    DB.updateDomainRegistration(reg.id, { status: "registered", expiresAt: "2020-01-01T00:00:00.000Z", ...extra });
    aws.set(domainName, {
      expiry: new Date("2027-06-01T00:00:00.000Z"),
      autoRenew: true,
      locked: false,
      nameservers: ["ns-1.awsdns-01.com"],
    });
    return DB.getDomainRegistration(reg.id);
  };

  const alertaDe = (tipo: string) => alertas.find((a) => a.tipo === tipo);

  it("guarda la fecha que reporta AWS, no la que tenía, y agenda el cobro 60 días antes", async () => {
    const reg = registrar("fecha");
    // `ExpirationDate` viaja como `Date`, que es lo que manda la API de verdad.
    aws.set(reg.domainName, { ...aws.get(reg.domainName)!, expiry: new Date("2028-03-15T00:00:00.000Z"), autoRenew: true });

    await sync.syncDomainExpirations();

    const fresco = DB.getDomainRegistration(reg.id);
    assert.equal(fresco.expiresAt, "2028-03-15T00:00:00.000Z");
    assert.equal(fresco.awsAutoRenew, true);
    assert.equal((Date.parse(fresco.expiresAt) - Date.parse(fresco.nextChargeAt)) / DAY, 60);
    assert.ok(fresco.lastSyncedAt, "no se marcó la última sincronización");
  });

  it("un dominio que llega en la segunda página de ListDomains no pierde el cobro", async () => {
    const reg = registrar("paginado", { renewalStatus: "active", mpPreapprovalId: `pre-pag-${suffix}` });
    enLaSegundaPagina = reg.domainName;

    await sync.syncDomainExpirations();

    enLaSegundaPagina = null;
    const fresco = DB.getDomainRegistration(reg.id);
    assert.equal(fresco.status, "registered");
    assert.equal(fresco.renewalStatus, "active");
    assert.equal(
      llamadas.filter((l) => l.startsWith("ListDomainsCommand")).length, 2,
      "no siguió el NextPageMarker",
    );
    assert.equal(alertaDe("transfer-out-completado"), undefined);
    assert.equal(llamadasFetch.length, 0);
  });

  it("una lista de dominios vacía no le quita el cobro a nadie", async () => {
    const reg = registrar("vacia", { renewalStatus: "active", mpPreapprovalId: `pre-vacia-${suffix}` });
    listaVacia = true;

    await sync.syncDomainExpirations();

    listaVacia = false;
    const fresco = DB.getDomainRegistration(reg.id);
    assert.equal(fresco.status, "registered");
    assert.equal(fresco.renewalStatus, "active");
    assert.equal(llamadasFetch.length, 0, "una lista vacía no debe cancelar nada en MercadoPago");
    assert.equal(alertaDe("transfer-out-completado"), undefined);
  });

  it("ausente de la lista pero AWS todavía lo describe: sigue cobrándose con la fecha nueva", async () => {
    const reg = registrar("ausente", { renewalStatus: "active", mpPreapprovalId: `pre-ausente-${suffix}` });
    aws.set(reg.domainName, { ...aws.get(reg.domainName)!, expiry: new Date("2028-09-01T00:00:00.000Z") });
    fueraDeLaCuenta.add(reg.domainName);

    await sync.syncDomainExpirations();

    const fresco = DB.getDomainRegistration(reg.id);
    assert.equal(fresco.status, "registered");
    assert.equal(fresco.renewalStatus, "active");
    assert.equal(fresco.expiresAt, "2028-09-01T00:00:00.000Z");
    assert.equal(llamadasFetch.length, 0);
  });

  it("ausente de la lista y AWS ya no lo describe: transfer-out consumado, sin renovación y con alerta", async () => {
    const reg = registrar("salido", { renewalStatus: "active", mpPreapprovalId: `pre-salido-${suffix}` });
    fueraDeLaCuenta.add(reg.domainName);
    aws.delete(reg.domainName);

    await sync.syncDomainExpirations();

    const fresco = DB.getDomainRegistration(reg.id);
    assert.equal(fresco.status, "transferred_out");
    assert.equal(fresco.renewalStatus, "cancelled");
    const cancelacion = llamadasFetch.filter((f) => f.url.endsWith(`/pre-salido-${suffix}`));
    assert.equal(cancelacion.length, 1, "no se canceló la preaprobación en MercadoPago");
    assert.equal(cancelacion[0].metodo, "PUT");
    assert.equal(cancelacion[0].status, "cancelled");
    const alerta = alertaDe("transfer-out-completado");
    assert.ok(alerta, "no se avisó del transfer-out consumado");
    assert.match(alerta!.mensaje, new RegExp(reg.domainName));
  });

  it("un candado de transferencia vencido se vuelve a poner y se avisa al dueño", async () => {
    const reg = registrar("candado", {
      transferLock: false,
      transferUnlockedUntil: new Date(Date.now() - DAY).toISOString(),
    });

    await sync.syncDomainExpirations();

    const fresco = DB.getDomainRegistration(reg.id);
    assert.deepEqual(candadosPuestos, [reg.domainName], "no se volvió a poner el candado en AWS");
    assert.equal(fresco.transferLock, true);
    assert.equal(fresco.transferUnlockedUntil, null, "no se cerró el plazo del desbloqueo");
    assert.ok(
      correos.some((c) => c.to === email && c.subject.includes(reg.domainName)),
      "no se avisó al dueño de que el candado volvió",
    );
  });

  it("un candado quitado por fuera de la app dispara la alerta de dominio sin candado", async () => {
    const reg = registrar("sin-candado", { transferLock: false, transferUnlockedUntil: null });

    await sync.syncDomainExpirations();

    const fresco = DB.getDomainRegistration(reg.id);
    assert.equal(fresco.transferLock, false);
    assert.equal(candadosPuestos.includes(reg.domainName), false, "no se repone sin fecha de regreso");
    const alerta = alertaDe(`dominio-sin-candado:${reg.domainName}`);
    assert.ok(alerta, "no se avisó de que el dominio quedó sin candado");
    assert.match(alerta!.mensaje, /SIN candado de transferencia/);
  });

  it(
    "un fallo pasajero al leer el detalle no debe cancelarle la renovación al cliente",
    {
      todo: "domain-sync.ts hace `.catch(() => false)` en la segunda opinión, así que CUALQUIER error (throttling, red) se lee como transfer-out consumado y le cancela la renovación a un cliente cuyo dominio sigue vivo. Sólo `DomainNotFound` debería contar. No se arregla aquí: lo reporta el plan.",
    },
    async () => {
      const reg = registrar("pasajero", { renewalStatus: "active", mpPreapprovalId: `pre-pasajero-${suffix}` });
      fueraDeLaCuenta.add(reg.domainName);
      aws.delete(reg.domainName);
      detalleConError.set(reg.domainName, "ThrottlingException");

      await sync.syncDomainExpirations();

      const fresco = DB.getDomainRegistration(reg.id);
      assert.equal(fresco.status, "registered", "un throttling no saca al dominio de la cuenta");
      assert.equal(fresco.renewalStatus, "active", "un throttling no debe cancelar la renovación");
      assert.equal(llamadasFetch.length, 0);
    },
  );
});
