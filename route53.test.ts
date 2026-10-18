// Suite propia de route53.ts: las funciones puras, la creación idempotente de la hosted zone, la
// protección de los MX ajenos y la lectura de transferabilidad. route53-dns.test.ts ya cubre el
// camino feliz de configureDnsRecords y ensureHostedZone; aquí sólo van los casos que faltaban.
//
// Dobles (ficha docs/agents/pruebas-mocks.md, «Doblar el cliente de AWS»): se sustituyen los dos
// clientes del SDK con el módulo real esparcido, así que los comandos son los de verdad y el
// despacho es por `cmd.constructor.name`. route53.ts se importa DENTRO de before(), después del doble.
// Además, una guardia de red (como cron.test.ts) registra y corta cualquier conexión o fetch.

import { describe, it, before, beforeEach, afterEach, after, mock } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";

type Zona = {
  Id: string;
  Name: string;
  Config: { PrivateZone: boolean };
  DelegationSet?: { NameServers: string[] };
};

type Registro = { Name: string; Type: string; TTL: number; ResourceRecords: { Value: string }[] };

type PaginaRegistros = {
  ResourceRecordSets: Registro[];
  IsTruncated: boolean;
  NextRecordName?: string;
  NextRecordType?: string;
};

const NAMESERVERS = ["ns-1.awsdns-01.com", "ns-2.awsdns-02.net"];

/** El SDK de AWS pone el código de error en `name`. */
function errorAws(name: string): Error {
  const err = new Error(name);
  err.name = name;
  return err;
}

// Estado de la cuenta falsa. Se reinicia en beforeEach.
let zonas: Zona[] = [];
// Paginas de ListResourceRecordSets, indexadas por StartRecordName ("" = primera página).
let paginasRegistros: Record<string, PaginaRegistros> = {};
let alCrearZona: { error?: string; dejaZona?: boolean } = {};
let zonasCreadas: any[] = [];
let cambiosEnviados: any[][] = [];
let respuestaTransferabilidad: any = {};
let comandos: string[] = [];

class FakeRoute53 {
  async send(cmd: { constructor: { name: string }; input: any }) {
    const nombre = cmd.constructor.name;
    comandos.push(nombre);
    switch (nombre) {
      case "ListHostedZonesByNameCommand":
        return { HostedZones: zonas.map((z) => ({ ...z })), IsTruncated: false };
      case "GetHostedZoneCommand": {
        // Route 53 recibe el Id sin el prefijo /hostedzone/ y lo contesta con él.
        const zona = zonas.find((z) => z.Id === `/hostedzone/${cmd.input.Id}`);
        return { HostedZone: zona, DelegationSet: zona?.DelegationSet };
      }
      case "CreateHostedZoneCommand": {
        zonasCreadas.push(structuredClone(cmd.input));
        const nombreZona = `${cmd.input.Name}.`;
        if (alCrearZona.error) {
          // La carrera: otra petición creó la zona justo antes, y ya es visible.
          if (alCrearZona.dejaZona) {
            zonas.push({ Id: "/hostedzone/ZCARRERA", Name: nombreZona, Config: { PrivateZone: false }, DelegationSet: { NameServers: NAMESERVERS } });
          }
          throw errorAws(alCrearZona.error);
        }
        const zona: Zona = { Id: "/hostedzone/ZNUEVA", Name: nombreZona, Config: { PrivateZone: false }, DelegationSet: { NameServers: NAMESERVERS } };
        zonas.push(zona);
        return { HostedZone: zona, DelegationSet: zona.DelegationSet };
      }
      case "ListResourceRecordSetsCommand":
        return structuredClone(paginasRegistros[cmd.input.StartRecordName ?? ""] ?? { ResourceRecordSets: [], IsTruncated: false });
      case "ChangeResourceRecordSetsCommand":
        cambiosEnviados.push(structuredClone(cmd.input.ChangeBatch.Changes));
        return { ChangeInfo: { Id: "/change/CAMBIO1" } };
      default:
        throw new Error(`comando de Route 53 no esperado: ${nombre}`);
    }
  }
}

class FakeRoute53Domains {
  async send(cmd: { constructor: { name: string } }) {
    const nombre = cmd.constructor.name;
    comandos.push(nombre);
    if (nombre === "CheckDomainTransferabilityCommand") return structuredClone(respuestaTransferabilidad);
    throw new Error(`comando de Route 53 Domains no esperado: ${nombre}`);
  }
}

const ORIGINAL_PREVIEW = process.env.PREVIEW;
const conexionesBloqueadas: string[] = [];
const fetchBloqueados: string[] = [];
const connectOriginal = net.Socket.prototype.connect;
const fetchOriginal = globalThis.fetch;

describe("route53.ts", () => {
  let r53: typeof import("./route53.ts");

  before(async () => {
    (net.Socket.prototype as any).connect = function (...args: unknown[]) {
      conexionesBloqueadas.push(String(args[0]));
      throw new Error("conexión de red bloqueada en pruebas");
    };
    globalThis.fetch = (async (input: unknown) => {
      fetchBloqueados.push(String(input));
      throw new Error("fetch bloqueado en pruebas");
    }) as typeof fetch;

    const real53 = await import("@aws-sdk/client-route-53");
    mock.module("@aws-sdk/client-route-53", { namedExports: { ...real53, Route53Client: FakeRoute53 } });
    const realDominios = await import("@aws-sdk/client-route-53-domains");
    mock.module("@aws-sdk/client-route-53-domains", { namedExports: { ...realDominios, Route53DomainsClient: FakeRoute53Domains } });
    r53 = await import("./route53.ts");
  });

  beforeEach(() => {
    zonas = [];
    paginasRegistros = { "": { ResourceRecordSets: [], IsTruncated: false } };
    alCrearZona = {};
    zonasCreadas = [];
    cambiosEnviados = [];
    respuestaTransferabilidad = {};
    comandos = [];
    conexionesBloqueadas.length = 0;
    fetchBloqueados.length = 0;
  });

  afterEach(() => {
    if (ORIGINAL_PREVIEW === undefined) delete process.env.PREVIEW;
    else process.env.PREVIEW = ORIGINAL_PREVIEW;
  });

  after(() => {
    (net.Socket.prototype as any).connect = connectOriginal;
    globalThis.fetch = fetchOriginal;
  });

  describe("fusionarSpf (pura)", () => {
    it("sin SPF agrega el nuestro y conserva los demás TXT", () => {
      assert.deepEqual(r53.fusionarSpf(["google-site-verification=abc"]), [
        "google-site-verification=abc",
        '"v=spf1 include:amazonses.com ~all"',
      ]);
    });

    for (const all of ["-all", "~all", "?all"]) {
      it(`con SPF ajeno mete el include justo antes de ${all}`, () => {
        assert.deepEqual(r53.fusionarSpf([`"v=spf1 include:_spf.google.com ${all}"`]), [
          `"v=spf1 include:_spf.google.com include:amazonses.com ${all}"`,
        ]);
      });
    }

    it("sin mecanismo all lo agrega al final", () => {
      assert.deepEqual(r53.fusionarSpf(['"v=spf1 include:_spf.google.com"']), [
        '"v=spf1 include:_spf.google.com include:amazonses.com"',
      ]);
    });

    it("con el include ya presente devuelve el arreglo idéntico", () => {
      const existentes = ['"v=spf1 include:amazonses.com include:_spf.google.com -all"', "google-site-verification=abc"];
      assert.deepEqual(r53.fusionarSpf(existentes), existentes);
    });

    it("reconoce V=SPF1 en mayúsculas y deja un solo registro SPF", () => {
      assert.deepEqual(r53.fusionarSpf(['"V=SPF1 include:_spf.google.com ~all"']), [
        '"V=SPF1 include:_spf.google.com include:amazonses.com ~all"',
      ]);
    });
  });

  describe("normalizeZoneName y unescapeRecordName (puras)", () => {
    it("quita el punto final y baja a minúsculas", () => {
      assert.equal(r53.normalizeZoneName("Ejemplo.MX."), "ejemplo.mx");
    });

    it("des-escapa los octales de Route 53 (\\052 es el asterisco)", () => {
      assert.equal(r53.normalizeZoneName("\\052.ejemplo.com."), "*.ejemplo.com");
    });

    it("unescapeRecordName convierte \\100 en arroba", () => {
      assert.equal(r53.unescapeRecordName("usuario\\100ejemplo.com"), "usuario@ejemplo.com");
    });
  });

  describe("ensureHostedZone (SDK doblado)", () => {
    const DOMINIO = "ejemplo.mx";

    it("zona pública existente: la adopta, created:false, cero CreateHostedZone", async () => {
      zonas = [{ Id: "/hostedzone/ZEXIST", Name: "ejemplo.mx.", Config: { PrivateZone: false }, DelegationSet: { NameServers: NAMESERVERS } }];
      const res = await r53.ensureHostedZone(DOMINIO);
      assert.deepEqual(res, { hostedZoneId: "ZEXIST", nameservers: NAMESERVERS, created: false });
      assert.ok(!comandos.includes("CreateHostedZoneCommand"));
    });

    it("sólo hay zona PRIVADA con ese nombre: la ignora y crea la pública", async () => {
      zonas = [{ Id: "/hostedzone/ZPRIV", Name: "ejemplo.mx.", Config: { PrivateZone: true } }];
      const res = await r53.ensureHostedZone(DOMINIO);
      assert.equal(res.created, true);
      assert.equal(res.hostedZoneId, "ZNUEVA");
      assert.equal(comandos.filter((c) => c === "CreateHostedZoneCommand").length, 1);
    });

    it("no hay zona: la crea con CallerReference estable, id sin prefijo y created:true", async () => {
      const res = await r53.ensureHostedZone(DOMINIO);
      assert.deepEqual(res, { hostedZoneId: "ZNUEVA", nameservers: NAMESERVERS, created: true });
      assert.equal(zonasCreadas.length, 1);
      assert.equal(zonasCreadas[0].Name, DOMINIO);
      assert.equal(zonasCreadas[0].CallerReference, "mailmask-ejemplo.mx");
    });

    it("CreateHostedZone lanza HostedZoneAlreadyExists y la zona ya es visible: la adopta con created:false", async () => {
      alCrearZona = { error: "HostedZoneAlreadyExists", dejaZona: true };
      const res = await r53.ensureHostedZone(DOMINIO);
      assert.deepEqual(res, { hostedZoneId: "ZCARRERA", nameservers: NAMESERVERS, created: false });
      assert.equal(comandos.filter((c) => c === "ListHostedZonesByNameCommand").length, 2);
      assert.equal(comandos.filter((c) => c === "CreateHostedZoneCommand").length, 1);
    });

    it("ConflictingDomainExists con la zona visible: también la adopta", async () => {
      alCrearZona = { error: "ConflictingDomainExists", dejaZona: true };
      const res = await r53.ensureHostedZone(DOMINIO);
      assert.equal(res.created, false);
      assert.equal(res.hostedZoneId, "ZCARRERA");
    });

    it("HostedZoneAlreadyExists sin zona visible: propaga el error original", async () => {
      alCrearZona = { error: "HostedZoneAlreadyExists", dejaZona: false };
      await assert.rejects(r53.ensureHostedZone(DOMINIO), (err: any) => err.name === "HostedZoneAlreadyExists");
    });

    it("cualquier otro error de CreateHostedZone se propaga tal cual", async () => {
      alCrearZona = { error: "Throttling" };
      await assert.rejects(r53.ensureHostedZone(DOMINIO), (err: any) => err.name === "Throttling");
    });
  });

  describe("configureDnsRecords: MX ajeno y paginación", () => {
    const MX_AJENO = ["10 mx1.hostinger.com", "20 mx2.hostinger.com"];

    it("con un MX ajeno y sin opciones rechaza con MxAjenoError, trae los MX y no escribe nada", async () => {
      paginasRegistros = {
        "": { ResourceRecordSets: [{ Name: "ejemplo.mx.", Type: "MX", TTL: 300, ResourceRecords: MX_AJENO.map((Value) => ({ Value })) }], IsTruncated: false },
      };
      await assert.rejects(
        r53.configureDnsRecords("ZNUEVA", "ejemplo.mx", "verificacion", ["tok1"]),
        (err: any) => err instanceof r53.MxAjenoError && JSON.stringify(err.existentes) === JSON.stringify(MX_AJENO),
      );
      assert.equal(cambiosEnviados.length, 0);
      assert.ok(!comandos.includes("ChangeResourceRecordSetsCommand"));
    });

    it("con lista paginada: lee la segunda página y ve el MX ajeno que está ahí", async () => {
      paginasRegistros = {
        "": {
          ResourceRecordSets: [{ Name: "ejemplo.mx.", Type: "TXT", TTL: 300, ResourceRecords: [{ Value: '"google-site-verification=abc"' }] }],
          IsTruncated: true,
          NextRecordName: "ejemplo.mx.",
          NextRecordType: "MX",
        },
        "ejemplo.mx.": {
          ResourceRecordSets: [{ Name: "ejemplo.mx.", Type: "MX", TTL: 300, ResourceRecords: [{ Value: MX_AJENO[0] }] }],
          IsTruncated: false,
        },
      };
      await assert.rejects(
        r53.configureDnsRecords("ZNUEVA", "ejemplo.mx", "verificacion", ["tok1"]),
        (err: any) => err instanceof r53.MxAjenoError && err.existentes.length === 1 && err.existentes[0] === MX_AJENO[0],
      );
      assert.equal(comandos.filter((c) => c === "ListResourceRecordSetsCommand").length, 2);
      assert.equal(cambiosEnviados.length, 0);
    });
  });

  describe("checkTransferability", () => {
    const MOTIVOS: Record<string, string> = {
      UNTRANSFERABLE: "El registrador actual no permite transferirlo todavía. Suele ser porque se registró o se transfirió hace menos de 60 días.",
      DOMAIN_IN_OWN_ACCOUNT: "Este dominio ya está en nuestra cuenta de AWS. Escríbenos: no hay nada que transferir.",
      DOMAIN_IN_ANOTHER_ACCOUNT: "El dominio está en otra cuenta de AWS. Tiene que salir de ahí antes de transferirlo.",
      DOESNT_HAVE_AUTHORIZATION_CODE: "Falta el código de autorización (EPP). Pídeselo a tu registrador actual.",
      DONT_KNOW: "No pudimos confirmarlo con el registrador. Puedes intentarlo de todos modos.",
      PREMIUM_DOMAIN: "Es un dominio premium y su transferencia se cotiza aparte. Escríbenos.",
    };

    it("TRANSFERABLE: transferable true y motivo null", async () => {
      respuestaTransferabilidad = { Transferability: { Transferable: "TRANSFERABLE" } };
      assert.deepEqual(await r53.checkTransferability("ejemplo.mx"), { transferable: true, motivo: null });
    });

    for (const [codigo, motivo] of Object.entries(MOTIVOS)) {
      it(`${codigo}: transferable false y el motivo en español, nunca el enum crudo`, async () => {
        respuestaTransferabilidad = { Transferability: { Transferable: codigo } };
        assert.deepEqual(await r53.checkTransferability("ejemplo.mx"), { transferable: false, motivo });
      });
    }

    it("respuesta sin Transferability: cae al motivo de DONT_KNOW", async () => {
      respuestaTransferabilidad = {};
      assert.deepEqual(await r53.checkTransferability("ejemplo.mx"), { transferable: false, motivo: MOTIVOS.DONT_KNOW });
    });

    it("enum desconocido: se devuelve tal cual, para que se vea en el reporte", async () => {
      respuestaTransferabilidad = { Transferability: { Transferable: "ALGO_NUEVO" } };
      assert.deepEqual(await r53.checkTransferability("ejemplo.mx"), { transferable: false, motivo: "ALGO_NUEVO" });
    });
  });

  describe("PREVIEW", () => {
    it("con PREVIEW=1 checkTransferability lanza PreviewDeshabilitado antes de llegar al doble", async () => {
      process.env.PREVIEW = "1";
      await assert.rejects(r53.checkTransferability("ejemplo.mx"), (err: any) => err.name === "PreviewDeshabilitado");
      assert.equal(comandos.length, 0);
    });
  });

  it("guardia de red: ninguna prueba del archivo abrió una conexión ni mandó un fetch", () => {
    assert.deepEqual(conexionesBloqueadas, []);
    assert.deepEqual(fetchBloqueados, []);
  });
});
