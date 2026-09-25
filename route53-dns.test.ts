// El UPSERT ciego de `configureDnsRecords`.
//
// `ChangeResourceRecordSets` con UPSERT reemplaza el RRSet **completo**, no fusiona valores.
// Así que escribir nuestro SPF en el TXT del apex borraba la verificación de Google del
// cliente, y escribir nuestro MX borraba su correo en producción. En un dominio recién
// registrado la zona está vacía y no se nota; en uno conectado o migrado es una caída
// silenciosa. Estos tests son la red de esa regresión.

import { describe, it, before, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";

type RRSet = { name: string; type: string; ttl: number; values: string[] };

// Zona en memoria: lo que "tiene" Route 53 antes de la llamada.
let zona: RRSet[] = [];
// Lo que la llamada mandó.
let cambios: { Action: string; ResourceRecordSet: any }[] = [];
let zonasCreadas = 0;
let zonaExistente: string | null = null;

describe("configureDnsRecords y hosted zones", () => {
  // deno-lint-ignore no-explicit-any
  let r53: any;

  before(async () => {
    mock.module("@aws-sdk/client-route-53", {
      namedExports: {
        Route53Client: class {
          // deno-lint-ignore no-explicit-any
          async send(cmd: any) {
            if (cmd.tipo === "ListResourceRecordSets") {
              return {
                ResourceRecordSets: zona.map((r) => ({
                  Name: `${r.name}.`,
                  Type: r.type,
                  TTL: r.ttl,
                  ResourceRecords: r.values.map((v) => ({ Value: v })),
                })),
                IsTruncated: false,
              };
            }
            if (cmd.tipo === "ChangeResourceRecordSets") {
              cambios = cmd.input.ChangeBatch.Changes;
              return { ChangeInfo: { Id: "/change/C123" } };
            }
            if (cmd.tipo === "ListHostedZonesByName") {
              return zonaExistente
                ? { HostedZones: [{ Id: `/hostedzone/${zonaExistente}`, Name: `${cmd.input.DNSName}.`, Config: { PrivateZone: false } }] }
                : { HostedZones: [] };
            }
            if (cmd.tipo === "CreateHostedZone") {
              zonasCreadas++;
              zonaExistente = "ZNUEVA";
              return { HostedZone: { Id: "/hostedzone/ZNUEVA" }, DelegationSet: { NameServers: ["ns-1.awsdns-01.com"] } };
            }
            if (cmd.tipo === "GetHostedZone") {
              return { DelegationSet: { NameServers: ["ns-1.awsdns-01.com"] } };
            }
            throw new Error(`comando inesperado: ${cmd.tipo}`);
          }
        },
        ListResourceRecordSetsCommand: class { constructor(public input: any) {} tipo = "ListResourceRecordSets"; },
        ChangeResourceRecordSetsCommand: class { constructor(public input: any) {} tipo = "ChangeResourceRecordSets"; },
        ListHostedZonesByNameCommand: class { constructor(public input: any) {} tipo = "ListHostedZonesByName"; },
        CreateHostedZoneCommand: class { constructor(public input: any) {} tipo = "CreateHostedZone"; },
        GetHostedZoneCommand: class { constructor(public input: any) {} tipo = "GetHostedZone"; },
        DeleteHostedZoneCommand: class { constructor(public input: any) {} tipo = "DeleteHostedZone"; },
      },
    });
    r53 = await import("./route53.ts");
  });

  beforeEach(() => {
    zona = [];
    cambios = [];
    zonasCreadas = 0;
    zonaExistente = null;
  });

  const buscar = (name: string, type: string) =>
    cambios.find((c) => c.ResourceRecordSet.Name === name && c.ResourceRecordSet.Type === type);
  const valores = (name: string, type: string) =>
    (buscar(name, type)?.ResourceRecordSet.ResourceRecords ?? []).map((v: any) => v.Value);

  it("conserva la verificación de Google al escribir el SPF", async () => {
    zona = [{
      name: "ejemplo.com",
      type: "TXT",
      ttl: 300,
      values: ['"google-site-verification=abc123"', '"v=spf1 include:_spf.google.com ~all"'],
    }];

    await r53.configureDnsRecords("Z1", "ejemplo.com", "tok", []);

    const txt = valores("ejemplo.com", "TXT");
    assert.ok(txt.includes('"google-site-verification=abc123"'), "se borró la verificación de Google");
    // Un solo SPF: dos registros v=spf1 en el apex son un SPF inválido, no dos políticas.
    assert.equal(txt.filter((v: string) => v.includes("v=spf1")).length, 1);
    const spf = txt.find((v: string) => v.includes("v=spf1"));
    assert.ok(spf.includes("include:_spf.google.com"), "se perdió el include del cliente");
    assert.ok(spf.includes("include:amazonses.com"), "no se añadió el nuestro");
    // El `all` se queda al final, que es donde el protocolo lo exige.
    assert.ok(/~all"$/.test(spf), `el all no quedó al final: ${spf}`);
  });

  it("escribe el SPF completo cuando el apex no tiene TXT", async () => {
    await r53.configureDnsRecords("Z1", "ejemplo.com", "tok", []);
    assert.deepEqual(valores("ejemplo.com", "TXT"), ['"v=spf1 include:amazonses.com ~all"']);
  });

  it("no duplica el include si ya está", async () => {
    zona = [{ name: "ejemplo.com", type: "TXT", ttl: 300, values: ['"v=spf1 include:amazonses.com ~all"'] }];
    await r53.configureDnsRecords("Z1", "ejemplo.com", "tok", []);
    const spf = valores("ejemplo.com", "TXT")[0];
    assert.equal(spf.match(/include:amazonses\.com/g).length, 1);
  });

  it("se niega a pisar el MX de otro proveedor", async () => {
    zona = [{ name: "ejemplo.com", type: "MX", ttl: 3600, values: ["1 aspmx.l.google.com"] }];

    await assert.rejects(
      () => r53.configureDnsRecords("Z1", "ejemplo.com", "tok", []),
      (e: any) => e.name === "MxAjenoError" && e.existentes.includes("1 aspmx.l.google.com"),
    );
    assert.equal(cambios.length, 0, "no debe mandar ningún cambio si aborta");
  });

  it("con preserveMx conserva el MX del cliente detrás del nuestro", async () => {
    zona = [{ name: "ejemplo.com", type: "MX", ttl: 3600, values: ["1 aspmx.l.google.com"] }];

    await r53.configureDnsRecords("Z1", "ejemplo.com", "tok", [], { preserveMx: true });

    const mx = valores("ejemplo.com", "MX");
    assert.ok(mx.some((v: string) => v.includes("inbound-smtp.")), "falta el nuestro");
    // Prioridad mayor = menos preferido: el correo entra por nosotros y el suyo queda de respaldo.
    assert.ok(mx.includes("101 aspmx.l.google.com"), `no se conservó con prioridad menor: ${mx}`);
  });

  it("con keepForeignMx (transfer-in) el MX del cliente no se toca", async () => {
    zona = [{ name: "ejemplo.com", type: "MX", ttl: 300, values: ["5 mx1.hostinger.com", "10 mx2.hostinger.com"] }];
    const r = await r53.configureDnsRecords("Z1", "ejemplo.com", "tok", [], { keepForeignMx: true });
    assert.equal(r.mxOurs, false);
    assert.equal(cambios.filter((c) => c.ResourceRecordSet.Type === "MX").length, 0, "no debe mandar cambios al MX");
  });

  it("escribe el TXT de verificación y un CNAME por token DKIM", async () => {
    await r53.configureDnsRecords("Z1", "ejemplo.com", "tok", ["a1", "b2", "c3"]);
    assert.deepEqual(valores("_amazonses.ejemplo.com", "TXT"), ['"tok"']);
    assert.deepEqual(valores("a1._domainkey.ejemplo.com", "CNAME"), ["a1.dkim.amazonses.com"]);
    assert.equal(cambios.filter((c) => c.ResourceRecordSet.Type === "CNAME").length, 3);
  });

  it("ensureHostedZone adopta la zona existente en vez de crear otra", async () => {
    zonaExistente = "ZVIEJA";
    const a = await r53.ensureHostedZone("ejemplo.com");
    assert.equal(a.hostedZoneId, "ZVIEJA");
    assert.equal(a.created, false);
    assert.equal(zonasCreadas, 0);
  });

  it("ensureHostedZone es idempotente: dos llamadas, una sola zona", async () => {
    // El CallerReference llevaba Date.now(), así que cada reintento del cron creaba otra
    // hosted zone para el mismo dominio: se pagan las dos y responde la equivocada.
    const a = await r53.ensureHostedZone("ejemplo.com");
    const b = await r53.ensureHostedZone("ejemplo.com");
    assert.equal(zonasCreadas, 1);
    assert.equal(a.hostedZoneId, b.hostedZoneId);
    assert.equal(a.created, true);
    assert.equal(b.created, false);
  });
});
