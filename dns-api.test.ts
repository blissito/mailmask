// Las rutas del editor de DNS contra la app real, con Route 53 en memoria.
//
// Lo que se fija aquí sobre todo es el guardián: quien llame a esta API puede ser un agente
// de IA que no ve nada, y borrar el MX o sustituir el TXT del apex le tumba el correo al
// cliente en silencio.

import { describe, it, before, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";

const suffix = Date.now();

// Zona de Route 53 en memoria, llaveada por `nombre|tipo`.
let zona = new Map<string, { name: string; type: string; ttl: number; values: string[] }>();
let zonasCreadas = 0;

const sembrar = (name: string, type: string, values: string[], ttl = 300) =>
  zona.set(`${name}|${type}`, { name, type, ttl, values });

describe("API de DNS", () => {
  // deno-lint-ignore no-explicit-any
  let app: any, dbmod: any, sqlite: any;
  let cookie = "";
  let csrf = "";
  let domainId = "";
  let ajenoId = "";
  const email = `dns-${suffix}@example.com`;
  const dominio = `dns-${suffix}.com`;

  before(async () => {
    mock.module("@aws-sdk/client-route-53", {
      namedExports: {
        Route53Client: class {
          // deno-lint-ignore no-explicit-any
          async send(cmd: any) {
            const i = cmd.input ?? {};
            switch (cmd.tipo) {
              case "ListResourceRecordSets":
                return {
                  IsTruncated: false,
                  ResourceRecordSets: [...zona.values()].map((r) => ({
                    Name: `${r.name}.`, Type: r.type, TTL: r.ttl,
                    ResourceRecords: r.values.map((v) => ({ Value: v })),
                  })),
                };
              case "ChangeResourceRecordSets":
                for (const c of i.ChangeBatch.Changes) {
                  const r = c.ResourceRecordSet;
                  const k = `${r.Name}|${r.Type}`;
                  if (c.Action === "DELETE") zona.delete(k);
                  else zona.set(k, { name: r.Name, type: r.Type, ttl: r.TTL, values: r.ResourceRecords.map((v: any) => v.Value) });
                }
                return { ChangeInfo: { Id: "/change/C1" } };
              case "ListHostedZonesByName":
                return { HostedZones: [] };
              case "CreateHostedZone":
                zonasCreadas++;
                return { HostedZone: { Id: "/hostedzone/ZTEST" }, DelegationSet: { NameServers: ["ns-1.awsdns-01.com", "ns-2.awsdns-02.net"] } };
              case "GetHostedZone":
                return { DelegationSet: { NameServers: ["ns-1.awsdns-01.com"] } };
              case "DeleteHostedZone":
                return {};
              default:
                throw new Error(`comando inesperado: ${cmd.tipo}`);
            }
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
    // Sondear el DNS de verdad desde una prueba sería lento y no determinista.
    mock.module("./dns-import.ts", {
      namedExports: {
        snapshotDns: async (d: string) => ({
          found: [{ name: `www.${d}`, type: "CNAME", ttl: 300, values: ["viejo.proveedor.com"] }],
          nameservers: ["ns1.proveedor.com"],
          warning: "aviso",
        }),
        delegacionActiva: async (_d: string, esperados: string[]) => ({ delegated: false, observed: ["ns1.proveedor.com"], expected: esperados }),
        nameserversActuales: async () => ["ns1.proveedor.com"],
      },
    });

    ({ app } = await import("./main.ts"));
    dbmod = await import("./db.ts");
    ({ sqlite } = await import("./pg.ts"));

    const { hashPassword } = await import("./auth.ts");
    dbmod.createUser(email, await hashPassword("password123"));
    const res = await app.fetch(new Request("http://localhost/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: "password123" }),
    }));
    // El login manda dos cookies: la sesión y el token CSRF, que además hay que repetir
    // como encabezado (double-submit) en todo lo que no sea GET.
    const galletas = (res.headers as any).getSetCookie?.() ?? [res.headers.get("set-cookie") ?? ""];
    cookie = galletas.map((c: string) => c.split(";")[0]).join("; ");
    csrf = /csrf_token=([^;]+)/.exec(cookie)?.[1] ?? "";

    domainId = dbmod.createDomain(email, dominio, ["a1", "b2", "c3"], "tokverif").id;

    const otroEmail = `dns-otro-${suffix}@example.com`;
    dbmod.createUser(otroEmail, await hashPassword("password123"));
    ajenoId = dbmod.createDomain(otroEmail, `ajeno-${suffix}.com`, ["x"], "t").id;
  });

  beforeEach(() => {
    sqlite.prepare("DELETE FROM rate_limits").run();
    zona = new Map();
    zonasCreadas = 0;
  });

  const pedir = (ruta: string, init: RequestInit = {}) =>
    app.fetch(new Request(`http://localhost${ruta}`, {
      ...init,
      headers: { "content-type": "application/json", cookie, "x-csrf-token": csrf, ...(init.headers ?? {}) },
    }));

  const conZona = () => sqlite.prepare("UPDATE domains SET hosted_zone_id = 'ZTEST', dns_zone_status = 'pending_delegation' WHERE id = ?").run(domainId);
  const sinZona = () => sqlite.prepare("UPDATE domains SET hosted_zone_id = NULL, dns_zone_status = 'none' WHERE id = ?").run(domainId);

  const upsert = (body: unknown) => pedir(`/api/domains/${domainId}/dns/records`, { method: "PUT", body: JSON.stringify(body) });

  it("sin zona responde 200 con una pista, no 404", async () => {
    // Un agente ante un 404 abandona; ante una pista accionable, actúa.
    sinZona();
    const r = await pedir(`/api/domains/${domainId}/dns`);
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.equal(j.zone.status, "none");
    assert.match(j.hint, /dns\/zone/);
  });

  it("crea la zona importando primero lo del proveedor anterior", async () => {
    sinZona();
    const r = await pedir(`/api/domains/${domainId}/dns/zone`, { method: "POST" });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.equal(j.nameservers.length, 2);
    assert.equal(j.imported.length, 1);

    // Lo del cliente tiene que estar en la zona ANTES de que delegue, o su web muere.
    assert.ok(zona.has(`www.${dominio}|CNAME`), "no se importó el CNAME del cliente");
    // Y lo nuestro encima.
    assert.ok(zona.has(`${dominio}|MX`));
    assert.ok(zona.has(`_amazonses.${dominio}|TXT`));
    assert.equal([...zona.values()].filter((r) => r.type === "CNAME" && r.name.includes("_domainkey")).length, 3);
  });

  it("no crea una segunda zona si ya hay una", async () => {
    conZona();
    const r = await pedir(`/api/domains/${domainId}/dns/zone`, { method: "POST" });
    assert.equal(r.status, 409);
    assert.equal(zonasCreadas, 0);
  });

  it("lista los registros marcando los gestionados", async () => {
    conZona();
    sembrar(dominio, "MX", ["10 inbound-smtp.us-east-1.amazonaws.com"]);
    sembrar(dominio, "TXT", ['"v=spf1 include:amazonses.com ~all"']);
    sembrar(`www.${dominio}`, "CNAME", ["x.vercel.app"]);

    const j = await (await pedir(`/api/domains/${domainId}/dns`)).json();
    const mx = j.records.find((r: any) => r.type === "MX");
    const txt = j.records.find((r: any) => r.type === "TXT");
    const www = j.records.find((r: any) => r.type === "CNAME");

    assert.deepEqual([mx.managed, mx.editable], [true, false]);
    assert.ok(mx.managedReason);
    // El TXT del apex es parcial: ahí también van las verificaciones de otros servicios.
    assert.deepEqual([txt.managed, txt.editable], [true, true]);
    assert.deepEqual([www.managed, www.editable], [false, true]);
  });

  it("crea un registro nuevo", async () => {
    conZona();
    const r = await upsert({ name: "www", type: "CNAME", values: ["cname.vercel-dns.com"] });
    assert.equal(r.status, 200);
    assert.deepEqual(zona.get(`www.${dominio}|CNAME`)!.values, ["cname.vercel-dns.com"]);
  });

  it("rechaza un TTL inválido y un CNAME en la raíz con 400", async () => {
    conZona();
    assert.equal((await upsert({ name: "www", type: "A", ttl: 5, values: ["1.2.3.4"] })).status, 400);
    const r = await upsert({ name: "@", type: "CNAME", values: ["x.vercel.app"] });
    assert.equal(r.status, 400);
    assert.match((await r.json()).error, /raíz del dominio/);
  });

  it("rechaza un CNAME donde ya hay otro tipo", async () => {
    conZona();
    sembrar(`www.${dominio}`, "A", ["1.2.3.4"]);
    const r = await upsert({ name: "www", type: "CNAME", values: ["x.com"] });
    assert.equal(r.status, 409);
    assert.match((await r.json()).error, /no puede convivir/);
  });

  it("no deja borrar el MX de MailMask", async () => {
    conZona();
    sembrar(dominio, "MX", ["10 inbound-smtp.us-east-1.amazonaws.com"]);
    const r = await pedir(`/api/domains/${domainId}/dns/records`, {
      method: "DELETE",
      body: JSON.stringify({ name: "@", type: "MX" }),
    });
    assert.equal(r.status, 409);
    assert.match((await r.json()).error, /dejas de recibir correo/);
    assert.ok(zona.has(`${dominio}|MX`), "el MX se borró de todos modos");
  });

  it("no deja quitar el SPF, y devuelve los valores ya corregidos", async () => {
    conZona();
    sembrar(dominio, "TXT", ['"v=spf1 include:amazonses.com ~all"']);
    const r = await upsert({ name: "@", type: "TXT", values: ["google-site-verification=abc"] });
    assert.equal(r.status, 409);
    const j = await r.json();
    assert.match(j.error, /caer en spam/);
    // El agente reintenta con esto sin tener que razonar la fusión.
    assert.ok(j.suggestedValues.some((v: string) => v.includes("include:amazonses.com")));

    const r2 = await upsert({ name: "@", type: "TXT", values: j.suggestedValues });
    assert.equal(r2.status, 200);
    assert.ok(zona.get(`${dominio}|TXT`)!.values.some((v) => v.includes("google-site-verification")));
  });

  it("aplica la plantilla de Vercel en un solo cambio", async () => {
    conZona();
    const r = await pedir(`/api/domains/${domainId}/dns/preset`, {
      method: "POST",
      body: JSON.stringify({ preset: "vercel", target: "mi-proyecto.vercel.app" }),
    });
    assert.equal(r.status, 200);
    assert.equal((await r.json()).records.length, 2);
    assert.deepEqual(zona.get(`${dominio}|A`)!.values, ["76.76.21.21"]);
    assert.deepEqual(zona.get(`www.${dominio}|CNAME`)!.values, ["mi-proyecto.vercel.app"]);
  });

  it("una plantilla que pisara el correo se rechaza entera", async () => {
    conZona();
    sembrar(dominio, "MX", ["10 inbound-smtp.us-east-1.amazonaws.com"]);
    const antes = new Map(zona);
    const r = await pedir(`/api/domains/${domainId}/dns/preset`, {
      method: "POST",
      body: JSON.stringify({ preset: "no-existe", target: "x" }),
    });
    assert.equal(r.status, 400);
    assert.deepEqual([...zona.keys()], [...antes.keys()]);
  });

  it("delegación: dice qué nameservers seguimos viendo", async () => {
    conZona();
    sqlite.prepare(`UPDATE domains SET dns_nameservers = '["ns-1.awsdns-01.com"]' WHERE id = ?`).run(domainId);
    const j = await (await pedir(`/api/domains/${domainId}/dns/delegation`)).json();
    assert.equal(j.delegated, false);
    assert.deepEqual(j.observed, ["ns1.proveedor.com"]);
  });

  it("el dominio de otra cuenta no existe para ti", async () => {
    assert.equal((await pedir(`/api/domains/${ajenoId}/dns`)).status, 404);
    assert.equal((await pedir(`/api/domains/${ajenoId}/dns/zone`, { method: "POST" })).status, 404);
  });

  it("sin sesión, 401", async () => {
    const r = await app.fetch(new Request(`http://localhost/api/domains/${domainId}/dns`));
    assert.equal(r.status, 401);
  });
});
