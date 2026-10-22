// «Conectar sin mudarte»: delegar los nameservers a MailMask sin tocar el correo actual.
//
// Lo que se fija aquí: (1) el MX ajeno NUNCA se mueve —antes `/dns/zone` nos ponía delante
// de Google y Gmail dejaba de recibir en cuanto el cliente delegaba—; (2) un SPF nuevo
// incluye al proveedor que ya manda el correo, y con uno desconocido no se crea; (3) los
// nameservers no se enseñan hasta que el dueño confirma que revisó; (4) los NS de antes se
// guardan, se pueden descargar respaldos de la zona y el rollback de un clic sólo existe
// para dominios registrados aquí.

import { describe, it, before, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";

const suffix = Date.now();

type Rec = { name: string; type: string; ttl: number; values: string[] };
let zone = new Map<string, Rec>();
let snapshot: { found: Rec[]; nameservers: string[]; warning: string; truncado?: boolean };
let snapshotArgs: string[] = [];
let nsUpdates: { domain: string; ns: string[] }[] = [];
let zonesDeleted = 0;

const GOOGLE_MX = ["1 aspmx.l.google.com", "5 alt1.aspmx.l.google.com"];
const GODADDY_NS = ["ns43.domaincontrol.com", "ns44.domaincontrol.com"];

describe("Conectar sin mudarte (zona DNS que conserva el correo)", () => {
  // deno-lint-ignore no-explicit-any
  let app: any, dbmod: any, sqlite: any, r53: any, dnsRecords: any;
  let cookie = "";
  let csrf = "";
  let apiKey = "";
  const email = `keepmail-${suffix}@example.com`;
  const domain = `keepmail-${suffix}.org`;
  let domainId = "";

  before(async () => {
    mock.module("@aws-sdk/client-route-53", {
      namedExports: {
        Route53Client: class {
          // deno-lint-ignore no-explicit-any
          async send(cmd: any) {
            const i = cmd.input ?? {};
            switch (cmd.kind) {
              case "ListResourceRecordSets":
                return {
                  IsTruncated: false,
                  ResourceRecordSets: [...zone.values()].map((r) => ({
                    Name: `${r.name}.`, Type: r.type, TTL: r.ttl,
                    ResourceRecords: r.values.map((v) => ({ Value: v })),
                  })),
                };
              case "ChangeResourceRecordSets":
                for (const c of i.ChangeBatch.Changes) {
                  const r = c.ResourceRecordSet;
                  const k = `${r.Name}|${r.Type}`;
                  if (c.Action === "DELETE") zone.delete(k);
                  // deno-lint-ignore no-explicit-any
                  else zone.set(k, { name: r.Name, type: r.Type, ttl: r.TTL, values: r.ResourceRecords.map((v: any) => v.Value) });
                }
                return { ChangeInfo: { Id: "/change/C1" } };
              case "ListHostedZonesByName":
                return { HostedZones: [] };
              case "CreateHostedZone":
                return { HostedZone: { Id: "/hostedzone/ZKEEP" }, DelegationSet: { NameServers: ["ns-1.awsdns-01.com", "ns-2.awsdns-02.net"] } };
              case "GetHostedZone":
                return { DelegationSet: { NameServers: ["ns-1.awsdns-01.com", "ns-2.awsdns-02.net"] } };
              case "DeleteHostedZone":
                zonesDeleted++;
                return {};
              default:
                throw new Error(`comando inesperado: ${cmd.kind}`);
            }
          }
        },
        // deno-lint-ignore no-explicit-any
        ListResourceRecordSetsCommand: class { constructor(public input: any) {} kind = "ListResourceRecordSets"; },
        // deno-lint-ignore no-explicit-any
        ChangeResourceRecordSetsCommand: class { constructor(public input: any) {} kind = "ChangeResourceRecordSets"; },
        // deno-lint-ignore no-explicit-any
        ListHostedZonesByNameCommand: class { constructor(public input: any) {} kind = "ListHostedZonesByName"; },
        // deno-lint-ignore no-explicit-any
        CreateHostedZoneCommand: class { constructor(public input: any) {} kind = "CreateHostedZone"; },
        // deno-lint-ignore no-explicit-any
        GetHostedZoneCommand: class { constructor(public input: any) {} kind = "GetHostedZone"; },
        // deno-lint-ignore no-explicit-any
        DeleteHostedZoneCommand: class { constructor(public input: any) {} kind = "DeleteHostedZone"; },
      },
    });
    mock.module("@aws-sdk/client-route-53-domains", {
      namedExports: {
        Route53DomainsClient: class {
          // deno-lint-ignore no-explicit-any
          async send(cmd: any) {
            if (cmd.kind === "UpdateDomainNameservers") {
              // deno-lint-ignore no-explicit-any
              nsUpdates.push({ domain: cmd.input.DomainName, ns: cmd.input.Nameservers.map((n: any) => n.Name) });
              return { OperationId: "op-1" };
            }
            throw new Error(`comando inesperado: ${cmd.kind}`);
          }
        },
        // deno-lint-ignore no-explicit-any
        UpdateDomainNameserversCommand: class { constructor(public input: any) {} kind = "UpdateDomainNameservers"; },
      },
    });
    // Sondear el DNS de verdad desde una prueba sería lento y no determinista.
    mock.module("./dns-import.ts", {
      namedExports: {
        snapshotDns: async (_d: string, extra: string[] = []) => { snapshotArgs = extra; return snapshot; },
        getDelegationStatus: async (_d: string, expected: string[]) => ({ delegated: false, observed: GODADDY_NS, expected }),
        currentNameservers: async () => GODADDY_NS,
      },
    });

    ({ app } = await import("./main.ts"));
    dbmod = await import("./db.ts");
    ({ sqlite } = await import("./pg.ts"));
    r53 = await import("./route53.ts");
    dnsRecords = await import("./dns-records.ts");

    const { hashPassword } = await import("./auth.ts");
    dbmod.createUser(email, await hashPassword("password123"));
    const res = await app.fetch(new Request("http://localhost/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: "password123" }),
    }));
    // deno-lint-ignore no-explicit-any
    const cookies = (res.headers as any).getSetCookie?.() ?? [res.headers.get("set-cookie") ?? ""];
    cookie = cookies.map((c: string) => c.split(";")[0]).join("; ");
    csrf = /csrf_token=([^;]+)/.exec(cookie)?.[1] ?? "";
    apiKey = (await dbmod.createApiKey(email, "pruebas")).plaintextKey;
  });

  // Cada prueba arranca con un dominio nuevo, activado y sin zona.
  beforeEach(() => {
    sqlite.prepare("DELETE FROM rate_limits").run();
    zone = new Map();
    nsUpdates = [];
    zonesDeleted = 0;
    snapshotArgs = [];
    snapshot = {
      found: [
        { name: domain, type: "MX", ttl: 3600, values: GOOGLE_MX },
        { name: domain, type: "TXT", ttl: 3600, values: ['"google-site-verification=abc123"'] },
        { name: `www.${domain}`, type: "CNAME", ttl: 3600, values: ["fixter.github.io"] },
        { name: domain, type: "A", ttl: 600, values: ["185.199.108.153"] },
      ],
      nameservers: GODADDY_NS,
      warning: "aviso",
    };
    sqlite.prepare("DELETE FROM domains WHERE domain = ?").run(domain);
    domainId = dbmod.createDomain(email, domain, ["tok1", "tok2", "tok3"], "verif").id;
    const addon = dbmod.createAddon(email, "domain", domainId);
    dbmod.updateAddon(addon.id, { status: "active", currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString() });
  });

  const call = (path: string, init: RequestInit = {}) =>
    app.fetch(new Request(`http://localhost${path}`, {
      ...init,
      headers: { "content-type": "application/json", cookie, "x-csrf-token": csrf, ...(init.headers ?? {}) },
    }));
  const createZone = () => call(`/api/domains/${domainId}/dns/zone`, { method: "POST" });
  const confirm = (body: unknown) => call(`/api/domains/${domainId}/dns/zone/confirm`, { method: "POST", body: JSON.stringify(body) });

  it("el MX de Google queda intacto y el SPF nuevo incluye a Google", async () => {
    const r = await createZone();
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.equal(j.mailKept, true);
    assert.equal(j.mailProvider, "Google Workspace");

    // Exactamente el MX de Google: ni el nuestro delante ni el suyo degradado a respaldo.
    assert.deepEqual(zone.get(`${domain}|MX`)!.values, GOOGLE_MX);
    const txt = zone.get(`${domain}|TXT`)!.values;
    assert.ok(txt.includes('"google-site-verification=abc123"'), "se perdió la verificación de Google");
    const spf = txt.filter((v) => v.includes("v=spf1"));
    assert.equal(spf.length, 1);
    assert.match(spf[0], /include:_spf\.google\.com/);
    assert.match(spf[0], /include:amazonses\.com/);
    // Lo demás del cliente sigue ahí, y lo nuestro (verificación y DKIM) también.
    assert.ok(zone.has(`www.${domain}|CNAME`));
    assert.ok(zone.has(`_amazonses.${domain}|TXT`));
    assert.ok(zone.has(`tok1._domainkey.${domain}|CNAME`));
  });

  it("pasa los DKIM conocidos al inventario", async () => {
    await createZone();
    assert.ok(snapshotArgs.includes("tok1._domainkey"), "faltan nuestros DKIM en extraNames");
    assert.ok(snapshotArgs.includes("google._domainkey"));
    assert.ok(snapshotArgs.includes("zmail._domainkey"));
  });

  it("con un proveedor desconocido y sin SPF no crea SPF y lo avisa", async () => {
    snapshot.found = [{ name: domain, type: "MX", ttl: 300, values: ["10 mx.correo-raro.net"] }];
    const j = await (await createZone()).json();
    assert.equal(j.spf, "skipped");
    assert.ok(j.spfWarning, "falta el aviso de que no hay SPF");
    assert.ok(!zone.has(`${domain}|TXT`), "no debe inventar un SPF que rompa al proveedor actual");
    assert.deepEqual(zone.get(`${domain}|MX`)!.values, ["10 mx.correo-raro.net"]);
  });

  it("sin MX previo, el nuestro entra (no hay correo que romper)", async () => {
    snapshot.found = [];
    await createZone();
    assert.ok(zone.get(`${domain}|MX`)!.values.some((v) => v.includes("inbound-smtp.")));
    assert.deepEqual(zone.get(`${domain}|TXT`)!.values, ['"v=spf1 include:amazonses.com ~all"']);
  });

  it("no enseña los nameservers hasta confirmar la revisión", async () => {
    const j = await (await createZone()).json();
    assert.equal(j.status, "pending_review");
    assert.deepEqual(j.nameservers, []);
    assert.deepEqual(j.previousNameservers, GODADDY_NS);

    const list = await (await call(`/api/domains/${domainId}/dns`)).json();
    assert.equal(list.zone.status, "pending_review");
    assert.deepEqual(list.zone.nameservers, []);
    assert.deepEqual(list.zone.previousNameservers, GODADDY_NS);
    assert.equal((await call(`/api/domains/${domainId}/dns/delegation`)).status, 409);
  });

  it("confirm sin checked:true da 400 y no cambia nada", async () => {
    await createZone();
    assert.equal((await confirm({})).status, 400);
    assert.equal((await confirm({ checked: "yes" })).status, 400);
    assert.equal(dbmod.getDomain(domainId).dnsZoneStatus, "pending_review");
  });

  it("confirm con checked:true guarda el respaldo y devuelve los NS nuevos y los de antes", async () => {
    await createZone();
    const r = await confirm({ checked: true });
    assert.equal(r.status, 200);
    const j = await r.json();
    assert.deepEqual(j.nameservers, ["ns-1.awsdns-01.com", "ns-2.awsdns-02.net"]);
    assert.deepEqual(j.previousNameservers, GODADDY_NS);

    const d = dbmod.getDomain(domainId);
    assert.equal(d.dnsZoneStatus, "pending_delegation");
    assert.deepEqual(d.dnsPreviousNs, GODADDY_NS);
    assert.ok(d.dnsPreSnapshot.some((x: Rec) => x.type === "MX" && x.values.includes("1 aspmx.l.google.com")));

    // Idempotente, y ahora la lista sí trae los NS.
    assert.equal((await confirm({ checked: true })).status, 200);
    const list = await (await call(`/api/domains/${domainId}/dns`)).json();
    assert.equal(list.zone.nameservers.length, 2);
  });

  it("un dominio que ya estaba en pending_delegation sigue igual (compatibilidad)", async () => {
    sqlite.prepare(`UPDATE domains SET hosted_zone_id = 'ZVIEJA', dns_zone_status = 'pending_delegation', dns_nameservers = '["ns-9.awsdns-09.org"]' WHERE id = ?`).run(domainId);
    const list = await (await call(`/api/domains/${domainId}/dns`)).json();
    assert.equal(list.zone.status, "pending_delegation");
    assert.deepEqual(list.zone.nameservers, ["ns-9.awsdns-09.org"]);
    assert.equal(list.zone.rollbackAvailable, false);
    assert.equal((await call(`/api/domains/${domainId}/dns/delegation`)).status, 200);
  });

  it("exporta la zona actual y la revisada como archivo de zona descargable", async () => {
    await createZone();
    // Antes de confirmar no hay respaldo «pre».
    assert.equal((await call(`/api/domains/${domainId}/dns/export?which=pre`)).status, 409);

    const r = await call(`/api/domains/${domainId}/dns/export?which=current`);
    assert.equal(r.status, 200);
    assert.match(r.headers.get("content-type"), /text\/plain/);
    assert.match(r.headers.get("content-disposition"), new RegExp(`attachment; filename="${domain}\\.zone"`));
    const text = await r.text();
    assert.match(text, new RegExp(`\\$ORIGIN ${domain.replace(/\./g, "\\.")}\\.`));
    assert.match(text, /@\t3600\tIN\tMX\t1 aspmx\.l\.google\.com\./);
    assert.match(text, /www\.[^\t]+\.\t3600\tIN\tCNAME\tfixter\.github\.io\./);

    await confirm({ checked: true });
    const pre = await call(`/api/domains/${domainId}/dns/export?which=pre`);
    assert.equal(pre.status, 200);
    assert.match(pre.headers.get("content-disposition"), /-antes\.zone"/);
    assert.match(await pre.text(), /IN\tMX\t5 alt1\.aspmx\.l\.google\.com\./);
  });

  it("rollback: sólo con sesión, y para un dominio de otro registrador da los NS para copiar", async () => {
    await createZone();
    await confirm({ checked: true });

    const bearer = await app.fetch(new Request(`http://localhost/api/domains/${domainId}/dns/rollback`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ confirm: true }),
    }));
    assert.equal(bearer.status, 403, "un agente con llave no regresa los nameservers");

    assert.equal((await call(`/api/domains/${domainId}/dns/rollback`, { method: "POST", body: "{}" })).status, 400);

    const r = await call(`/api/domains/${domainId}/dns/rollback`, { method: "POST", body: JSON.stringify({ confirm: true }) });
    assert.equal(r.status, 409);
    assert.deepEqual((await r.json()).previousNameservers, GODADDY_NS);
    assert.equal(nsUpdates.length, 0);
  });

  it("rollback de un clic para un dominio registrado aquí: regresa los NS y no borra la zona", async () => {
    const reg = dbmod.createDomainRegistration({ domainName: domain, ownerEmail: email, tld: "org", priceCents: 1, awsCostCents: 1 });
    dbmod.updateDomainRegistration(reg.id, { status: "registered" });
    try {
      await createZone();
      await confirm({ checked: true });
      const list = await (await call(`/api/domains/${domainId}/dns`)).json();
      assert.equal(list.zone.rollbackAvailable, true);

      const r = await call(`/api/domains/${domainId}/dns/rollback`, { method: "POST", body: JSON.stringify({ confirm: true }) });
      assert.equal(r.status, 200);
      assert.deepEqual(nsUpdates, [{ domain, ns: GODADDY_NS }]);
      const d = dbmod.getDomain(domainId);
      assert.equal(d.dnsZoneStatus, "rolled_back");
      assert.equal(d.hostedZoneId, "ZKEEP", "la zona se conserva por si vuelve");
      assert.equal(zonesDeleted, 0);
    } finally {
      sqlite.prepare("DELETE FROM domain_registrations WHERE id = ?").run(reg.id);
    }
  });

  describe("SPF por proveedor (route53.ts)", () => {
    it("reconoce Google, Microsoft y Zoho por su MX, con o sin punto final", () => {
      assert.equal(r53.mailProviderFromMx(["1 aspmx.l.google.com."]).spfInclude, "include:_spf.google.com");
      assert.equal(r53.mailProviderFromMx(["0 fixter-org.mail.protection.outlook.com"]).spfInclude, "include:spf.protection.outlook.com");
      assert.equal(r53.mailProviderFromMx(["10 mx.zoho.com"]).spfInclude, "include:zohomail.com");
      assert.equal(r53.mailProviderFromMx(["10 mx.zoho.eu."]).spfInclude, "include:zohomail.eu");
      assert.equal(r53.mailProviderFromMx(["10 mx1.hostinger.com"]), null);
    });

    it("con SPF previo sólo se agrega el nuestro, sea cual sea el proveedor", () => {
      const out = r53.fusionarSpf(['"v=spf1 include:_spf.raro.net -all"'], ["10 mx.raro.net"]);
      assert.deepEqual(out, ['"v=spf1 include:_spf.raro.net include:amazonses.com -all"']);
    });
  });

  it("toZoneFile omite el NS y el SOA de la raíz y entrecomilla el TXT", () => {
    const text = dnsRecords.toZoneFile("ej.com", [
      { name: "ej.com", type: "NS", ttl: 172800, values: ["ns-1.awsdns-01.com."] },
      { name: "ej.com", type: "TXT", ttl: 300, values: ['"v=spf1 ~all"'] },
      { name: "_dmarc.ej.com", type: "TXT", ttl: 300, values: ["v=DMARC1; p=none"] },
    ]);
    assert.ok(!/\tNS\t/.test(text));
    assert.match(text, /@\t300\tIN\tTXT\t"v=spf1 ~all"/);
    assert.match(text, /_dmarc\.ej\.com\.\t300\tIN\tTXT\t"v=DMARC1; p=none"/);
  });
});
