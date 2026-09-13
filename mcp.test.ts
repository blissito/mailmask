// El servidor MCP habla JSON-RPC sobre POST /mcp con la API key de siempre. Igual que
// sdk.test.ts, el mock de ses.ts tiene que instalarse antes de cargar main.ts.
import { describe, it, before, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";

const suffix = Date.now().toString(36);

const zonaDns = new Map<string, { name: string; type: string; ttl: number; values: string[] }>();

describe("MCP: agentes contra la app", () => {
  // deno-lint-ignore no-explicit-any
  let app: any, dbmod: any, sqlite: any;
  let key = "";
  let keyGratis = "";
  const email = `mcp-${suffix}@example.com`;
  let dominioGratisId = "";
  let idRpc = 0;

  const rpc = async (method: string, params: Record<string, unknown> = {}, apiKey: string | null = key) => {
    const headers: Record<string, string> = { "content-type": "application/json", accept: "application/json, text/event-stream" };
    if (apiKey) headers.authorization = `Bearer ${apiKey}`;
    const res = await app.fetch(new Request("http://localhost/mcp", { method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", id: ++idRpc, method, params }) }));
    return { status: res.status, json: await res.json().catch(() => null) };
  };
  const call = (name: string, args: Record<string, unknown>, apiKey?: string) => rpc("tools/call", { name, arguments: args }, apiKey ?? key);

  before(async () => {
    const realSes = await import("./ses.ts");
    mock.module("./route53.ts", {
      namedExports: {
        listRecordSets: async () => [...zonaDns.values()],
        // deno-lint-ignore no-explicit-any
        applyRecordChanges: async (_z: string, cambios: any[]) => {
          for (const c of cambios) {
            const k = `${c.rrset.name}|${c.rrset.type}`;
            if (c.action === "DELETE") zonaDns.delete(k); else zonaDns.set(k, c.rrset);
          }
          return { changeId: "C1" };
        },
        ensureHostedZone: async () => ({ hostedZoneId: "ZMCP", nameservers: ["ns-1.awsdns-01.com"], created: true }),
        configureDnsRecords: async () => undefined,
        deleteHostedZone: async () => undefined,
      },
    });
    mock.module("./dns-import.ts", {
      namedExports: {
        snapshotDns: async () => ({ found: [], nameservers: [], warning: "aviso" }),
        delegacionActiva: async (_d: string, e: string[]) => ({ delegated: false, observed: ["ns1.viejo.com"], expected: e }),
        nameserversActuales: async () => ["ns1.viejo.com"],
      },
    });

    mock.module("./ses.ts", { namedExports: {
      ...realSes,
      verifyDomain: async () => ({ verificationToken: "tok", dkimTokens: ["d1", "d2", "d3"] }),
      createReceiptRule: async () => undefined,
      deleteReceiptRule: async () => undefined,
      deleteConfigurationSet: async () => undefined,
      deleteDomainIdentity: async () => undefined,
    } });
    ({ app } = await import("./main.ts"));
    dbmod = await import("./db.ts");
    ({ sqlite } = await import("./pg.ts"));
    const { hashPassword } = await import("./auth.ts");

    dbmod.createUser(email, await hashPassword("password123"));
    // Suscripción legado vigente = todos sus dominios activados.
    await dbmod.updateUserSubscription(email, { plan: "equipo", status: "active", mpSubscriptionId: `sub-${email}`, currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString() });
    key = (await dbmod.createApiKey(email, "mcp-test")).plaintextKey;

    const gratis = `mcp-gratis-${suffix}@example.com`;
    dbmod.createUser(gratis, await hashPassword("password123"));
    keyGratis = (await dbmod.createApiKey(gratis, "mcp-test")).plaintextKey;
    dominioGratisId = dbmod.createDomain(gratis, `mcp-gratis-${suffix}.com`, ["dk"], "vf").id;
  });
  beforeEach(() => sqlite.prepare("DELETE FROM rate_limits").run());

  it("sin Bearer contesta 401 JSON, no JSON-RPC", async () => {
    const r = await rpc("tools/list", {}, null);
    assert.equal(r.status, 401);
    assert.match(r.json.error, /API key/);
    assert.equal((await rpc("tools/list", {}, "mk_inventada")).status, 401);
  });

  it("GET no es una sesión: 405", async () => {
    const res = await app.fetch(new Request("http://localhost/mcp", { headers: { authorization: `Bearer ${key}` } }));
    assert.equal(res.status, 405);
  });

  it("initialize y tools/list traen el catálogo", async () => {
    const init = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "0" } });
    assert.equal(init.status, 200);
    assert.equal(init.json.result.serverInfo.name, "mailmask");
    const list = await rpc("tools/list");
    const nombres = list.json.result.tools.map((t: { name: string }) => t.name);
    for (const n of ["create_domain", "create_alias", "create_mailbox", "reset_mailbox_password", "create_rule", "create_webhook", "send_email", "search_tools"]) assert.ok(nombres.includes(n), n);
    assert.ok(!nombres.some((n: string) => n.includes("api_key")), "las API keys no se fabrican por MCP");
  });

  it("create_domain devuelve los registros DNS y create_alias con buzón funciona en activado", async () => {
    const r = await call("create_domain", { domain: `mcp-${suffix}.com` });
    assert.equal(r.status, 200);
    assert.ok(!r.json.result.isError, JSON.stringify(r.json.result));
    const dominio = r.json.result.structuredContent;
    assert.equal(dominio.dnsRecords.mx.type, "MX");
    assert.equal(dominio.dnsRecords.dkim.length, 3);

    const a = await call("create_alias", { domainId: dominio.domain.id, alias: "ventas", mailbox: true });
    assert.ok(!a.json.result.isError, JSON.stringify(a.json.result));
    assert.equal(a.json.result.structuredContent.alias, "ventas");
    // Stalwart no está configurado en pruebas: la máscara nace y la razón viene en texto.
    assert.equal(typeof a.json.result.structuredContent.errorBuzon, "string");
  });

  it("un 403 del servidor llega como isError con el precio, no como excepción", async () => {
    const r = await call("create_alias", { domainId: dominioGratisId, alias: "hola", mailbox: true }, keyGratis);
    assert.equal(r.status, 200);
    assert.equal(r.json.result.isError, true);
    assert.match(r.json.result.content[0].text, /HTTP 403.*\$99/);
  });

  it("una API key no ve los dominios de otra cuenta", async () => {
    const r = await call("get_domain", { domainId: dominioGratisId });
    assert.equal(r.json.result.isError, true);
    assert.match(r.json.result.content[0].text, /HTTP 404/);
  });

  it("el tope por llave (60/min) se cuenta una vez por herramienta, no dos", async () => {
    for (let i = 0; i < 50; i++) {
      const r = await call("list_domains", {});
      assert.ok(!r.json.result?.isError, `llamada ${i}: ${JSON.stringify(r.json)}`);
    }
  });

  it("search_tools encuentra por palabra", async () => {
    const r = await call("search_tools", { query: "webhook" });
    const nombres = r.json.result.structuredContent.result.map((t: { name: string }) => t.name);
    assert.ok(nombres.includes("create_webhook"));
    assert.ok(!nombres.includes("create_domain"));
  });
  it("el agente puede montar el DNS de un dominio de punta a punta", async () => {
    const dom = (await call("create_domain", { domain: `mcp-dns-${suffix}.com` })).json.result.structuredContent.domain;

    // 1. Sin zona no hay 404, hay una pista accionable: ante un 404 un agente abandona.
    const sinZona = await call("list_dns_records", { domainId: dom.id });
    assert.equal(sinZona.json.result.structuredContent.zone.status, "none");
    assert.match(sinZona.json.result.structuredContent.hint, /dns\/zone/);

    // 2. Crea la zona y recibe los nameservers para el registrador.
    const zona = await call("create_dns_zone", { domainId: dom.id });
    assert.ok(!zona.json.result.isError, JSON.stringify(zona.json.result));
    assert.deepEqual(zona.json.result.structuredContent.nameservers, ["ns-1.awsdns-01.com"]);

    // 3. Apunta el dominio a Vercel con una sola herramienta.
    const vercel = await call("point_domain_to", { domainId: dom.id, provider: "vercel", target: "mi-proyecto.vercel.app" });
    assert.ok(!vercel.json.result.isError, JSON.stringify(vercel.json.result));
    assert.equal(vercel.json.result.structuredContent.records.length, 2);

    // 4. Y ve lo que quedó, con lo de MailMask marcado como intocable.
    // (`configureDnsRecords` está mockeada, así que el MX se siembra a mano.)
    zonaDns.set(`mcp-dns-${suffix}.com|MX`, { name: `mcp-dns-${suffix}.com`, type: "MX", ttl: 300, values: ["10 inbound-smtp.us-east-1.amazonaws.com"] });
    const listado = await call("list_dns_records", { domainId: dom.id });
    const registros = listado.json.result.structuredContent.records;
    assert.ok(registros.some((r: any) => r.type === "A" && r.values.includes("76.76.21.21")));
    assert.equal(registros.find((r: any) => r.type === "MX").managed, true);
    assert.equal(registros.find((r: any) => r.type === "MX").editable, false);
  });

  it("borrar el MX vuelve como isError, no como excepción", async () => {
    const dom = (await call("create_domain", { domain: `mcp-mx-${suffix}.com` })).json.result.structuredContent.domain;
    await call("create_dns_zone", { domainId: dom.id });
    zonaDns.set(`mcp-mx-${suffix}.com|MX`, { name: `mcp-mx-${suffix}.com`, type: "MX", ttl: 300, values: ["10 inbound-smtp.us-east-1.amazonaws.com"] });

    const r = await call("delete_dns_record", { domainId: dom.id, name: "@", type: "MX" });
    assert.equal(r.status, 200);
    assert.equal(r.json.result.isError, true);
    assert.match(r.json.result.content[0].text, /HTTP 409/);
    // El texto le dice al agente cuál es la salida legítima, para que no busque un force.
    assert.match(r.json.result.content[0].text, /elimina el dominio de MailMask/);
  });
});
