// El servidor MCP habla JSON-RPC sobre POST /mcp con la API key de siempre. Igual que
// sdk.test.ts, el mock de ses.ts tiene que instalarse antes de cargar main.ts.
import { describe, it, before, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";

const suffix = Date.now().toString(36);

const zonaDns = new Map<string, { name: string; type: string; ttl: number; values: string[] }>();
const enviados: { from: string; to: string; subject: string }[] = [];
const correoCrudo = [
  "From: cliente@example.com", "To: soporte@x.com", "Subject: Factura", "MIME-Version: 1.0",
  'Content-Type: multipart/mixed; boundary="b1"', "",
  "--b1", "Content-Type: text/plain; charset=utf-8", "", "Les mando la lista de productos.", "",
  "--b1", 'Content-Type: text/csv; name="lista.csv"', 'Content-Disposition: attachment; filename="lista.csv"', "",
  "sku,cantidad", "A1,3", "",
  "--b1--", "",
].join("\r\n");

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

    const realTransfer = await import("./domain-transfer.ts");
    mock.module("./domain-transfer.ts", { namedExports: {
      ...realTransfer,
      checkDomainReadiness: async () => ({ listo: true, requisitos: [{ clave: "aws", ok: true, texto: "El registrador actual permite la transferencia" }] }),
    } });
    class MpFalso { async create() { return { id: `mp-${crypto.randomUUID()}`, init_point: "https://mp.test/checkout" }; } }
    mock.module("mercadopago", { namedExports: { MercadoPagoConfig: class {}, PreApproval: MpFalso, Preference: MpFalso } });

    mock.module("./ses.ts", { namedExports: {
      ...realSes,
      verifyDomain: async () => ({ verificationToken: "tok", dkimTokens: ["d1", "d2", "d3"] }),
      createReceiptRule: async () => undefined,
      deleteReceiptRule: async () => undefined,
      deleteConfigurationSet: async () => undefined,
      deleteDomainIdentity: async () => undefined,
      // Bandeja: envíos y un correo recibido con un adjunto de texto, en memoria.
      // deno-lint-ignore no-explicit-any
      sendFromDomain: async (from: string, to: string, subject: string, _b: string, _o?: any) => {
        enviados.push({ from, to, subject });
        return { messageId: `<stub-${crypto.randomUUID()}@test>`, sesMessageId: `ses-${crypto.randomUUID()}` };
      },
      fetchEmailFromS3: async () => correoCrudo,
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

  it("la prueba de dominio del MCP Registry se sirve en el apex sin redirect", async () => {
    // El registry lee https://mailmask.studio/.well-known/mcp-registry-auth con redirects
    // deshabilitados; un 301 al www rompería la verificación del namespace.
    const res = await app.fetch(new Request("http://mailmask.studio/.well-known/mcp-registry-auth"));
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /text\/plain/);
    assert.match(await res.text(), /^v=MCPv1; k=ed25519; p=[A-Za-z0-9+/]+=*\n$/);
    // Y el resto del apex sigue yendo al www.
    const otro = await app.fetch(new Request("http://mailmask.studio/docs"));
    assert.equal(otro.status, 301);
    assert.match(otro.headers.get("location") ?? "", /^https?:\/\/www\.mailmask\.studio\/docs$/);
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

  it("initialize trae la guía de onboarding (≤ 6000 caracteres) con lo que no se negocia", async () => {
    const init = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "0" } });
    const g: string = init.json.result.instructions;
    assert.ok(g, "sin instructions");
    assert.ok(g.length <= 6000, `instructions mide ${g.length}`);
    for (const p of ["domain_dns_setup", "verify_domain", "activation_link", "Bloqueado", "EPP", "MercadoPago"]) assert.ok(g.includes(p), p);
  });

  it("las herramientas nuevas están en el catálogo y search_tools las encuentra en español", async () => {
    const nombres = (await rpc("tools/list")).json.result.tools.map((t: { name: string }) => t.name);
    for (const n of ["domain_dns_setup", "activation_link", "billing_status", "list_addons", "search_domains", "domain_prices", "register_domain",
      "list_registrations", "transfer_check", "transfer_start", "transfer_status", "transfer_dns", "update_transfer_dns", "approve_transfer_dns",
      "resend_transfer_email", "transfer_out", "lock_domain_transfer", "renewal_status", "renewal_link", "list_members", "invite_member", "remove_member", "cancel_invite",
      "get_signature", "set_signature", "list_canned_replies", "create_canned_reply", "delete_canned_reply", "apple_profile_link", "mailbox_export_link"]) {
      assert.ok(nombres.includes(n), n);
    }
    const buscar = async (q: string) => (await call("search_tools", { query: q })).json.result.structuredContent.result.map((t: { name: string }) => t.name);
    assert.ok((await buscar("renovacion")).includes("renewal_status"), "sin acento también");
    assert.ok((await buscar("hostinger")).includes("domain_dns_setup"));
    assert.ok((await buscar("firma")).includes("set_signature"));
    assert.ok((await buscar("invitar")).includes("invite_member"));
    assert.ok((await buscar("candado")).includes("lock_domain_transfer"));
  });

  it("transfer_start no recibe el EPP: devuelve la liga al formulario de la app", async () => {
    const tools = (await rpc("tools/list")).json.result.tools;
    const schema = tools.find((t: { name: string }) => t.name === "transfer_start").inputSchema;
    assert.deepEqual(Object.keys(schema.properties), ["domain"], "el código EPP no puede ser un parámetro");
    const r = await call("transfer_start", { domain: `traer-${suffix}.com` });
    assert.ok(!r.json.result.isError, JSON.stringify(r.json.result));
    const out = r.json.result.structuredContent;
    assert.equal(out.ready, true);
    assert.match(out.formUrl, new RegExp(`/app#transfer=traer-${suffix}\\.com$`));
  });

  it("activation_link da la liga de pago y deja claro que no está pagado", async () => {
    const segundo = dbmod.createDomain(`mcp-gratis-${suffix}@example.com`, `mcp-bloq-${suffix}.com`, ["dk"], "vf");
    const r = await call("activation_link", { domainId: segundo.id }, keyGratis);
    assert.ok(!r.json.result.isError, JSON.stringify(r.json.result));
    assert.equal(r.json.result.structuredContent.paymentUrl, "https://mp.test/checkout");
    assert.equal(r.json.result.structuredContent.paid, false);
  });

  it("domain_dns_setup sin live devuelve los registros a pegar", async () => {
    const r = await call("domain_dns_setup", { domainId: dominioGratisId, live: false }, keyGratis);
    assert.ok(!r.json.result.isError, JSON.stringify(r.json.result));
    const recs = r.json.result.structuredContent.records;
    assert.equal(recs.find((x: { id: string }) => x.id === "mx").value, "10 inbound-smtp.us-east-1.amazonaws.com");
    assert.equal(recs.find((x: { id: string }) => x.id === "verification").value, "vf");
  });

  it("apple_profile_link sin buzón es isError con la salida, no una liga rota", async () => {
    const r = await call("apple_profile_link", { domainId: dominioGratisId, alias: "nadie" }, keyGratis);
    assert.equal(r.json.result.isError, true);
    assert.match(r.json.result.content[0].text, /create_mailbox/);
  });

  it("perfil: get/update_profile y set_profile_photo rechaza una URL que no es adjunto firmado", async () => {
    const up = await call("update_profile", { displayName: "Dueña MCP" });
    assert.ok(!up.json.result.isError, JSON.stringify(up.json.result));
    assert.equal(up.json.result.structuredContent.displayName, "Dueña MCP");
    const get = await call("get_profile", {});
    assert.equal(get.json.result.structuredContent.email, email);

    const r = await call("set_profile_photo", { url: "https://ejemplo.com/foto.png" });
    assert.equal(r.json.result.isError, true);
    assert.match(r.json.result.content[0].text, /HTTP 400: .*adjuntaste/);
    const forged = await call("set_profile_photo", { url: `http://localhost/api/asistente/files/abc/foto.png?exp=9999999999&sig=${"0".repeat(64)}` });
    assert.equal(forged.json.result.isError, true);

    const buscar = async (q: string) => (await call("search_tools", { query: q })).json.result.structuredContent.result.map((t: { name: string }) => t.name);
    assert.ok((await buscar("foto")).includes("set_profile_photo"));
    assert.ok((await buscar("avatar")).includes("set_profile_photo"));
    assert.ok((await buscar("nombre")).includes("update_profile"));
  });

  it("Bandeja de punta a punta: listar no leídas por máscara, leer, adjunto, responder, cerrar, nota y redactar", async () => {
    const dom = (await call("create_domain", { domain: `mcp-inbox-${suffix}.com` })).json.result.structuredContent.domain;
    sqlite.prepare("UPDATE domains SET verified = 1 WHERE id = ?").run(dom.id);
    await call("create_alias", { domainId: dom.id, alias: "soporte", destinations: ["d@example.com"] });
    const conv = dbmod.createConversation({
      domainId: dom.id, from: "cliente@example.com", to: `soporte@mcp-inbox-${suffix}.com`, subject: "Factura",
      status: "open", priority: "normal", lastMessageAt: new Date().toISOString(), messageCount: 1, tags: [], threadReferences: ["<f@cliente>"],
    });
    const msg = dbmod.addMessage({ conversationId: conv.id, from: "cliente@example.com", direction: "inbound", createdAt: new Date().toISOString(), s3Bucket: "b", s3Key: "k", messageId: "<f@cliente>" });

    const lista = await call("inbox_list", { domainId: dom.id, alias: "soporte", status: "unread" });
    assert.ok(!lista.json.result.isError, JSON.stringify(lista.json.result));
    const fila = lista.json.result.structuredContent.conversations.find((c: { id: string }) => c.id === conv.id);
    assert.equal(fila.unread, true);
    assert.equal(fila.contact, "cliente@example.com");

    const leida = (await call("inbox_read", { domainId: dom.id, conversationId: conv.id })).json.result.structuredContent;
    assert.match(leida.messages[0].text, /lista de productos/);
    assert.deepEqual(leida.messages[0].attachments.map((x: { filename: string }) => x.filename), ["lista.csv"]);
    assert.equal(leida.messages[0].html, undefined, "al modelo le llega texto, no HTML");
    const despues = (await call("inbox_list", { domainId: dom.id, status: "unread" })).json.result.structuredContent.conversations;
    assert.ok(!despues.some((c: { id: string }) => c.id === conv.id), "leerla la marca leída");

    const adj = await call("inbox_attachment", { domainId: dom.id, conversationId: conv.id, messageId: msg.id, index: 0 });
    assert.ok(!adj.json.result.isError, JSON.stringify(adj.json.result));
    assert.match(adj.json.result.structuredContent.text, /A1,3/);

    enviados.length = 0;
    const resp = await call("inbox_reply", { domainId: dom.id, conversationId: conv.id, markdown: "Recibida, gracias." });
    assert.ok(!resp.json.result.isError, JSON.stringify(resp.json.result));
    assert.deepEqual(enviados[0], { from: `soporte@mcp-inbox-${suffix}.com`, to: "cliente@example.com", subject: "Re: Factura" });

    const marca = await call("inbox_mark", { domainId: dom.id, conversationId: conv.id, status: "closed", tags: ["factura"], read: true });
    assert.equal(marca.json.result.structuredContent.status, "closed");
    assert.equal((await call("inbox_mark", { domainId: dom.id, conversationId: conv.id })).json.result.isError, true, "sin cambios es error claro");
    assert.ok(!(await call("inbox_note", { domainId: dom.id, conversationId: conv.id, body: "Pidió factura" })).json.result.isError);

    const nuevo = await call("inbox_send", { domainId: dom.id, fromAlias: "soporte", to: "prospecto@example.com", subject: "Hola", markdown: "Te escribo de..." });
    assert.ok(!nuevo.json.result.isError, JSON.stringify(nuevo.json.result));
    assert.ok(nuevo.json.result.structuredContent.conversationId);

    // Otra cuenta (otra llave) no ve esta Bandeja.
    const ajena = await call("inbox_list", { domainId: dom.id }, keyGratis);
    assert.equal(ajena.json.result.isError, true);
    assert.match(ajena.json.result.content[0].text, /HTTP 403/);
    const ajenaLeer = await call("inbox_read", { domainId: dom.id, conversationId: conv.id }, keyGratis);
    assert.equal(ajenaLeer.json.result.isError, true);
  });

  it("inbox_send en dominio gratis o sin verificar: el error dice qué falta", async () => {
    const gratis = await call("inbox_send", { domainId: dominioGratisId, fromAlias: "x", to: "a@example.com", subject: "x", body: "x" }, keyGratis);
    assert.equal(gratis.json.result.isError, true);
    assert.match(gratis.json.result.content[0].text, /HTTP 403.*activado/);

    const dom = (await call("create_domain", { domain: `mcp-noverif-${suffix}.com` })).json.result.structuredContent.domain;
    const conv = dbmod.createConversation({
      domainId: dom.id, from: "c@example.com", to: `hola@mcp-noverif-${suffix}.com`, subject: "x",
      status: "open", priority: "normal", lastMessageAt: new Date().toISOString(), messageCount: 1, tags: [], threadReferences: [],
    });
    const r = await call("inbox_reply", { domainId: dom.id, conversationId: conv.id, body: "x" });
    assert.equal(r.json.result.isError, true);
    assert.match(r.json.result.content[0].text, /verify_domain/);
  });

  it("con el turn token del asistente, cancelar un add-on pide confirmación en vez de ejecutar", async () => {
    const { issueTurnToken } = await import("./auth.ts");
    const mt = await issueTurnToken(email);
    const addon = dbmod.createAddon(email, "sends100");
    dbmod.updateAddon(addon.id, { status: "active", currentPeriodEnd: new Date(Date.now() + 5 * 864e5).toISOString() });
    const r = await call("cancel_addon", { addonId: addon.id }, mt);
    assert.equal(r.json.result.structuredContent.needsConfirmation, true);
    assert.match(r.json.result.structuredContent.title, /^Cancelar/);
    assert.equal(dbmod.getAddonById(addon.id).status, "active", "no se canceló");
    // Con la mk_ (sin asistente de por medio) sí ejecuta.
    assert.equal((await call("cancel_addon", { addonId: addon.id })).json.result.structuredContent.ok, true);
  });

  it("el catálogo cubre la app: Bandeja, cuenta y logo, y search_tools los encuentra", async () => {
    const nombres = (await rpc("tools/list")).json.result.tools.map((t: { name: string }) => t.name);
    for (const n of ["inbox_list", "inbox_read", "inbox_attachment", "inbox_reply", "inbox_send", "inbox_mark", "inbox_assign", "inbox_note",
      "inbox_delete", "inbox_restore", "inbox_metrics", "upload_attachment", "set_domain_logo", "delete_domain_logo", "delete_profile_photo",
      "list_orders", "cancel_addon", "cancel_renewal", "referral_status", "set_referral_slug", "set_referral_name", "export_link"]) {
      assert.ok(nombres.includes(n), n);
    }
    const tools = (await rpc("tools/list")).json.result.tools;
    for (const n of ["inbox_reply", "inbox_send", "send_email"]) {
      assert.match(tools.find((t: { name: string }) => t.name === n).description, /⚠️ Confirma/, `${n} pide confirmar antes de enviar`);
    }
    const buscar = async (q: string) => (await call("search_tools", { query: q })).json.result.structuredContent.result.map((t: { name: string }) => t.name);
    assert.ok((await buscar("responder")).includes("inbox_reply"));
    assert.ok((await buscar("correos recibidos")).includes("inbox_list"));
    assert.ok((await buscar("archivar")).includes("inbox_mark"));
    assert.ok((await buscar("facturas")).includes("list_orders"));
  });
});
