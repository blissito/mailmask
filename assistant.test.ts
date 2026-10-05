process.env.ASSISTANT_PUBLIC = "1"; // las pruebas no corren como admin
// Asistente de /app: turn token `mt_`, relay del SSE de Ghosty, historial, adjuntos y la
// confirmación de lo destructivo. Ghosty es un fetch simulado (`setGhostyFetch`); el mock
// de ses.ts va antes de cargar main.ts, igual que en mcp.test.ts.
import { describe, it, before, beforeEach, after, mock } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";

const suffix = Date.now().toString(36);
const uploads = new Map<string, { body: Uint8Array; contentType: string }>();

describe("Asistente: Ghosty, turn token y confirmaciones", () => {
  // deno-lint-ignore no-explicit-any
  let app: any, dbmod: any, sqlite: any, authmod: any, asis: any;
  const email = `asis-${suffix}@example.com`;
  let session = { cookie: "", csrf: "" };
  let key = "";
  let domainId = "";
  const domainName = `asis-${suffix}.com`;
  let idRpc = 0;

  const withSession = (extra: Record<string, string> = {}) => ({
    cookie: `${session.cookie}; csrf_token=${session.csrf}`,
    "x-csrf-token": session.csrf,
    ...extra,
  });
  const req = (path: string, init: RequestInit = {}) => app.fetch(new Request(`http://localhost${path}`, init));
  const postJson = (path: string, body: unknown, headers: Record<string, string>) =>
    req(path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
  const mcp = async (bearer: string, method: string, params: Record<string, unknown> = {}) => {
    const res = await req("/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${bearer}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++idRpc, method, params }),
    });
    return { status: res.status, json: await res.json().catch(() => null) };
  };

  // Ghosty simulado: guarda la última petición y contesta el SSE que se le ponga.
  let lastCall: { url: string; headers: Headers; raw: string } | null = null;
  let sseFrames: string[] = [];
  const fakeGhosty = (async (url: string | URL | Request, init?: RequestInit) => {
    lastCall = { url: String(url), headers: new Headers(init?.headers), raw: String(init?.body ?? "") };
    const enc = new TextEncoder();
    const frames = sseFrames;
    return new Response(new ReadableStream({
      start(c) {
        // Partido a la mitad a propósito: el relay debe re-armar frames entre lecturas.
        const all = frames.join("");
        const mid = Math.floor(all.length / 2);
        c.enqueue(enc.encode(all.slice(0, mid)));
        c.enqueue(enc.encode(all.slice(mid)));
        c.close();
      },
    }), { headers: { "content-type": "text/event-stream" } });
  }) as typeof fetch;

  before(async () => {
    process.env.GHOSTY_PARTNER_KEY = "gpk_test";
    process.env.GHOSTY_PARTNER_SECRET = "gps_secret";
    process.env.GHOSTY_AGENT_ID = "agent-123";
    process.env.GHOSTY_BASE_URL = "https://ghosty.test";
    const realSes = await import("./ses.ts");
    mock.module("./ses.ts", { namedExports: {
      ...realSes,
      verifyDomain: async () => ({ verificationToken: "tok", dkimTokens: ["d1", "d2", "d3"] }),
      createReceiptRule: async () => undefined,
      deleteReceiptRule: async () => undefined,
      deleteConfigurationSet: async () => undefined,
      deleteDomainIdentity: async () => undefined,
      checkDomainStatus: async () => ({ verified: true, dkimVerified: true, respondio: true }),
      putAssistantUploadToS3: async (k: string, body: Uint8Array, contentType: string) => { uploads.set(k, { body, contentType }); },
      getAssistantUploadFromS3: async (k: string) => uploads.get(k) ?? null,
    } });
    ({ app } = await import("./main.ts"));
    dbmod = await import("./db.ts");
    ({ sqlite } = await import("./pg.ts"));
    authmod = await import("./auth.ts");
    asis = await import("./assistant.ts");
    asis.setGhostyFetch(fakeGhosty);

    dbmod.createUser(email, await authmod.hashPassword("password123"));
    await dbmod.updateUserSubscription(email, { plan: "equipo", status: "active", mpSubscriptionId: `sub-${email}`, currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString() });
    session = { cookie: `token=${await authmod.signJwt({ email })}`, csrf: authmod.generateCsrfToken() };
    key = (await dbmod.createApiKey(email, "asis-test")).plaintextKey;
    domainId = dbmod.createDomain(email, domainName, ["d1", "d2", "d3"], "vt").id;
  });
  after(() => asis?.setGhostyFetch(null));
  beforeEach(() => {
    sqlite.prepare("DELETE FROM rate_limits").run();
    delete process.env.GHOSTY_RUNTIME;
  });

  // --- Firma y runtimes ---

  it("firma igual que Ghosty: hex HMAC-SHA256 de `${ts}.${keyId}.${rawBody}`", () => {
    const h = asis.signGhostyRequest("gpk_x", "gps_y", '{"a":1}', 1700000000);
    const want = createHmac("sha256", "gps_y").update('1700000000.gpk_x.{"a":1}').digest("hex");
    assert.deepEqual(h, { "X-Ghosty-Key": "gpk_x", "X-Ghosty-Ts": "1700000000", "X-Ghosty-Sig": want });
  });

  it("stream (fleet): firma válida, mt_ en el body, re-emite el SSE y guarda el turno con done autoritativo", async () => {
    sseFrames = [
      `data: ${JSON.stringify({ type: "chunk", value: "Hola " })}\n\n`,
      ": hb\n\n",
      `data: ${JSON.stringify({ type: "tool", name: "mcp__mailmask__list_domains" })}\n\n`,
      `data: ${JSON.stringify({ type: "chunk", value: "borrador" })}\n\n`,
      `data: ${JSON.stringify({ type: "done", value: "Hola, tienes 1 dominio." })}\n\n`,
    ];
    const res = await postJson("/api/asistente/stream", { text: "¿cuántos dominios tengo?", attachments: [], surface: "dock", screen: { domainId, tab: "dns" }, screenChanged: true }, withSession());
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /text\/event-stream/);
    const messageId = res.headers.get("x-message-id");
    assert.ok(messageId);
    const out = await res.text();
    assert.equal(out, sseFrames.join(""), "se re-emite frame por frame, sin perder el heartbeat");

    // Lo que recibió Ghosty
    assert.equal(lastCall!.url, "https://ghosty.test/api/v2/fleet-agents/agent-123/message-stream");
    const ts = lastCall!.headers.get("x-ghosty-ts")!;
    assert.equal(lastCall!.headers.get("x-ghosty-key"), "gpk_test");
    assert.equal(lastCall!.headers.get("x-ghosty-sig"), createHmac("sha256", "gps_secret").update(`${ts}.gpk_test.${lastCall!.raw}`).digest("hex"));
    assert.ok(Math.abs(Number(ts) - Date.now() / 1000) < 5, "ts en segundos");
    const body = JSON.parse(lastCall!.raw);
    assert.match(body.groupId, /^web-[0-9a-f]{24}$/);
    assert.ok(!body.groupId.includes("@"), "el correo no viaja a Ghosty");
    assert.match(body.turnToken, /^mt_/);
    assert.match(body.appendSystemPrompt, new RegExp(domainName.replace(/\./g, "\\.")));
    assert.match(body.appendSystemPrompt, /Pestaña abierta: dns/);
    assert.match(body.text, /<contexto-de-pantalla>/);
    assert.match(body.text, /¿cuántos dominios tengo\?$/);
    // El token que recibe Ghosty sirve en /mcp.
    const viaToken = await mcp(body.turnToken, "tools/call", { name: "list_domains", arguments: {} });
    assert.equal(viaToken.status, 200);
    assert.ok(!viaToken.json.result.isError, JSON.stringify(viaToken.json));

    const hist = await (await req("/api/asistente", { headers: { cookie: session.cookie } })).json();
    const last2 = hist.messages.slice(-2);
    assert.equal(last2[0].id, messageId);
    assert.equal(last2[0].role, "user");
    assert.equal(last2[0].content, "¿cuántos dominios tengo?", "en el historial va el texto limpio, sin el contexto");
    assert.equal(last2[1].role, "assistant");
    assert.equal(last2[1].content, "Hola, tienes 1 dominio.");
    assert.equal(last2[1].status, "ok");
  });

  it("stream (partner): /partner/turns con tenant opaco, token y adjuntos como links", async () => {
    process.env.GHOSTY_RUNTIME = "partner";
    sseFrames = [`data: ${JSON.stringify({ type: "chunk", value: "ok" })}\n\n`, `data: ${JSON.stringify({ type: "error", message: "capacidad" })}\n\n`];
    const res = await postJson("/api/asistente/stream", { text: "hola", attachments: [] }, withSession());
    assert.equal(res.status, 200);
    await res.text();
    assert.equal(lastCall!.url, "https://ghosty.test/api/v2/partner/turns");
    const body = JSON.parse(lastCall!.raw);
    assert.match(body.tenant.externalId, /^[0-9a-f]{24}$/);
    assert.match(body.token, /^mt_/);
    assert.equal(body.turnToken, undefined);
    const hist = await (await req("/api/asistente", { headers: { cookie: session.cookie } })).json();
    const last = hist.messages.at(-1);
    assert.equal(last.content, "ok");
    assert.equal(last.status, "failed", "un evento error marca el turno como fallido");
  });

  it("stream: sin CSRF 403, con Bearer 403, Ghosty caído 502", async () => {
    const sinCsrf = await postJson("/api/asistente/stream", { text: "x" }, { cookie: session.cookie });
    assert.equal(sinCsrf.status, 403);
    const conBearer = await postJson("/api/asistente/stream", { text: "x" }, { authorization: `Bearer ${key}` });
    assert.equal(conBearer.status, 403);
    asis.setGhostyFetch((async () => new Response("boom", { status: 503 })) as typeof fetch);
    try {
      const caido = await postJson("/api/asistente/stream", { text: "x" }, withSession());
      assert.equal(caido.status, 502);
      assert.equal((await caido.json()).error, "No se pudo contactar al asistente");
    } finally {
      asis.setGhostyFetch(fakeGhosty);
    }
  });

  it("stream: «Detener» aborta el fetch a Ghosty y guarda lo que llegó como stopped", async () => {
    let upstreamSignal: AbortSignal | undefined;
    asis.setGhostyFetch((async (_u: unknown, init?: RequestInit) => {
      upstreamSignal = init?.signal ?? undefined;
      const enc = new TextEncoder();
      return new Response(new ReadableStream({
        start(c) { c.enqueue(enc.encode(`data: ${JSON.stringify({ type: "chunk", value: "a medias" })}\n\n`)); },
      }));
    }) as typeof fetch);
    try {
      const res = await postJson("/api/asistente/stream", { text: "algo largo" }, withSession());
      const reader = res.body!.getReader();
      await reader.read();
      await reader.cancel();
      assert.equal(upstreamSignal?.aborted, true);
      const hist = await (await req("/api/asistente", { headers: { cookie: session.cookie } })).json();
      const last = hist.messages.at(-1);
      assert.equal(last.content, "a medias");
      assert.equal(last.status, "stopped");
    } finally {
      asis.setGhostyFetch(fakeGhosty);
    }
  });

  it("adjuntos: sube, sirve con URL firmada, viajan como parts y rechaza SVG", async () => {
    const fd = new FormData();
    fd.set("file", new File([new Uint8Array([137, 80, 78, 71])], "captura.png", { type: "image/png" }));
    const up = await req("/api/asistente/upload", { method: "POST", headers: withSession(), body: fd });
    assert.equal(up.status, 200);
    const a = await up.json();
    assert.match(a.url, /^http:\/\/localhost\/api\/asistente\/files\/[0-9a-f]{24}\//);
    assert.equal(a.contentType, "image/png");
    assert.equal(a.size, 4);
    assert.equal([...uploads.keys()].length, 1);

    const file = await req(new URL(a.url).pathname + new URL(a.url).search);
    assert.equal(file.status, 200);
    assert.equal(file.headers.get("content-type"), "image/png");
    const tampered = await req(new URL(a.url).pathname + "?exp=9999999999&sig=00");
    assert.equal(tampered.status, 403);

    sseFrames = [`data: ${JSON.stringify({ type: "done", value: "Veo la captura." })}\n\n`];
    const foreign = { url: "https://evil.example/x.png", name: "x.png", contentType: "image/png" };
    const res = await postJson("/api/asistente/stream", { text: "mira", attachments: [a, foreign] }, withSession());
    await res.text();
    const body = JSON.parse(lastCall!.raw);
    assert.equal(body.parts.length, 1, "sólo los adjuntos propios");
    assert.equal(body.parts[0].file.uri, a.url);

    const svg = new FormData();
    svg.set("file", new File(["<svg/>"], "x.svg", { type: "image/svg+xml" }));
    assert.equal((await req("/api/asistente/upload", { method: "POST", headers: withSession(), body: svg })).status, 415);
  });

  it("reset (FormData) borra el hilo y cambia el groupId; send da 410; last-tool no aplica", async () => {
    const antes = asis.assistantGroupId(email, asis.getAssistantNonce(email));
    const fd = new FormData();
    fd.set("intent", "reset");
    const r = await req("/api/asistente", { method: "POST", headers: withSession(), body: fd });
    assert.equal(r.status, 200);
    const hist = await (await req("/api/asistente", { headers: { cookie: session.cookie } })).json();
    assert.deepEqual(hist, { messages: [], hasMore: false });
    assert.notEqual(asis.assistantGroupId(email, asis.getAssistantNonce(email)), antes);

    const send = new FormData();
    send.set("intent", "send");
    assert.equal((await req("/api/asistente", { method: "POST", headers: withSession(), body: send })).status, 410);
    assert.deepEqual(await (await req("/api/asistente/last-tool", { headers: { cookie: session.cookie } })).json(), { name: null });
  });

  it("historial paginado con ?before= y hasMore", async () => {
    for (let i = 0; i < 45; i++) asis.saveAssistantMessage(email, i % 2 ? "assistant" : "user", `m${i}`);
    const p1 = await (await req("/api/asistente", { headers: { cookie: session.cookie } })).json();
    assert.equal(p1.messages.length, 40);
    assert.equal(p1.hasMore, true);
    assert.equal(p1.messages.at(-1).content, "m44");
    const p2 = await (await req(`/api/asistente?before=${encodeURIComponent(p1.messages[0].createdAt)}`, { headers: { cookie: session.cookie } })).json();
    assert.equal(p2.messages.length, 5);
    assert.equal(p2.hasMore, false);
    assert.equal(p2.messages[0].content, "m0");
  });

  // --- Turn token ---

  it("mt_: no crea ni lista API keys ni SMTP; vencido o como cookie no sirve", async () => {
    const mt = await authmod.issueTurnToken(email);
    const crear = await postJson("/api/api-keys", { name: "robada" }, { authorization: `Bearer ${mt}` });
    assert.equal(crear.status, 403);
    assert.equal((await req("/api/api-keys", { headers: { authorization: `Bearer ${mt}` } })).status, 403);
    assert.equal((await postJson(`/api/domains/${domainId}/smtp-credentials`, { label: "x" }, { authorization: `Bearer ${mt}` })).status, 403);
    // Pero sí opera la cuenta.
    assert.equal((await req(`/api/domains/${domainId}`, { headers: { authorization: `Bearer ${mt}` } })).status, 200);

    const vencido = `mt_${await authmod.signJwt({ email, aud: "assistant", jti: "x" }, -10)}`;
    assert.equal((await req(`/api/domains/${domainId}`, { headers: { authorization: `Bearer ${vencido}` } })).status, 401);
    assert.equal((await mcp(vencido, "tools/list")).status, 401);
    // Una cookie de sesión no es un turn token, ni al revés.
    const sesionComoMt = `mt_${session.cookie.slice("token=".length)}`;
    assert.equal((await mcp(sesionComoMt, "tools/list")).status, 401);
    assert.equal((await req("/api/agent-actions", { headers: { cookie: `token=${mt.slice(3)}` } })).status, 401);
  });

  // --- Confirmaciones ---

  it("borrar con mt_ pide confirmación; confirmar ejecuta una sola vez", async () => {
    dbmod.createAlias(domainId, "ventas", ["dueno@example.com"]);
    const mt = await authmod.issueTurnToken(email);
    const r = await mcp(mt, "tools/call", { name: "delete_alias", arguments: { domainId, alias: "ventas" } });
    assert.equal(r.status, 200);
    const result = r.json.result;
    assert.ok(!result.isError, "no es error para el modelo");
    assert.match(result.content[0].text, new RegExp(`Necesita confirmación del usuario: .*«Borrar la dirección ventas@${domainName.replace(/\./g, "\\.")}»\\. No reintentes`));
    assert.ok(dbmod.getAlias(domainId, "ventas"), "todavía no se borró");

    // Reintentar lo mismo reusa la tarjeta.
    await mcp(mt, "tools/call", { name: "delete_alias", arguments: { domainId, alias: "ventas" } });
    const lista = await (await req("/api/agent-actions", { headers: { cookie: session.cookie } })).json();
    const mias = lista.actions.filter((a: { tool: string }) => a.tool === "delete_alias");
    assert.equal(mias.length, 1);
    const action = mias[0];
    assert.equal(action.summary.title, `Borrar la dirección ventas@${domainName}`);
    assert.equal(action.summary.destructive, true);
    assert.ok(action.summary.lines.some((l: string) => l.includes("dueno@example.com")), "el resumen sale de la base");

    // Ni el mt_ ni una API key pueden aprobar.
    assert.equal((await postJson("/api/agent-actions", { intent: "confirm", actionId: action.id }, { authorization: `Bearer ${mt}` })).status, 403);
    assert.equal((await req("/api/agent-actions", { headers: { authorization: `Bearer ${key}` } })).status, 403);
    // Sin CSRF tampoco.
    assert.equal((await postJson("/api/agent-actions", { intent: "confirm", actionId: action.id }, { cookie: session.cookie })).status, 403);

    const ok = await postJson("/api/agent-actions", { intent: "confirm", actionId: action.id }, withSession());
    assert.equal(ok.status, 200);
    const okBody = await ok.json();
    assert.equal(okBody.outcome, "executed");
    assert.equal(dbmod.getAlias(domainId, "ventas"), null);

    const otra = await postJson("/api/agent-actions", { intent: "confirm", actionId: action.id }, withSession());
    assert.equal(otra.status, 409);
    assert.equal((await otra.json()).status, "executed");
  });

  it("rechazar no ejecuta; una vencida no se puede confirmar", async () => {
    dbmod.createAlias(domainId, "soporte", ["dueno@example.com"]);
    const mt = await authmod.issueTurnToken(email);
    const res = await req(`/api/domains/${domainId}/alias/soporte`, { method: "DELETE", headers: { authorization: `Bearer ${mt}` } });
    assert.equal(res.status, 409);
    const pend = await res.json();
    assert.equal(pend.error, "needs_confirmation");

    const rej = await postJson("/api/agent-actions", { intent: "reject", actionId: pend.actionId }, withSession());
    assert.equal(rej.status, 200);
    assert.equal((await rej.json()).outcome, "rejected");
    assert.ok(dbmod.getAlias(domainId, "soporte"));
    assert.equal((await postJson("/api/agent-actions", { intent: "confirm", actionId: pend.actionId }, withSession())).status, 409);

    const res2 = await req(`/api/domains/${domainId}/alias/soporte`, { method: "DELETE", headers: { authorization: `Bearer ${mt}` } });
    const pend2 = await res2.json();
    assert.notEqual(pend2.actionId, pend.actionId);
    sqlite.prepare("UPDATE pending_agent_actions SET created_at = ? WHERE id = ?").run(new Date(Date.now() - 16 * 60_000).toISOString(), pend2.actionId);
    const venc = await postJson("/api/agent-actions", { intent: "confirm", actionId: pend2.actionId }, withSession());
    assert.equal(venc.status, 409);
    const vb = await venc.json();
    assert.equal(vb.status, "expired");
    assert.equal(vb.outcome, "expired");
    assert.ok(dbmod.getAlias(domainId, "soporte"), "vencida no ejecuta");
    const lista = await (await req("/api/agent-actions", { headers: { cookie: session.cookie } })).json();
    assert.ok(!lista.actions.some((a: { id: string }) => a.id === pend2.actionId));
  });

  it("borrar el dominio y quitar a una persona también piden confirmación; con sesión o API key no", async () => {
    const mt = await authmod.issueTurnToken(email);
    const otro = dbmod.createDomain(email, `asis-otro-${suffix}.com`, ["d1"], "vt");
    const miembro = dbmod.createAgent({ domainId: otro.id, email: `miembro-${suffix}@example.com`, name: "Miembro", role: "agent" });

    const quitar = await req(`/api/domains/${otro.id}/agents/${miembro.id}`, { method: "DELETE", headers: { authorization: `Bearer ${mt}` } });
    assert.equal(quitar.status, 409);
    assert.equal((await quitar.json()).summary.title, `Quitar a miembro-${suffix}@example.com de asis-otro-${suffix}.com`);

    const borrar = await req(`/api/domains/${otro.id}`, { method: "DELETE", headers: { authorization: `Bearer ${mt}` } });
    assert.equal(borrar.status, 409);
    const pb = await borrar.json();
    assert.equal(pb.summary.title, `Borrar el dominio asis-otro-${suffix}.com`);
    assert.ok(dbmod.getDomain(otro.id));

    const conf = await postJson("/api/agent-actions", { intent: "confirm", actionId: pb.actionId }, withSession());
    assert.equal(conf.status, 200);
    assert.equal(dbmod.getDomain(otro.id), null);

    // La API key de siempre no cambia de comportamiento.
    const tercero = dbmod.createDomain(email, `asis-tres-${suffix}.com`, ["d1"], "vt");
    const conKey = await req(`/api/domains/${tercero.id}`, { method: "DELETE", headers: { authorization: `Bearer ${key}` } });
    assert.equal(conKey.status, 200);
  });

  // --- Quién lo usa ---

  it("canUseAssistant: con ASSISTANT_PUBLIC sólo cuentas con dominio activado (o lista/admin); sin él sólo lista/admin", async () => {
    const saved = { pub: process.env.ASSISTANT_PUBLIC, list: process.env.ASSISTANT_EMAILS, admins: process.env.ADMIN_EMAILS };
    const free = `asis-free-${suffix}@example.com`;
    const paid = `asis-paid-${suffix}@example.com`;
    const tester = `asis-tester-${suffix}@example.com`;
    const admin = `asis-admin-${suffix}@example.com`;
    for (const e of [free, paid, tester, admin]) dbmod.createUser(e, await authmod.hashPassword("password123"));
    dbmod.createDomain(free, `asis-free-${suffix}.com`, ["d1"], "vt");
    const paidDomain = dbmod.createDomain(paid, `asis-paid-${suffix}.com`, ["d1"], "vt");
    const addon = dbmod.createAddon(paid, "domain", paidDomain.id);
    dbmod.updateAddon(addon.id, { status: "active", currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString() });

    const asUser = async (e: string) => {
      const csrf = authmod.generateCsrfToken();
      const cookie = `token=${await authmod.signJwt({ email: e })}`;
      const me = await (await req("/api/auth/me", { headers: { cookie } })).json();
      const stream = await postJson("/api/asistente/stream", { text: "hola" }, { cookie: `${cookie}; csrf_token=${csrf}`, "x-csrf-token": csrf });
      if (stream.status === 200) await stream.text();
      const fd = new FormData();
      fd.append("file", new File(["hola"], "a.txt", { type: "text/plain" }));
      const upload = await req("/api/asistente/upload", { method: "POST", headers: { cookie: `${cookie}; csrf_token=${csrf}`, "x-csrf-token": csrf }, body: fd });
      return { me: me.assistant, stream: stream.status, upload: upload.status };
    };

    try {
      sseFrames = [`data: ${JSON.stringify({ type: "done", value: "ok" })}\n\n`];
      process.env.ASSISTANT_EMAILS = tester;
      process.env.ADMIN_EMAILS = admin;

      process.env.ASSISTANT_PUBLIC = "1";
      assert.deepEqual(await asUser(free), { me: false, stream: 403, upload: 403 }, "gratis sin dominio activado: nada");
      assert.deepEqual(await asUser(paid), { me: true, stream: 200, upload: 200 }, "dominio activado: sí");
      assert.equal(asis.canUseAssistant(tester), true, "lista, aunque sea gratis");
      assert.equal(asis.canUseAssistant(admin), true, "admin, aunque sea gratis");
      assert.equal(asis.canUseAssistant(`nadie-${suffix}@example.com`), false, "cuenta inexistente");

      delete process.env.ASSISTANT_PUBLIC;
      assert.deepEqual(await asUser(paid), { me: false, stream: 403, upload: 403 }, "sin ASSISTANT_PUBLIC el dominio activado no basta");
      assert.deepEqual(await asUser(tester), { me: true, stream: 200, upload: 200 });
      assert.equal(asis.canUseAssistant(admin), true);
    } finally {
      for (const [k, v] of [["ASSISTANT_PUBLIC", saved.pub], ["ASSISTANT_EMAILS", saved.list], ["ADMIN_EMAILS", saved.admins]] as const) {
        if (v === undefined) delete process.env[k]; else process.env[k] = v;
      }
    }
  });

  // --- Salud ---

  it("un dominio sin activar es aviso, no error", async () => {
    const gratis = `asis-gratis-${suffix}@example.com`;
    dbmod.createUser(gratis, await authmod.hashPassword("password123"));
    dbmod.createDomain(gratis, `asis-uno-${suffix}.invalid`, ["d1"], "vt");
    const bloqueado = dbmod.createDomain(gratis, `asis-dos-${suffix}.invalid`, ["d1"], "vt");
    dbmod.updateDomain(bloqueado.id, { verified: true });
    const cookie = `token=${await authmod.signJwt({ email: gratis })}`;
    const h = await (await req(`/api/domains/${bloqueado.id}/health`, { headers: { cookie } })).json();
    assert.equal(h.checks.plan.ok, false);
    assert.equal(h.status, "warning");
    assert.equal(h.summary, "Falta activar este dominio: guarda el correo pero no lo reenvía");
  });
});
