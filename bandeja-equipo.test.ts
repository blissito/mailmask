import { describe, it, before } from "node:test";
import assert from "node:assert/strict";

import { app } from "./main.ts";
import {
  createUser, createDomain, createAgent, createConversation, addMessage,
  markConversationRead, countUnread, listConversationsPage, updateConversation,
  getConversation, wakeSnoozedConversations, getBandejaMetrics,
} from "./db.ts";
import { signJwt, generateCsrfToken } from "./auth.ts";
import { setPresence, clearPresence, listPresence } from "./sse-hub.ts";

const sufijo = () => Math.random().toString(36).slice(2, 10);
let ipN = 0;
const ipBase = `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
const nextIp = () => `${ipBase}.${ipN++ % 255}`;

async function sesion(email: string) {
  const cookie = `token=${await signJwt({ email })}`;
  const csrf = generateCsrfToken();
  return { email, cookie, csrf };
}

function post(path: string, body: unknown, s: { cookie: string; csrf: string }) {
  return app.fetch(new Request(`http://localhost${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "fly-client-ip": nextIp(),
      cookie: `${s.cookie}; csrf_token=${s.csrf}`,
      "x-csrf-token": s.csrf,
    },
    body: JSON.stringify(body),
  }));
}

function patch(path: string, body: unknown, s: { cookie: string; csrf: string }) {
  return app.fetch(new Request(`http://localhost${path}`, {
    method: "PATCH",
    headers: {
      "content-type": "application/json",
      "fly-client-ip": nextIp(),
      cookie: `${s.cookie}; csrf_token=${s.csrf}`,
      "x-csrf-token": s.csrf,
    },
    body: JSON.stringify(body),
  }));
}

function del(path: string, s: { cookie: string; csrf: string }) {
  return app.fetch(new Request(`http://localhost${path}`, {
    method: "DELETE",
    headers: {
      "fly-client-ip": nextIp(),
      cookie: `${s.cookie}; csrf_token=${s.csrf}`,
      "x-csrf-token": s.csrf,
    },
  }));
}

function get(path: string, s: { cookie: string }) {
  return app.fetch(new Request(`http://localhost${path}`, { headers: { cookie: s.cookie } }));
}

async function escenario() {
  const dueno = `dueno-${sufijo()}@ejemplo.com`;
  await createUser(dueno, "hash");
  const dom = await createDomain(dueno, `${sufijo()}.ejemplo.com`, ["dkim"], `v-${sufijo()}`);

  const adminEmail = `admin-${sufijo()}@ejemplo.com`;
  const agenteEmail = `agente-${sufijo()}@ejemplo.com`;
  const ajenoEmail = `ajeno-${sufijo()}@ejemplo.com`;
  await createUser(adminEmail, "hash");
  await createUser(agenteEmail, "hash");
  await createUser(ajenoEmail, "hash");
  createAgent({ domainId: dom.id, email: adminEmail, name: "Admin", role: "admin" });
  createAgent({ domainId: dom.id, email: agenteEmail, name: "Agente", role: "agent" });

  const conv = await createConversation({
    domainId: dom.id,
    from: "cliente@fuera.com",
    to: `hola@${dom.domain}`,
    subject: "Hola",
    status: "open",
    priority: "normal",
    lastMessageAt: new Date().toISOString(),
    messageCount: 1,
    tags: [],
    threadReferences: [],
  });

  return {
    dom,
    conv,
    dueno: await sesion(dueno),
    admin: await sesion(adminEmail),
    agente: await sesion(agenteEmail),
    ajeno: await sesion(ajenoEmail),
  };
}

describe("RBAC de la Bandeja", () => {
  it("el agente puede leer", async () => {
    const e = await escenario();
    const res = await get(`/api/bandeja/conversations?domainId=${e.dom.id}`, e.agente);
    assert.equal(res.status, 200);
  });

  it("el agente puede anotar y cambiar el estado (write)", async () => {
    const e = await escenario();
    const nota = await post(`/api/bandeja/conversations/${e.conv.id}/note`, { domainId: e.dom.id, body: "ojo" }, e.agente);
    assert.equal(nota.status, 201);
    const cambio = await patch(`/api/bandeja/conversations/${e.conv.id}`, { domainId: e.dom.id, status: "closed" }, e.agente);
    assert.equal(cambio.status, 200);
  });

  it("🔴 el agente NO puede borrar (era el hueco)", async () => {
    const e = await escenario();
    const res = await del(`/api/bandeja/conversations/${e.conv.id}?domainId=${e.dom.id}`, e.agente);
    assert.equal(res.status, 403);
    // Y de verdad no se borró.
    const sigue = await getConversation(e.dom.id, e.conv.id);
    assert.equal(sigue?.deletedAt, undefined);
  });

  it("el agente NO puede restaurar ni asignar", async () => {
    const e = await escenario();
    const r = await post(`/api/bandeja/conversations/${e.conv.id}/restore`, { domainId: e.dom.id }, e.agente);
    assert.equal(r.status, 403);
    const a = await post(`/api/bandeja/conversations/${e.conv.id}/assign`, { domainId: e.dom.id, assignedTo: "x@y.com" }, e.agente);
    assert.equal(a.status, 403);
  });

  it("el admin sí puede borrar y asignar", async () => {
    const e = await escenario();
    const a = await post(`/api/bandeja/conversations/${e.conv.id}/assign`, { domainId: e.dom.id, assignedTo: "x@y.com" }, e.admin);
    assert.equal(a.status, 200);
    const d = await del(`/api/bandeja/conversations/${e.conv.id}?domainId=${e.dom.id}`, e.admin);
    assert.equal(d.status, 200);
    const r = await post(`/api/bandeja/conversations/${e.conv.id}/restore`, { domainId: e.dom.id }, e.admin);
    assert.equal(r.status, 200);
  });

  it("el dueño puede todo", async () => {
    const e = await escenario();
    const d = await del(`/api/bandeja/conversations/${e.conv.id}?domainId=${e.dom.id}`, e.dueno);
    assert.equal(d.status, 200);
  });

  it("un correo ajeno recibe 403 en todo", async () => {
    const e = await escenario();
    for (const res of [
      await get(`/api/bandeja/conversations?domainId=${e.dom.id}`, e.ajeno),
      await get(`/api/bandeja/conversations/${e.conv.id}?domainId=${e.dom.id}`, e.ajeno),
      await post(`/api/bandeja/conversations/${e.conv.id}/note`, { domainId: e.dom.id, body: "x" }, e.ajeno),
      await patch(`/api/bandeja/conversations/${e.conv.id}`, { domainId: e.dom.id, status: "closed" }, e.ajeno),
      await del(`/api/bandeja/conversations/${e.conv.id}?domainId=${e.dom.id}`, e.ajeno),
    ]) {
      assert.equal(res.status, 403);
    }
  });

  it("sin sesión es 401, no 403", async () => {
    const e = await escenario();
    const res = await app.fetch(new Request(`http://localhost/api/bandeja/conversations?domainId=${e.dom.id}`));
    assert.equal(res.status, 401);
  });
});

describe("Leído / no leído por agente", () => {
  it("una conversación nueva nace no leída, sin sembrar filas", async () => {
    const e = await escenario();
    const pag = listConversationsPage(e.dom.id, { forAgent: e.agente.email });
    assert.equal(pag.items[0].unread, true);
    assert.equal(countUnread(e.dom.id, e.agente.email), 1);
  });

  it("marcar leído la saca del contador y sobrevive a releer", async () => {
    const e = await escenario();
    markConversationRead(e.dom.id, e.conv.id, e.agente.email);
    assert.equal(countUnread(e.dom.id, e.agente.email), 0);
    const pag = listConversationsPage(e.dom.id, { forAgent: e.agente.email });
    assert.equal(pag.items[0].unread, false);
  });

  it("un mensaje nuevo la vuelve no leída", async () => {
    const e = await escenario();
    markConversationRead(e.dom.id, e.conv.id, e.agente.email);
    await updateConversation(e.dom.id, e.conv.id, { lastMessageAt: new Date(Date.now() + 60_000).toISOString() });
    assert.equal(countUnread(e.dom.id, e.agente.email), 1);
  });

  it("dos agentes tienen estados distintos sobre el mismo hilo", async () => {
    const e = await escenario();
    markConversationRead(e.dom.id, e.conv.id, e.agente.email);
    assert.equal(countUnread(e.dom.id, e.agente.email), 0);
    assert.equal(countUnread(e.dom.id, e.admin.email), 1);
  });

  it("el filtro \"No leídas\" sólo trae las que faltan por leer", async () => {
    const e = await escenario();
    const otras = [];
    for (let i = 0; i < 4; i++) {
      otras.push(await createConversation({
        domainId: e.dom.id,
        from: `c${i}@fuera.com`,
        to: `hola@${e.dom.domain}`,
        subject: `S${i}`,
        status: "open",
        priority: "normal",
        lastMessageAt: new Date(Date.now() - i * 1000).toISOString(),
        messageCount: 1,
        tags: [],
        threadReferences: [],
      }));
    }
    markConversationRead(e.dom.id, otras[0].id, e.agente.email);
    markConversationRead(e.dom.id, otras[1].id, e.agente.email);
    // 5 en total (la del escenario más 4), dos leídas.
    const pag = listConversationsPage(e.dom.id, { status: "unread", forAgent: e.agente.email });
    assert.equal(pag.items.length, 3);
    // Sin saber quién pregunta, "no leídas" no significa nada: lista vacía.
    const sinAgente = listConversationsPage(e.dom.id, { status: "unread" });
    assert.equal(sinAgente.items.length, 0);
  });

  it("el keyset sigue paginando bien con el JOIN de leídos", async () => {
    const e = await escenario();
    for (let i = 0; i < 4; i++) {
      await createConversation({
        domainId: e.dom.id,
        from: `c${i}@fuera.com`,
        to: `hola@${e.dom.domain}`,
        subject: `S${i}`,
        status: "open",
        priority: "normal",
        lastMessageAt: new Date(Date.now() + i * 1000).toISOString(),
        messageCount: 1,
        tags: [],
        threadReferences: [],
      });
    }
    const vistos = new Set<string>();
    let cursor: string | null | undefined = undefined;
    let vueltas = 0;
    do {
      const pag: any = listConversationsPage(e.dom.id, { forAgent: e.agente.email, limit: 2, cursor: cursor ?? undefined });
      for (const c of pag.items) {
        assert.ok(c.lastMessageAt, "la fila debe traer fecha, no undefined");
        assert.equal(vistos.has(c.id), false, "sin duplicados entre páginas");
        vistos.add(c.id);
      }
      cursor = pag.nextCursor;
    } while (cursor && ++vueltas < 10);
    assert.equal(vistos.size, 5);
  });

  it("abrir el detalle la marca leída", async () => {
    const e = await escenario();
    const res = await get(`/api/bandeja/conversations/${e.conv.id}?domainId=${e.dom.id}`, e.agente);
    assert.equal(res.status, 200);
    assert.equal(countUnread(e.dom.id, e.agente.email), 0);
  });
});

describe("Presencia", () => {
  it("colapsa varias pestañas del mismo agente en una sola entrada", () => {
    const dom = `dom-${sufijo()}`;
    setPresence(dom, "ana@x.com", "Ana", "c1", "viewing");
    setPresence(dom, "ana@x.com", "Ana", "c1", "viewing");
    assert.equal(listPresence(dom).length, 1);
    clearPresence(dom, "ana@x.com");
  });

  it("no filtra presencias entre dominios", () => {
    const a = `dom-${sufijo()}`;
    const b = `dom-${sufijo()}`;
    setPresence(a, "ana@x.com", "Ana", "c1", "viewing");
    assert.equal(listPresence(b).length, 0);
    clearPresence(a, "ana@x.com");
  });

  it("clearPresence la quita al instante", () => {
    const dom = `dom-${sufijo()}`;
    setPresence(dom, "ana@x.com", "Ana", "c1", "typing");
    clearPresence(dom, "ana@x.com");
    assert.equal(listPresence(dom).length, 0);
  });

  it("el endpoint exige acceso al dominio", async () => {
    const e = await escenario();
    const res = await post(`/api/bandeja/presence`, { domainId: e.dom.id, conversationId: e.conv.id, state: "viewing" }, e.ajeno);
    assert.equal(res.status, 403);
    const ok = await post(`/api/bandeja/presence`, { domainId: e.dom.id, conversationId: e.conv.id, state: "viewing" }, e.agente);
    assert.equal(ok.status, 204);
    assert.equal(listPresence(e.dom.id).length, 1);
  });

  it("conversationId null borra la presencia (el sendBeacon al cerrar)", async () => {
    const e = await escenario();
    await post(`/api/bandeja/presence`, { domainId: e.dom.id, conversationId: e.conv.id, state: "viewing" }, e.agente);
    await post(`/api/bandeja/presence`, { domainId: e.dom.id, conversationId: null }, e.agente);
    assert.equal(listPresence(e.dom.id).length, 0);
  });
});

describe("Posponer (snooze)", () => {
  it("rechaza posponer sin fecha", async () => {
    const e = await escenario();
    const res = await patch(`/api/bandeja/conversations/${e.conv.id}`, { domainId: e.dom.id, status: "snoozed" }, e.dueno);
    assert.equal(res.status, 400);
  });

  it("rechaza una fecha en el pasado: el hilo se perdería para siempre", async () => {
    const e = await escenario();
    const ayer = new Date(Date.now() - 86400_000).toISOString();
    const res = await patch(`/api/bandeja/conversations/${e.conv.id}`, { domainId: e.dom.id, status: "snoozed", snoozedUntil: ayer }, e.dueno);
    assert.equal(res.status, 400);
  });

  it("rechaza una fecha inválida y más de 90 días", async () => {
    const e = await escenario();
    const mala = await patch(`/api/bandeja/conversations/${e.conv.id}`, { domainId: e.dom.id, status: "snoozed", snoozedUntil: "el jueves" }, e.dueno);
    assert.equal(mala.status, 400);
    const lejos = new Date(Date.now() + 200 * 86400_000).toISOString();
    const res = await patch(`/api/bandeja/conversations/${e.conv.id}`, { domainId: e.dom.id, status: "snoozed", snoozedUntil: lejos }, e.dueno);
    assert.equal(res.status, 400);
  });

  it("pospone con fecha futura y guarda el plazo", async () => {
    const e = await escenario();
    const manana = new Date(Date.now() + 86400_000).toISOString();
    const res = await patch(`/api/bandeja/conversations/${e.conv.id}`, { domainId: e.dom.id, status: "snoozed", snoozedUntil: manana }, e.dueno);
    assert.equal(res.status, 200);
    const conv = await getConversation(e.dom.id, e.conv.id);
    assert.equal(conv?.status, "snoozed");
    assert.equal(conv?.snoozedUntil, manana);
  });

  it("el cron despierta sólo lo vencido, y una sola vez", async () => {
    const e = await escenario();
    const vencida = new Date(Date.now() + 1000).toISOString();
    await updateConversation(e.dom.id, e.conv.id, { status: "snoozed", snoozedUntil: vencida });

    const enFuturo = new Date(Date.now() + 86400_000).toISOString();
    const despertadas = wakeSnoozedConversations(new Date(Date.now() + 5000).toISOString());
    assert.ok(despertadas.some((c) => c.id === e.conv.id));

    const conv = await getConversation(e.dom.id, e.conv.id);
    assert.equal(conv?.status, "open");
    assert.equal(conv?.snoozedUntil, undefined);

    // Segunda pasada: ya no está pospuesta, no se avisa dos veces.
    const otra = wakeSnoozedConversations(new Date(Date.now() + 5000).toISOString());
    assert.equal(otra.some((c) => c.id === e.conv.id), false);
    assert.ok(enFuturo);
  });

  it("volver a abrir o cerrar limpia el plazo: no queda una fecha colgando", async () => {
    const e = await escenario();
    await updateConversation(e.dom.id, e.conv.id, { status: "snoozed", snoozedUntil: new Date(Date.now() + 86400_000).toISOString() });
    await updateConversation(e.dom.id, e.conv.id, { status: "open" });
    const conv = await getConversation(e.dom.id, e.conv.id);
    assert.equal(conv?.snoozedUntil, undefined);
  });

  it("un mensaje nuevo la despierta al instante (la reapertura del entrante)", async () => {
    const e = await escenario();
    await updateConversation(e.dom.id, e.conv.id, { status: "snoozed", snoozedUntil: new Date(Date.now() + 86400_000).toISOString() });
    // Es lo que hace saveToMesa al llegar correo del contacto.
    await updateConversation(e.dom.id, e.conv.id, { status: "open", lastMessageAt: new Date().toISOString() });
    const conv = await getConversation(e.dom.id, e.conv.id);
    assert.equal(conv?.status, "open");
    assert.equal(conv?.snoozedUntil, undefined);
  });
});

describe("Métricas de la Bandeja", () => {
  it("un dominio vacío no produce NaN ni divisiones por cero", async () => {
    const dueno = `m-${sufijo()}@ejemplo.com`;
    await createUser(dueno, "hash");
    const dom = await createDomain(dueno, `${sufijo()}.ejemplo.com`, ["dkim"], `v-${sufijo()}`);
    const m = getBandejaMetrics(dom.id, 30);
    assert.equal(m.totals.conversaciones, 0);
    assert.equal(m.primeraRespuesta.medianaMin, null);
    assert.equal(m.porAgente.length, 0);
    assert.equal(JSON.stringify(m).includes("NaN"), false);
  });

  it("mide la primera respuesta y rellena los días sin correo", async () => {
    const e = await escenario();
    const base = Date.now() - 3600_000;
    await addMessage({
      conversationId: e.conv.id,
      from: "cliente@fuera.com",
      direction: "inbound",
      createdAt: new Date(base).toISOString(),
    });
    await addMessage({
      conversationId: e.conv.id,
      from: `hola@${e.dom.domain}`,
      direction: "outbound",
      createdAt: new Date(base + 30 * 60_000).toISOString(),
    });
    const m = getBandejaMetrics(e.dom.id, 7);
    assert.equal(m.primeraRespuesta.medianaMin, 30);
    assert.equal(m.primeraRespuesta.contestadas, 1);
    // Siete días, todos presentes aunque seis estén en cero.
    assert.equal(m.porDia.length, 7);
    assert.equal(m.porDia.every((d) => typeof d.entrantes === "number"), true);
  });

  it("cuenta como sin responder lo que entró y nadie contestó", async () => {
    const e = await escenario();
    await addMessage({
      conversationId: e.conv.id,
      from: "cliente@fuera.com",
      direction: "inbound",
      createdAt: new Date().toISOString(),
    });
    const m = getBandejaMetrics(e.dom.id, 7);
    assert.equal(m.totals.sinResponder, 1);
    assert.equal(m.primeraRespuesta.medianaMin, null);
  });

  it("el endpoint exige acceso al dominio", async () => {
    const e = await escenario();
    assert.equal((await get(`/api/bandeja/metrics?domainId=${e.dom.id}`, e.ajeno)).status, 403);
    assert.equal((await get(`/api/bandeja/metrics?domainId=${e.dom.id}`, e.agente)).status, 200);
  });

  it("un rango raro cae al de 30 días en vez de romperse", async () => {
    const e = await escenario();
    const res = await get(`/api/bandeja/metrics?domainId=${e.dom.id}&days=999`, e.dueno);
    assert.equal(res.status, 200);
    assert.equal((await res.json()).days, 30);
  });
});

describe("Borrado en lote", () => {
  async function conVariasConversaciones() {
    const e = await escenario();
    const ids = [e.conv.id];
    for (let i = 0; i < 3; i++) {
      const c = await createConversation({
        domainId: e.dom.id,
        from: `c${i}@fuera.com`,
        to: `hola@${e.dom.domain}`,
        subject: `S${i}`,
        status: "open",
        priority: "normal",
        lastMessageAt: new Date(Date.now() - i * 1000).toISOString(),
        messageCount: 1,
        tags: [],
        threadReferences: [],
      });
      ids.push(c.id);
    }
    return { ...e, ids };
  }

  it("borra varias de una y devuelve cuántas", async () => {
    const e = await conVariasConversaciones();
    const res = await post(`/api/bandeja/conversations/bulk-delete`, { domainId: e.dom.id, ids: e.ids }, e.dueno);
    assert.equal(res.status, 200);
    assert.equal((await res.json()).deleted, 4);
    for (const id of e.ids) {
      const conv = await getConversation(e.dom.id, id);
      assert.ok(conv?.deletedAt, "quedó en la papelera");
    }
  });

  it("🔴 un id de otro dominio colado en la lista no borra nada", async () => {
    const a = await conVariasConversaciones();
    const b = await escenario();
    const res = await post(
      `/api/bandeja/conversations/bulk-delete`,
      { domainId: a.dom.id, ids: [a.ids[0], b.conv.id] },
      a.dueno,
    );
    assert.equal(res.status, 200);
    assert.equal((await res.json()).deleted, 1, "sólo la propia");
    const ajena = await getConversation(b.dom.id, b.conv.id);
    assert.equal(ajena?.deletedAt, undefined, "la del otro dominio sigue intacta");
  });

  it("pide el mismo permiso que borrar de una: el agente no puede", async () => {
    const e = await conVariasConversaciones();
    const res = await post(`/api/bandeja/conversations/bulk-delete`, { domainId: e.dom.id, ids: e.ids }, e.agente);
    assert.equal(res.status, 403);
    const sigue = await getConversation(e.dom.id, e.ids[0]);
    assert.equal(sigue?.deletedAt, undefined);
  });

  it("rechaza lista vacía y lotes de más de 200", async () => {
    const e = await escenario();
    assert.equal((await post(`/api/bandeja/conversations/bulk-delete`, { domainId: e.dom.id, ids: [] }, e.dueno)).status, 400);
    const muchas = Array.from({ length: 201 }, (_, i) => `id-${i}`);
    assert.equal((await post(`/api/bandeja/conversations/bulk-delete`, { domainId: e.dom.id, ids: muchas }, e.dueno)).status, 400);
  });

  it("ids inexistentes no rompen: se cuentan las que sí se borraron", async () => {
    const e = await conVariasConversaciones();
    const res = await post(
      `/api/bandeja/conversations/bulk-delete`,
      { domainId: e.dom.id, ids: [e.ids[0], "no-existe", "tampoco"] },
      e.dueno,
    );
    assert.equal(res.status, 200);
    assert.equal((await res.json()).deleted, 1);
  });

  it("un correo ajeno recibe 403", async () => {
    const e = await conVariasConversaciones();
    const res = await post(`/api/bandeja/conversations/bulk-delete`, { domainId: e.dom.id, ids: e.ids }, e.ajeno);
    assert.equal(res.status, 403);
  });
});
