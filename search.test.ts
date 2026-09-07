import { describe, it, before } from "node:test";
import assert from "node:assert/strict";

import {
  createDomain,
  createUser,
  createConversation,
  addMessage,
  indexMessage,
  searchConversations,
  listConversationsPage,
  listConversationAliases,
  listMessages,
  countMessages,
  contarSinIndexar,
  deleteFtsForConversation,
  createCourtesyAddon,
} from "./db.ts";
import { ftsDisponible } from "./pg.ts";

const sufijo = () => Math.random().toString(36).slice(2, 10);

/** Crea un dominio con dueño propio, para que dos dominios no compartan nada. */
async function dominioNuevo(activado = false) {
  const email = `busqueda-${sufijo()}@ejemplo.com`;
  await createUser(email, "hash-de-prueba");
  const d = createDomain(email, `${sufijo()}.ejemplo.com`, ["dkim-prueba"], `verify-${sufijo()}`);
  // Un dominio gratis sólo muestra 7 días de Bandeja: las pruebas que siembran fechas
  // viejas necesitan el dominio activado, que conserva el historial completo.
  if (activado) createCourtesyAddon({ userEmail: email, kind: "domain", domainId: d.id, currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString() });
  return d;
}

/** Conversación con un mensaje entrante ya indexado. */
async function conversacionCon(domainId: string, subject: string, texto: string, alias = "hola@x.com") {
  const conv = await createConversation({
    domainId,
    from: "cliente@fuera.com",
    to: alias,
    subject,
    status: "open",
    priority: "normal",
    lastMessageAt: new Date().toISOString(),
    messageCount: 1,
    tags: [],
    threadReferences: [],
  });
  const msg = await addMessage({
    conversationId: conv.id,
    from: "cliente@fuera.com",
    direction: "inbound",
    createdAt: new Date().toISOString(),
  });
  indexMessage({
    messageId: msg.id,
    conversationId: conv.id,
    domainId,
    from: "cliente@fuera.com",
    subject,
    text: texto,
  });
  return conv;
}

describe("Búsqueda en el cuerpo de los correos", () => {
  it("FTS5 está disponible en este entorno", () => {
    // Si esto falla, la búsqueda degrada a LIKE y las pruebas de abajo que
    // dependen del cuerpo se saltan solas. Es informativo, no un fallo real.
    assert.equal(typeof ftsDisponible, "boolean");
  });

  it("encuentra una palabra que sólo existe en el cuerpo, no en el asunto", async (t) => {
    if (!ftsDisponible) return t.skip("sin FTS5");
    const dom = await dominioNuevo();
    await conversacionCon(dom.id, "Asunto genérico", "Adjunto la cotización del proyecto Zarpazo.");

    const r = searchConversations(dom.id, "Zarpazo");
    assert.equal(r.length, 1);
    assert.equal(r[0].subject, "Asunto genérico");
  });

  it("ignora acentos en ambos sentidos", async (t) => {
    if (!ftsDisponible) return t.skip("sin FTS5");
    const dom = await dominioNuevo();
    await conversacionCon(dom.id, "Datos", "Necesito la información del pedido.");

    assert.equal(searchConversations(dom.id, "informacion").length, 1, "sin acento encuentra con acento");
    assert.equal(searchConversations(dom.id, "información").length, 1, "con acento encuentra con acento");
  });

  // La fuga entre dominios es el riesgo número uno de esta función: un fallo aquí
  // le enseña a un cliente el correo de otro.
  it("nunca cruza dominios, en ninguna dirección", async (t) => {
    if (!ftsDisponible) return t.skip("sin FTS5");
    const a = await dominioNuevo();
    const b = await dominioNuevo();
    const termino = `termino${sufijo()}`;

    await conversacionCon(a.id, "De A", `Esto es de A y dice ${termino}`);
    await conversacionCon(b.id, "De B", `Esto es de B y dice ${termino}`);

    const enA = searchConversations(a.id, termino);
    const enB = searchConversations(b.id, termino);

    assert.equal(enA.length, 1);
    assert.equal(enA[0].subject, "De A");
    assert.equal(enB.length, 1);
    assert.equal(enB[0].subject, "De B");
  });

  it("no devuelve conversaciones borradas", async (t) => {
    if (!ftsDisponible) return t.skip("sin FTS5");
    const dom = await dominioNuevo();
    const termino = `borrado${sufijo()}`;
    const conv = await conversacionCon(dom.id, "Se va a borrar", `contiene ${termino}`);
    assert.equal(searchConversations(dom.id, termino).length, 1);

    const { softDeleteConversation } = await import("./db.ts");
    await softDeleteConversation(dom.id, conv.id);
    assert.equal(searchConversations(dom.id, termino).length, 0);
  });

  it("no truena con consultas que son pura sintaxis de FTS5", async () => {
    const dom = await dominioNuevo();
    for (const veneno of ['"', "*", "NEAR(a b)", "a:b", "-x", "((", "AND OR"]) {
      assert.doesNotThrow(() => searchConversations(dom.id, veneno), `reventó con: ${veneno}`);
    }
  });

  it("respeta el filtro por alias", async (t) => {
    if (!ftsDisponible) return t.skip("sin FTS5");
    const dom = await dominioNuevo();
    const termino = `alias${sufijo()}`;
    await conversacionCon(dom.id, "A ventas", `pide ${termino}`, "ventas@x.com");
    await conversacionCon(dom.id, "A soporte", `pide ${termino}`, "soporte@x.com");

    assert.equal(searchConversations(dom.id, termino).length, 2);
    const soloVentas = searchConversations(dom.id, termino, { to: "ventas@x.com" });
    assert.equal(soloVentas.length, 1);
    assert.equal(soloVentas[0].subject, "A ventas");
  });

  it("deleteFtsForConversation deja el índice sin huérfanos", async (t) => {
    if (!ftsDisponible) return t.skip("sin FTS5");
    const dom = await dominioNuevo();
    const termino = `huerfano${sufijo()}`;
    const conv = await conversacionCon(dom.id, "Se purga", `dice ${termino}`);

    deleteFtsForConversation(conv.id);
    assert.equal(searchConversations(dom.id, termino).length, 0);
  });

  it("lo indexado no queda contado como pendiente de backfill", async (t) => {
    if (!ftsDisponible) return t.skip("sin FTS5");
    const antes = contarSinIndexar();
    const dom = await dominioNuevo();
    await conversacionCon(dom.id, "Ya indexada", "cuerpo cualquiera");
    assert.equal(contarSinIndexar(), antes, "indexar en vivo no deja deuda para el backfill");
  });
});

describe("Paginación por keyset", () => {
  it("recorre todo sin duplicados ni huecos", async () => {
    const dom = await dominioNuevo(true);
    const total = 120;
    const base = Date.parse("2026-01-01T00:00:00.000Z");
    for (let i = 0; i < total; i++) {
      await createConversation({
        domainId: dom.id,
        from: `c${i}@fuera.com`,
        to: "hola@x.com",
        subject: `Hilo ${i}`,
        status: "open",
        priority: "normal",
        lastMessageAt: new Date(base + i * 1000).toISOString(),
        messageCount: 1,
        tags: [],
        threadReferences: [],
      });
    }

    const vistos: string[] = [];
    let cursor: string | undefined;
    let vueltas = 0;
    do {
      const p = listConversationsPage(dom.id, { limit: 25, cursor });
      vistos.push(...p.items.map((c) => c.id));
      cursor = p.nextCursor ?? undefined;
      if (++vueltas > 20) throw new Error("el cursor no avanza: bucle infinito");
    } while (cursor);

    assert.equal(vistos.length, total, "faltan o sobran conversaciones");
    assert.equal(new Set(vistos).size, total, "hay duplicados entre páginas");
  });

  it("el cursor sobrevive a dos conversaciones con la misma fecha exacta", async () => {
    const dom = await dominioNuevo(true);
    const mismaFecha = "2026-02-02T02:02:02.000Z";
    for (let i = 0; i < 5; i++) {
      await createConversation({
        domainId: dom.id,
        from: `empate${i}@fuera.com`,
        to: "hola@x.com",
        subject: `Empate ${i}`,
        status: "open",
        priority: "normal",
        lastMessageAt: mismaFecha,
        messageCount: 1,
        tags: [],
        threadReferences: [],
      });
    }

    const vistos: string[] = [];
    let cursor: string | undefined;
    do {
      const p = listConversationsPage(dom.id, { limit: 2, cursor });
      vistos.push(...p.items.map((c) => c.id));
      cursor = p.nextCursor ?? undefined;
    } while (cursor);

    assert.equal(vistos.length, 5);
    assert.equal(new Set(vistos).size, 5, "el desempate por id falló y se perdieron filas");
  });

  it("nextCursor es null en la última página", async () => {
    const dom = await dominioNuevo(true);
    await conversacionCon(dom.id, "Única", "texto");
    const p = listConversationsPage(dom.id, { limit: 50 });
    assert.equal(p.items.length, 1);
    assert.equal(p.nextCursor, null);
  });

  it("un cursor corrupto no truena: devuelve la primera página", async () => {
    const dom = await dominioNuevo(true);
    await conversacionCon(dom.id, "Algo", "texto");
    assert.doesNotThrow(() => listConversationsPage(dom.id, { cursor: "no-es-base64-!!!" }));
  });

  it("excluye las borradas y las muestra sólo con status=deleted", async () => {
    const dom = await dominioNuevo(true);
    const conv = await conversacionCon(dom.id, "Se borra", "texto");
    const { softDeleteConversation } = await import("./db.ts");
    await softDeleteConversation(dom.id, conv.id);

    assert.equal(listConversationsPage(dom.id).items.length, 0);
    assert.equal(listConversationsPage(dom.id, { status: "deleted" }).items.length, 1);
  });

  it("listConversationAliases ve todos los aliases, no sólo los de la primera página", async () => {
    const dom = await dominioNuevo(true);
    await conversacionCon(dom.id, "1", "a", "ventas@x.com");
    await conversacionCon(dom.id, "2", "b", "soporte@x.com");
    await conversacionCon(dom.id, "3", "c", "ventas@x.com");

    assert.deepEqual(listConversationAliases(dom.id), ["soporte@x.com", "ventas@x.com"]);
  });
});

describe("listMessages: el tramo reciente sin romper a los llamadores viejos", () => {
  it("sin opts devuelve el hilo entero en orden ascendente", async () => {
    const dom = await dominioNuevo(true);
    const conv = await conversacionCon(dom.id, "Hilo", "primero");
    const base = Date.parse("2026-03-01T00:00:00.000Z");
    for (let i = 1; i <= 4; i++) {
      await addMessage({
        conversationId: conv.id,
        from: "x@fuera.com",
        direction: "inbound",
        createdAt: new Date(base + i * 1000).toISOString(),
      });
    }

    const todos = listMessages(conv.id);
    assert.equal(todos.length, 5);
    const fechas = todos.map((m) => m.createdAt);
    assert.deepEqual([...fechas].sort(), fechas, "no está en orden ascendente");
  });

  it("con limit devuelve el tramo MÁS RECIENTE, en orden ascendente", async () => {
    const dom = await dominioNuevo(true);
    // Sin el helper: éste crea su mensaje con la fecha de hoy, que sería el más
    // reciente de todos y enturbiaría lo que se quiere comprobar.
    const conv = await createConversation({
      domainId: dom.id,
      from: "cliente@fuera.com",
      to: "hola@x.com",
      subject: "Largo",
      status: "open",
      priority: "normal",
      lastMessageAt: "2026-04-01T00:00:00.000Z",
      messageCount: 1,
      tags: [],
      threadReferences: [],
    });
    const base = Date.parse("2026-04-01T00:00:00.000Z");
    for (let i = 1; i <= 9; i++) {
      await addMessage({
        conversationId: conv.id,
        from: "x@fuera.com",
        body: `mensaje ${i}`,
        direction: "inbound",
        createdAt: new Date(base + i * 1000).toISOString(),
      });
    }

    assert.equal(countMessages(conv.id), 9);
    const tramo = listMessages(conv.id, { limit: 3 });
    assert.equal(tramo.length, 3);
    assert.deepEqual(tramo.map((m) => m.body), ["mensaje 7", "mensaje 8", "mensaje 9"]);
  });

  it("respeta el createdAt que le pasan, no la hora de insercion", async () => {
    const dom = await dominioNuevo(true);
    const conv = await conversacionCon(dom.id, "Fechas", "cuerpo");
    const fecha = "2020-07-07T07:07:07.000Z";
    const msg = await addMessage({
      conversationId: conv.id,
      from: "viejo@fuera.com",
      direction: "inbound",
      createdAt: fecha,
    });
    assert.equal(msg.createdAt, fecha, "addMessage estaba descartando createdAt");
  });
});
