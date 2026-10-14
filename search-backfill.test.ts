import { describe, it, before, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";

import {
  createDomain,
  createUser,
  createConversation,
  addMessage,
  searchConversations,
} from "./db.ts";
import { sqlite, ftsDisponible } from "./pg.ts";

// Doble de S3: va ANTES del import del backfill (ver docs/agents/pruebas-mocks.md).
// Tabla s3Key → raw MIME | "" (sin cuerpo) | Error | promesa diferida.
const realSes = await import("./ses.ts");
const llamadas: string[] = [];
const respuestas = new Map<string, string | Error | Promise<string>>();

mock.module("./ses.ts", {
  namedExports: {
    ...realSes,
    fetchEmailFromS3: async (_bucket: string, key: string) => {
      llamadas.push(key);
      const r = respuestas.get(key);
      if (r instanceof Error) throw r;
      return r ?? "";
    },
  },
});

let runBackfill: typeof import("./search-backfill.ts").runBackfill;

before(async () => {
  ({ runBackfill } = await import("./search-backfill.ts"));
});

const sufijo = () => Math.random().toString(36).slice(2, 10);
const BUCKET = "bucket-prueba";

/** Un MIME mínimo text/plain: extractPlainBody lo devuelve tal cual. */
const mime = (cuerpo: string) =>
  `From: cliente@fuera.com\r\nSubject: prueba\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${cuerpo}\r\n`;

async function dominioNuevo() {
  const email = `backfill-${sufijo()}@ejemplo.com`;
  await createUser(email, "hash-de-prueba");
  return createDomain(email, `${sufijo()}.ejemplo.com`, ["dkim-prueba"], `verify-${sufijo()}`);
}

async function conversacion(domainId: string, subject: string) {
  return createConversation({
    domainId,
    from: "cliente@fuera.com",
    to: "hola@x.com",
    subject,
    status: "open",
    priority: "normal",
    lastMessageAt: new Date().toISOString(),
    messageCount: 1,
    tags: [],
    threadReferences: [],
  });
}

/** addMessage NO indexa: el backfill es quien debe encontrarlo. */
async function mensaje(conversationId: string, extra: Record<string, unknown> = {}) {
  return addMessage({
    conversationId,
    from: "cliente@fuera.com",
    direction: "inbound",
    createdAt: new Date().toISOString(),
    ...extra,
  } as Parameters<typeof addMessage>[0]);
}

function estado(messageId: string) {
  return sqlite
    .prepare(`SELECT status, error FROM search_index_state WHERE message_id = ?`)
    .get(messageId) as { status: string; error: string | null } | undefined;
}

async function esperarA(condicion: () => boolean, ms = 5000) {
  const limite = Date.now() + ms;
  while (!condicion()) {
    if (Date.now() > limite) throw new Error("el doble de S3 nunca recibió la llamada");
    await new Promise((r) => setImmediate(r));
  }
}

beforeEach(() => {
  llamadas.length = 0;
  respuestas.clear();
  if (!ftsDisponible) return;
  // La base de pruebas es UNA para toda la suite: lo pendiente de otros archivos
  // se marca como saltado, para que la corrida sólo vea lo que siembra cada caso.
  sqlite
    .prepare(
      `INSERT INTO search_index_state (message_id, indexed_at, status, error)
       SELECT m.id, ?, 'skipped', 'ajeno a la prueba'
       FROM messages m LEFT JOIN search_index_state s ON s.message_id = m.id
       WHERE s.message_id IS NULL`
    )
    .run(new Date().toISOString());
});

describe("runBackfill: indexar, saltar, fallar y reanudar", () => {
  it("un saliente con cuerpo queda buscable y S3 no se consulta para él", async (t) => {
    if (!ftsDisponible) return t.skip("sin FTS5");
    const dom = await dominioNuevo();
    const conv = await conversacion(dom.id, "Saliente");
    const termino = `salienteunico${sufijo()}`;
    const s3Key = `saliente-${sufijo()}`;
    const msg = await mensaje(conv.id, {
      direction: "outbound",
      body: `respuesta con ${termino}`,
      s3Bucket: BUCKET,
      s3Key,
    });

    await runBackfill({ pauseMs: 0 });

    assert.equal(llamadas.includes(s3Key), false, "el saliente ya trae su cuerpo");
    assert.equal(estado(msg.id)?.status, "ok");
    assert.ok(searchConversations(dom.id, termino).some((c) => c.id === conv.id));
  });

  it("un entrante se indexa con el cuerpo que baja de S3", async (t) => {
    if (!ftsDisponible) return t.skip("sin FTS5");
    const dom = await dominioNuevo();
    const conv = await conversacion(dom.id, "Entrante");
    const termino = `entrantes3${sufijo()}`;
    const s3Key = `entrante-${sufijo()}`;
    respuestas.set(s3Key, mime(`hola desde S3 ${termino}`));
    const msg = await mensaje(conv.id, { s3Bucket: BUCKET, s3Key });

    await runBackfill({ pauseMs: 0 });

    assert.equal(llamadas.filter((k) => k === s3Key).length, 1, "una sola descarga de S3");
    assert.equal(estado(msg.id)?.status, "ok");
    assert.ok(searchConversations(dom.id, termino).some((c) => c.id === conv.id));
  });

  it("un entrante sin cuerpo recuperable queda saltado y la siguiente corrida no lo pide", async (t) => {
    if (!ftsDisponible) return t.skip("sin FTS5");
    const dom = await dominioNuevo();
    const conv = await conversacion(dom.id, "Sin cuerpo");
    const s3Key = `vacio-${sufijo()}`;
    respuestas.set(s3Key, "");
    const msg = await mensaje(conv.id, { s3Bucket: BUCKET, s3Key });

    const primera = await runBackfill({ pauseMs: 0 });

    assert.equal(estado(msg.id)?.status, "skipped");
    assert.equal(primera.indexed, 1, "el saltado cuenta en indexed (comportamiento actual)");

    llamadas.length = 0;
    await runBackfill({ pauseMs: 0 });
    assert.equal(llamadas.includes(s3Key), false, "ya quedó marcado: no se vuelve a pedir");
  });

  it("si S3 falla en un mensaje, queda con error, la corrida sigue y no se reintenta", async (t) => {
    if (!ftsDisponible) return t.skip("sin FTS5");
    const dom = await dominioNuevo();
    const conv = await conversacion(dom.id, "Falla S3");
    const termino = `sobrevive${sufijo()}`;
    const roto = `roto-${sufijo()}`;
    const bueno = `bien-${sufijo()}`;
    respuestas.set(roto, new Error("S3 caído"));
    respuestas.set(bueno, mime(`cuerpo que sí llega ${termino}`));
    const mRoto = await mensaje(conv.id, { s3Bucket: BUCKET, s3Key: roto });
    const mBueno = await mensaje(conv.id, { s3Bucket: BUCKET, s3Key: bueno });

    const res = await runBackfill({ pauseMs: 0 });

    assert.equal(estado(mRoto.id)?.status, "error");
    assert.match(estado(mRoto.id)?.error ?? "", /S3 caído/);
    assert.equal(estado(mBueno.id)?.status, "ok", "el siguiente mensaje sí se indexa");
    assert.equal(res.errors, 1);
    assert.ok(searchConversations(dom.id, termino).some((c) => c.id === conv.id));

    llamadas.length = 0;
    await runBackfill({ pauseMs: 0 });
    assert.equal(llamadas.includes(roto), false, "el error no se reintenta en bucle");
  });

  it("con tope de 3 procesa los 3 más nuevos y la siguiente corrida termina los 2", async (t) => {
    if (!ftsDisponible) return t.skip("sin FTS5");
    const dom = await dominioNuevo();
    const conv = await conversacion(dom.id, "Tope");
    const ahora = Date.now();
    // i = 0 es el más nuevo; orden de la consulta: created_at DESC.
    const claves = [0, 1, 2, 3, 4].map((i) => `tope-${i}-${sufijo()}`);
    for (const [i, key] of claves.entries()) {
      respuestas.set(key, mime(`cuerpo ${i}`));
      await mensaje(conv.id, {
        s3Bucket: BUCKET,
        s3Key: key,
        createdAt: new Date(ahora - i * 60_000).toISOString(),
      });
    }

    const primera = await runBackfill({ batchSize: 2, maxMessages: 3, pauseMs: 0 });

    assert.equal(primera.indexed, 3);
    assert.deepEqual([...llamadas].sort(), claves.slice(0, 3).sort());

    llamadas.length = 0;
    const segunda = await runBackfill({ batchSize: 2, pauseMs: 0 });

    assert.equal(segunda.indexed, 2);
    assert.equal(segunda.remaining, 0);
    assert.deepEqual([...llamadas].sort(), claves.slice(3).sort(), "cero descargas repetidas");
  });

  it("una segunda corrida mientras la primera espera a S3 regresa sin procesar nada", async (t) => {
    if (!ftsDisponible) return t.skip("sin FTS5");
    const dom = await dominioNuevo();
    const conv = await conversacion(dom.id, "Concurrencia");
    const termino = `concurrente${sufijo()}`;
    const key = `lento-${sufijo()}`;
    let liberar: (raw: string) => void = () => {};
    respuestas.set(key, new Promise<string>((resolve) => { liberar = resolve; }));
    const msg = await mensaje(conv.id, { s3Bucket: BUCKET, s3Key: key });

    const p1 = runBackfill({ pauseMs: 0 });
    await esperarA(() => llamadas.includes(key));

    // Sin la guarda `running`, esta segunda corrida se queda esperando el mismo S3:
    // el tope la deja fallar en rojo en vez de colgar el proceso.
    const p2 = runBackfill({ pauseMs: 0 });
    const tope = new Promise<null>((resolve) => setTimeout(() => resolve(null), 2000));
    const res2 = await Promise.race([p2, tope]);
    liberar(mime(`cuerpo lento ${termino}`));

    assert.ok(res2, "la segunda corrida regresó sin esperar a S3");
    assert.deepEqual({ indexed: res2.indexed, errors: res2.errors }, { indexed: 0, errors: 0 });

    const res1 = await p1;
    assert.equal(res1.indexed, 1);
    assert.equal(llamadas.filter((k) => k === key).length, 1, "una sola llamada a S3");
    assert.equal(estado(msg.id)?.status, "ok");
    assert.ok(searchConversations(dom.id, termino).some((c) => c.id === conv.id));
  });
});
