// Pruebas de `sse-hub.ts`: el hub en memoria del que cuelga el tiempo real de la Bandeja.
//
// `bandeja-equipo.test.ts` ya lo toca, pero a través de la app (endpoints y SSE de verdad):
// eso prueba que el cableado está, no el contrato del módulo. Aquí va el módulo solo, con un
// doble del controller de `ReadableStream` (los bytes que se encolan y a quién le llegan) y
// con el reloj congelado para los TTL. Ver docs/agents/pruebas-mocks.md.
import { describe, it, afterEach, mock } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  addSseClient,
  notifyInbox,
  getSseClientCount,
  setPresence,
  clearPresence,
  listPresence,
  notifyPresence,
} from "./sse-hub.ts";

/** Doble del controller: en vez de servir un stream, guarda los bytes que le encolan. */
function clienteFalso({ revienta = false }: { revienta?: boolean } = {}) {
  const chunks: Uint8Array[] = [];
  const controller = {
    enqueue(chunk: Uint8Array) {
      if (revienta) throw new TypeError("stream ya cerrado");
      chunks.push(chunk);
    },
    close() {},
    error() {},
    desiredSize: 1,
  } as unknown as ReadableStreamDefaultController;
  /** El aviso que recibió, como texto: es lo que vería el `EventSource` del navegador. */
  const recibido = () => chunks.map((c) => new TextDecoder().decode(c)).join("");
  return { controller, chunks, recibido };
}

describe("sse-hub: a quién le llega el aviso de la Bandeja", () => {
  it("sólo lo reciben los clientes del dominio avisado", () => {
    const propio = clienteFalso();
    const ajeno = clienteFalso();
    const sueltaPropio = addSseClient("ana@x.com", "dom-a", propio.controller);
    const sueltaAjeno = addSseClient("beto@x.com", "dom-b", ajeno.controller);

    notifyInbox("dom-a", "new_message", { conversationId: "c1" });

    assert.equal(propio.chunks.length, 1);
    assert.equal(ajeno.chunks.length, 0, "el aviso no cruza de dominio");

    sueltaPropio();
    sueltaAjeno();
  });

  it("sale con el formato SSE exacto", () => {
    const cliente = clienteFalso();
    const suelta = addSseClient("ana@x.com", "dom-a", cliente.controller);

    notifyInbox("dom-a", "new_message", { conversationId: "c1", unread: 2 });

    assert.equal(cliente.recibido(), 'event: new_message\ndata: {"conversationId":"c1","unread":2}\n\n');
    suelta();
  });

  it("las tres pestañas del mismo agente reciben el aviso", () => {
    const p1 = clienteFalso();
    const p2 = clienteFalso();
    const p3 = clienteFalso();
    const sueltas = [
      addSseClient("ana@x.com", "dom-a", p1.controller),
      addSseClient("ana@x.com", "dom-a", p2.controller),
      addSseClient("ana@x.com", "dom-a", p3.controller),
    ];

    notifyInbox("dom-a", "conv_updated", { conversationId: "c1" });

    assert.deepEqual([p1.chunks.length, p2.chunks.length, p3.chunks.length], [1, 1, 1]);
    sueltas.forEach((s) => s());
  });

  it("un cliente caído no impide que los demás reciban el aviso", () => {
    const caido = clienteFalso({ revienta: true });
    const sano = clienteFalso();
    // El caído se registra primero: si el `try` no estuviera donde está, el aviso no llegaría al sano.
    const sueltaCaido = addSseClient("ana@x.com", "dom-a", caido.controller);
    const sueltaSano = addSseClient("beto@x.com", "dom-a", sano.controller);

    assert.doesNotThrow(() => notifyInbox("dom-a", "new_message", { conversationId: "c1" }));
    assert.equal(sano.chunks.length, 1);

    sueltaCaido();
    sueltaSano();
  });

  it("al irse el último cliente el conteo vuelve a cero", () => {
    const base = getSseClientCount();
    const uno = clienteFalso();
    const dos = clienteFalso();
    const sueltaUno = addSseClient("ana@x.com", "dom-a", uno.controller);
    const sueltaDos = addSseClient("beto@x.com", "dom-b", dos.controller);

    assert.equal(getSseClientCount(), base + 2);
    sueltaUno();
    assert.equal(getSseClientCount(), base + 1);
    sueltaDos();
    assert.equal(getSseClientCount(), base, "sin clientes el mapa queda vacío");

    // Y la baja es idempotente: soltar dos veces no puede descontar a otro.
    sueltaDos();
    assert.equal(getSseClientCount(), base);
  });
});

describe("sse-hub: presencia (TTL de typing vs viewing)", () => {
  afterEach(() => mock.timers.reset());

  it("el typing caduca antes que el viewing", () => {
    const T0 = 1_760_000_000_000;
    mock.timers.enable({ apis: ["Date"], now: T0 });
    const dom = "dom-ttl";
    setPresence(dom, "ana@x.com", "Ana", "c1", "typing");
    setPresence(dom, "beto@x.com", "Beto", "c2", "viewing");

    mock.timers.tick(12_001);
    assert.deepEqual(
      listPresence(dom).map((p) => p.email),
      ["beto@x.com"],
      "a los 12 s el typing ya no está y el viewing todavía sí",
    );

    mock.timers.tick(35_000 - 12_001 + 1);
    assert.equal(listPresence(dom).length, 0, "a los 35 s el viewing también caduca");

    clearPresence(dom, "ana@x.com");
    clearPresence(dom, "beto@x.com");
  });

  it("la presencia viva viaja con su caducidad", () => {
    const T0 = 1_760_000_000_000;
    mock.timers.enable({ apis: ["Date"], now: T0 });
    const dom = "dom-campo";
    setPresence(dom, "ana@x.com", "Ana", "c1", "viewing");

    // El campo es `expiresAt` y va en el mismo JSON que come el front (`agents`).
    assert.deepEqual(listPresence(dom), [
      { email: "ana@x.com", name: "Ana", conversationId: "c1", state: "viewing", expiresAt: T0 + 35_000 },
    ]);

    clearPresence(dom, "ana@x.com");
  });

  it("notifyPresence manda el snapshot completo", () => {
    const cliente = clienteFalso();
    const suelta = addSseClient("ana@x.com", "dom-p", cliente.controller);
    setPresence("dom-p", "ana@x.com", "Ana", "c1", "viewing");
    setPresence("dom-p", "beto@x.com", "Beto", "c2", "typing");

    notifyPresence("dom-p");

    const payload = cliente.recibido();
    assert.ok(payload.startsWith("event: presence\ndata: "), `formato inesperado: ${payload}`);
    assert.ok(payload.endsWith("\n\n"));
    const data = JSON.parse(payload.slice("event: presence\ndata: ".length, -2)) as {
      agents: { email: string; state: string }[];
    };
    assert.deepEqual(
      data.agents.map((a) => `${a.email}:${a.state}`).sort(),
      ["ana@x.com:viewing", "beto@x.com:typing"],
      "el snapshot lleva a todos los del dominio, no deltas",
    );

    suelta();
    clearPresence("dom-p", "ana@x.com");
    clearPresence("dom-p", "beto@x.com");
  });
});

describe("sse-hub.ts: sin identificadores en español", () => {
  it("no conserva los nombres viejos del módulo", () => {
    const fuente = readFileSync(new URL("./sse-hub.ts", import.meta.url), "utf8")
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/.*$/gm, "");
    for (const viejo of ["expira", "ahora", "vivos"]) {
      assert.ok(
        !new RegExp(`\\b${viejo}\\b`).test(fuente),
        `\`${viejo}\` sigue en el código de sse-hub.ts (los comentarios en español no cuentan)`,
      );
    }
  });
});
