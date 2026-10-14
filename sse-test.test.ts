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
function fakeClient({ throws = false }: { throws?: boolean } = {}) {
  const chunks: Uint8Array[] = [];
  const controller = {
    enqueue(chunk: Uint8Array) {
      if (throws) throw new TypeError("stream ya cerrado");
      chunks.push(chunk);
    },
    close() {},
    error() {},
    desiredSize: 1,
  } as unknown as ReadableStreamDefaultController;
  /** El aviso que recibió, como texto: es lo que vería el `EventSource` del navegador. */
  const received = () => chunks.map((c) => new TextDecoder().decode(c)).join("");
  return { controller, chunks, received };
}

describe("sse-hub: a quién le llega el aviso de la Bandeja", () => {
  it("sólo lo reciben los clientes del dominio avisado", () => {
    const own = fakeClient();
    const other = fakeClient();
    const releaseOwn = addSseClient("ana@x.com", "dom-a", own.controller);
    const releaseOther = addSseClient("beto@x.com", "dom-b", other.controller);

    notifyInbox("dom-a", "new_message", { conversationId: "c1" });

    assert.equal(own.chunks.length, 1);
    assert.equal(other.chunks.length, 0, "el aviso no cruza de dominio");

    releaseOwn();
    releaseOther();
  });

  it("sale con el formato SSE exacto", () => {
    const client = fakeClient();
    const release = addSseClient("ana@x.com", "dom-a", client.controller);

    notifyInbox("dom-a", "new_message", { conversationId: "c1", unread: 2 });

    assert.equal(client.received(), 'event: new_message\ndata: {"conversationId":"c1","unread":2}\n\n');
    release();
  });

  it("las tres pestañas del mismo agente reciben el aviso", () => {
    const tab1 = fakeClient();
    const tab2 = fakeClient();
    const tab3 = fakeClient();
    const releases = [
      addSseClient("ana@x.com", "dom-a", tab1.controller),
      addSseClient("ana@x.com", "dom-a", tab2.controller),
      addSseClient("ana@x.com", "dom-a", tab3.controller),
    ];

    notifyInbox("dom-a", "conv_updated", { conversationId: "c1" });

    assert.deepEqual([tab1.chunks.length, tab2.chunks.length, tab3.chunks.length], [1, 1, 1]);
    releases.forEach((release) => release());
  });

  it("un cliente caído no impide que los demás reciban el aviso", () => {
    const dead = fakeClient({ throws: true });
    const healthy = fakeClient();
    // El caído se registra primero: si el `try` no estuviera donde está, el aviso no llegaría al sano.
    const releaseDead = addSseClient("ana@x.com", "dom-a", dead.controller);
    const releaseHealthy = addSseClient("beto@x.com", "dom-a", healthy.controller);

    assert.doesNotThrow(() => notifyInbox("dom-a", "new_message", { conversationId: "c1" }));
    assert.equal(healthy.chunks.length, 1);

    releaseDead();
    releaseHealthy();
  });

  it("al irse el último cliente el conteo vuelve a cero", () => {
    const base = getSseClientCount();
    const one = fakeClient();
    const two = fakeClient();
    const releaseOne = addSseClient("ana@x.com", "dom-a", one.controller);
    const releaseTwo = addSseClient("beto@x.com", "dom-b", two.controller);

    assert.equal(getSseClientCount(), base + 2);
    releaseOne();
    assert.equal(getSseClientCount(), base + 1);
    releaseTwo();
    assert.equal(getSseClientCount(), base, "sin clientes el mapa queda vacío");

    // Y la baja es idempotente: soltar dos veces no puede descontar a otro.
    releaseTwo();
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
    const client = fakeClient();
    const release = addSseClient("ana@x.com", "dom-p", client.controller);
    setPresence("dom-p", "ana@x.com", "Ana", "c1", "viewing");
    setPresence("dom-p", "beto@x.com", "Beto", "c2", "typing");

    notifyPresence("dom-p");

    const payload = client.received();
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

    release();
    clearPresence("dom-p", "ana@x.com");
    clearPresence("dom-p", "beto@x.com");
  });
});

describe("identificadores en inglés: el módulo y esta prueba", () => {
  it("no quedan nombres en español en el código (comentarios y strings no cuentan)", () => {
    // Quita comentarios y literales de texto: los comentarios y los strings pueden seguir en español.
    const codeOnly = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8")
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/.*$/gm, "")
      .replace(/"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`/g, '""');
    const forbidden = [
      "expira", "ahora", "vivos",
      "clienteFalso", "revienta", "recibido", "propio", "ajeno",
      "sueltaPropio", "sueltaAjeno", "suelta", "sueltas", "cliente",
      "caido", "sano", "sueltaCaido", "sueltaSano", "uno", "dos", "sueltaUno", "sueltaDos",
      "fuente", "viejo",
    ];
    for (const file of ["./sse-hub.ts", "./sse-test.test.ts"]) {
      const code = codeOnly(file);
      for (const name of forbidden) {
        assert.ok(!new RegExp(`\\b${name}\\b`).test(code), `\`${name}\` sigue en el código de ${file}`);
      }
    }
  });
});
