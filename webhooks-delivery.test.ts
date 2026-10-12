// Entrega de webhooks: qué se manda firmado, cuándo se reprograma y cuándo se rinde.
//
// `webhooks.test.ts` (pedido #54) fija `signPayload`/`verifyWebhookSignature` como unidad.
// Aquí se prueba la otra mitad: la entrega real, los reintentos con backoff y la rendición
// al quinto intento. Va en archivo propio a propósito, para no chocar con aquél.
//
// Nada sale a la red: `deliverPending` acepta el `fetch` inyectado.
//
// TRAMPA: `deliverPending` toma TODAS las entregas vencidas de la base, y la base de
// pruebas es una sola para toda la suite. Por eso cada prueba se aísla con su propia URL en
// el receptor y sólo cuenta las llamadas a ESA URL.

import { describe, it, before, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";
import { eq } from "drizzle-orm";

import { createUser, createDomain } from "./db.ts";
import { db } from "./pg.ts";
import { webhookDeliveries } from "./schema.ts";
import {
  MAX_ATTEMPTS,
  RETRY_DELAYS_MS,
  createWebhook,
  deliverPending,
  emitEvent,
  enqueuePing,
  listDeliveries,
  updateWebhook,
  verifyWebhookSignature,
} from "./webhooks.ts";

/** Un POST que el webhook le hizo al receptor. */
interface Llamada { url: string; init: any }

describe("webhooks: entrega, reintentos y rendición", () => {
  const tag = crypto.randomUUID().slice(0, 8);
  const email = `wh-entrega-${tag}@test.com`;
  let domainId: string;

  const llamadas: Llamada[] = [];
  /** Qué contesta el receptor. Cada prueba lo cambia. */
  let responder: (llamada: Llamada) => Response | Promise<Response> =
    () => new Response(null, { status: 200 });

  const receptor = mock.fn(async (url: string, init: any): Promise<Response> => {
    const llamada = { url, init };
    llamadas.push(llamada);
    return responder(llamada);
  });
  const doFetch = receptor as unknown as typeof fetch;

  /** Sólo lo que le llegó a esa URL: el receptor es uno para toda la suite. */
  const aLaUrl = (url: string) => llamadas.filter((l) => l.url === url);

  /** Trae al presente una entrega reprogramada, para ver el intento siguiente sin esperar. */
  const adelantar = (id: string) =>
    db.update(webhookDeliveries)
      .set({ nextAt: new Date(Date.now() - 1000).toISOString() })
      .where(eq(webhookDeliveries.id, id))
      .run();

  before(() => {
    createUser(email, "x");
    domainId = createDomain(email, `wh-entrega-${tag}.test`, [], `ver-${tag}`).id;
  });

  beforeEach(() => {
    llamadas.length = 0;
    responder = () => new Response(null, { status: 200 });
  });

  it("una entrega 2xx queda entregada y su firma se verifica con el secreto del webhook", async () => {
    const url = `https://receptor-${tag}-ok.example.test/hook`;
    const webhook = createWebhook(domainId, url, ["email.received"]);
    enqueuePing(webhook.id, domainId);

    const resultado = await deliverPending(500, doFetch);
    assert.ok(resultado.delivered >= 1);

    const [entrega] = listDeliveries(webhook.id);
    assert.equal(entrega.status, "delivered");
    assert.equal(entrega.attempts, 1);
    assert.equal(entrega.lastStatusCode, 200);
    assert.equal(entrega.lastError, null);

    const [llamada] = aLaUrl(url);
    assert.ok(llamada, "el receptor recibió el POST");
    assert.equal(llamada.init.method, "POST");
    assert.equal(llamada.init.headers["x-mailmask-event"], "ping");
    assert.equal(llamada.init.headers["x-mailmask-delivery"], entrega.id);

    // El receptor verifica con lo que recibió, tal como lo haría un cliente real.
    assert.equal(
      verifyWebhookSignature(
        webhook.secret,
        {
          signature: llamada.init.headers["x-mailmask-signature"],
          timestamp: llamada.init.headers["x-mailmask-timestamp"],
        },
        llamada.init.body,
      ),
      true,
    );
  });

  it("un 5xx deja la entrega pendiente y la reprograma con el primer backoff", async () => {
    const url = `https://receptor-${tag}-500.example.test/hook`;
    const webhook = createWebhook(domainId, url, ["ping"]);
    enqueuePing(webhook.id, domainId);
    responder = () => new Response(null, { status: 503 });

    const antes = Date.now();
    const resultado = await deliverPending(500, doFetch);
    const despues = Date.now();

    const [entrega] = listDeliveries(webhook.id);
    assert.equal(entrega.status, "pending");
    assert.equal(entrega.attempts, 1);
    assert.equal(entrega.lastStatusCode, 503);
    assert.equal(entrega.lastError, "HTTP 503");
    assert.ok(resultado.retried >= 1);

    const nextAt = Date.parse(entrega.nextAt);
    assert.ok(nextAt >= antes + RETRY_DELAYS_MS[0], `nextAt ${entrega.nextAt} antes del backoff`);
    assert.ok(nextAt <= despues + RETRY_DELAYS_MS[0], `nextAt ${entrega.nextAt} después del backoff`);
  });

  it("un error de red reprograma y el segundo intento espera más que el primero", async () => {
    const url = `https://receptor-${tag}-red.example.test/hook`;
    const webhook = createWebhook(domainId, url, ["ping"]);
    const entregaId = enqueuePing(webhook.id, domainId);
    responder = () => { throw new Error("ECONNREFUSED 127.0.0.1:9"); };

    await deliverPending(500, doFetch);
    const trasPrimero = listDeliveries(webhook.id)[0];
    assert.equal(trasPrimero.status, "pending");
    assert.equal(trasPrimero.attempts, 1);
    assert.match(String(trasPrimero.lastError), /ECONNREFUSED/);

    adelantar(entregaId);
    const antes = Date.now();
    await deliverPending(500, doFetch);
    const despues = Date.now();

    const trasSegundo = listDeliveries(webhook.id)[0];
    assert.equal(trasSegundo.status, "pending");
    assert.equal(trasSegundo.attempts, 2);
    assert.ok(RETRY_DELAYS_MS[1] > RETRY_DELAYS_MS[0], "el backoff tiene que crecer");

    const nextAt = Date.parse(trasSegundo.nextAt);
    assert.ok(nextAt >= antes + RETRY_DELAYS_MS[1], `nextAt ${trasSegundo.nextAt} antes del backoff`);
    assert.ok(nextAt <= despues + RETRY_DELAYS_MS[1], `nextAt ${trasSegundo.nextAt} después del backoff`);
  });

  it("al quinto intento la entrega queda fallida", async () => {
    const url = `https://receptor-${tag}-final.example.test/hook`;
    const webhook = createWebhook(domainId, url, ["ping"]);
    const entregaId = enqueuePing(webhook.id, domainId);
    // Cuatro intentos ya gastados: el que sigue es el último.
    db.update(webhookDeliveries).set({ attempts: MAX_ATTEMPTS - 1 })
      .where(eq(webhookDeliveries.id, entregaId)).run();
    responder = () => new Response(null, { status: 500 });

    const resultado = await deliverPending(500, doFetch);

    const [entrega] = listDeliveries(webhook.id);
    assert.equal(entrega.status, "failed");
    assert.equal(entrega.attempts, MAX_ATTEMPTS);
    assert.equal(entrega.lastStatusCode, 500);
    assert.equal(entrega.lastError, "HTTP 500");
    assert.ok(resultado.failed >= 1);
  });

  it("un webhook desactivado falla sin llamar al receptor", async () => {
    const url = `https://receptor-${tag}-off.example.test/hook`;
    const webhook = createWebhook(domainId, url, ["ping"]);
    enqueuePing(webhook.id, domainId);
    // Se desactiva DESPUÉS de encolar: hacia afuera, `emitEvent` ya no encola para un
    // webhook apagado, así que apagarlo antes dejaría la prueba sin entrega que procesar.
    updateWebhook(domainId, webhook.id, { enabled: false });

    const resultado = await deliverPending(500, doFetch);

    const [entrega] = listDeliveries(webhook.id);
    assert.equal(entrega.status, "failed");
    assert.equal(entrega.lastError, "webhook desactivado");
    assert.equal(aLaUrl(url).length, 0, "a un webhook apagado no se le llama");
    assert.ok(resultado.failed >= 1);
  });

  it("emitEvent encola sólo para los webhooks activos que suscriben el evento", () => {
    const emailEvento = `wh-evento-${tag}@test.com`;
    createUser(emailEvento, "x");
    const dominioEvento = createDomain(emailEvento, `wh-evento-${tag}.test`, [], `ver-evento-${tag}`).id;
    const webhook = createWebhook(dominioEvento, `https://receptor-${tag}-evento.example.test/hook`, ["email.received"]);

    assert.equal(emitEvent(dominioEvento, "email.received", { subject: "hola" }), 1);
    const [entrega] = listDeliveries(webhook.id);
    assert.equal(entrega.event, "email.received");
    assert.equal(entrega.status, "pending");

    updateWebhook(dominioEvento, webhook.id, { enabled: false });
    assert.equal(emitEvent(dominioEvento, "email.received", { subject: "otra vez" }), 0);
    assert.equal(listDeliveries(webhook.id).length, 1, "el evento repetido no encoló otra entrega");
  });
});
