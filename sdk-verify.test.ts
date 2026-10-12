// `webhooks.test.ts` prueba la versión del SERVIDOR (síncrona): la `verifyWebhookSignature`
// de `webhooks.ts`. El SDK trae su PROPIA copia en `sdk/src/verify.ts` —asíncrona, con
// WebCrypto y con su propio `constantTimeEqual`— y `sdk.test.ts` sólo cubre el ida y vuelta
// feliz contra el servidor. Aquí van los BORDES de la copia del SDK, que es la que corre en
// el receptor. Ficha del contrato: docs/agents/firma-webhooks.md
import { describe, it, afterEach, mock } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";

import { verifyWebhookSignature } from "./sdk/src/verify.ts";

const SECRETO = "whsec_secreto_de_prueba";
const CUERPO = JSON.stringify({ event: "email.received", domainId: "dom_1", data: { id: "msg_1" } });
const TOLERANCIA = 5 * 60_000;

/**
 * Firma de referencia, calculada APARTE con `node:crypto` (no con el código bajo prueba):
 * `sha256=` + HMAC-SHA256(secreto, `` `${timestamp}.${cuerpo}` ``). Es el vector del
 * contrato: si alguien le diera la vuelta al mensaje firmado, esto dejaría de coincidir.
 */
function firmaDeReferencia(ts: string, opts: { secreto?: string; cuerpo?: string } = {}): string {
  const mac = createHmac("sha256", opts.secreto ?? SECRETO).update(`${ts}.${opts.cuerpo ?? CUERPO}`).digest("hex");
  return `sha256=${mac}`;
}

const headers = (timestamp: string, signature: string) => ({ signature, timestamp });

describe("firma del SDK: acepta lo que el emisor manda", () => {
  afterEach(() => mock.timers.reset());

  it("acepta una firma calculada aparte con node:crypto", async () => {
    const ts = String(Date.now());
    assert.equal(await verifyWebhookSignature(SECRETO, headers(ts, firmaDeReferencia(ts)), CUERPO), true);
  });

  it("rechaza el cuerpo alterado aunque la firma sea válida para el original", async () => {
    const ts = String(Date.now());
    const firma = firmaDeReferencia(ts);
    const alterado = CUERPO.replace("msg_1", "msg_2");
    assert.equal(await verifyWebhookSignature(SECRETO, headers(ts, firma), alterado), false);
  });

  it("rechaza un secreto distinto", async () => {
    const ts = String(Date.now());
    assert.equal(await verifyWebhookSignature("otro-secreto", headers(ts, firmaDeReferencia(ts)), CUERPO), false);
  });

  it("rechaza una firma alterada del MISMO largo", async () => {
    // El largo igual es el caso que atraviesa todos los cortes previos: sólo lo detiene la
    // comparación de contenido.
    const ts = String(Date.now());
    const firma = firmaDeReferencia(ts);
    const alterada = firma.slice(0, 10) + (firma[10] === "0" ? "1" : "0") + firma.slice(11);
    assert.notEqual(alterada, firma);
    assert.equal(await verifyWebhookSignature(SECRETO, headers(ts, alterada), CUERPO), false);
  });
});

describe("firma del SDK: entradas mal formadas dan false SIN lanzar", () => {
  afterEach(() => mock.timers.reset());

  it("firmas truncadas, vacías o con relleno", async () => {
    // El largo de la firma lo elige quien llama: el chequeo de largo debe ir ANTES de
    // comparar, o una entrada maliciosa tumba la verificación con una excepción.
    const ts = String(Date.now());
    const buena = firmaDeReferencia(ts);
    const malas = [
      "",                 // vacía
      "sha256=",          // sólo el prefijo
      "sha256=deadbeef",  // truncada a unos bytes
      buena.slice(0, -1), // un hex de menos
      buena + "00",       // relleno de más
      buena.toUpperCase(),// mismo largo, otro alfabeto
    ];
    for (const firma of malas) {
      await assert.doesNotReject(async () => {
        assert.equal(
          await verifyWebhookSignature(SECRETO, headers(ts, firma), CUERPO),
          false,
          `la firma «${firma.slice(0, 16)}…» no dio false`,
        );
      });
    }
  });

  it("un timestamp no numérico no lanza", async () => {
    await assert.doesNotReject(async () => {
      assert.equal(await verifyWebhookSignature(SECRETO, headers("abc", firmaDeReferencia("abc")), CUERPO), false);
    });
  });
});

describe("firma del SDK: la ventana de tolerancia es estricta", () => {
  afterEach(() => mock.timers.reset());

  it("justo en el límite pasa; 1 ms después se rechaza", async () => {
    const T0 = 1_760_000_000_000;
    mock.timers.enable({ apis: ["Date"], now: T0 });

    const enElLimite = String(T0 - TOLERANCIA);
    assert.equal(
      await verifyWebhookSignature(SECRETO, headers(enElLimite, firmaDeReferencia(enElLimite)), CUERPO, TOLERANCIA),
      true,
      "a exactamente toleranceMs debía pasar",
    );

    const unMsTarde = String(T0 - TOLERANCIA - 1);
    assert.equal(
      await verifyWebhookSignature(SECRETO, headers(unMsTarde, firmaDeReferencia(unMsTarde)), CUERPO, TOLERANCIA),
      false,
      "a toleranceMs + 1 debía rechazarse",
    );
  });

  it("un timestamp viejo pero bien firmado se rechaza por la ventana, no por la firma", async () => {
    const T0 = 1_760_000_000_000;
    mock.timers.enable({ apis: ["Date"], now: T0 });
    const viejo = String(T0 - 10 * TOLERANCIA);
    assert.equal(await verifyWebhookSignature(SECRETO, headers(viejo, firmaDeReferencia(viejo)), CUERPO, TOLERANCIA), false);
  });
});
