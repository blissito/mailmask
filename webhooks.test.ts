// Firma de webhooks: `signPayload` es lo que `deliverPending` manda en
// `x-mailmask-signature` y `verifyWebhookSignature` lo que un receptor corre para decidir
// si un webhook es nuestro. Estaban sin pruebas, así que un cambio en el formato
// `timestamp.body`, en el prefijo `sha256=` o en la ventana de 5 min rompía a TODOS los
// receptores sin que el CI lo notara.
//
// Lo que se fija aquí es el CONTRATO —qué firma se acepta y cuál se rechaza—, no la
// implementación: un refactor que lo conserve debe dejar estas pruebas en verde. Los dos
// bordes que hoy se comportan de una manera concreta quedan dichos en comentario.

import { describe, it, afterEach, mock } from "node:test";
import assert from "node:assert/strict";

import { signPayload, verifyWebhookSignature } from "./webhooks.ts";

// Igual que en `deliverPending`: el timestamp viaja como string de MILISEGUNDOS y entra
// tal cual en el mensaje firmado, aunque la tolerancia se compruebe sobre su valor numérico.
const T0 = 1_760_000_000_000;
const TOLERANCIA = 5 * 60_000;
const SECRETO = "whsec_secreto_de_prueba";
const CUERPO = JSON.stringify({
  event: "email.received",
  domainId: "dom_1",
  timestamp: new Date(T0).toISOString(),
  data: { id: "msg_1" },
});

/** Congela `Date.now()` en `t`. El reloj es del proceso: lo restaura el `afterEach`. */
function reloj(t: number): void {
  mock.method(Date, "now", () => t);
}

/** Arma los dos headers como los manda el emisor para el timestamp `ts`. */
function firmar(ts: number, opts: { secreto?: string; cuerpo?: string } = {}): { signature: string; timestamp: string } {
  const timestamp = String(ts);
  return { signature: signPayload(opts.secreto ?? SECRETO, timestamp, opts.cuerpo ?? CUERPO), timestamp };
}

describe("firma de webhooks", () => {
  afterEach(() => {
    mock.restoreAll();
  });

  it("signPayload es determinista y su formato es `sha256=` + 64 hex", () => {
    const a = signPayload(SECRETO, String(T0), CUERPO);
    const b = signPayload(SECRETO, String(T0), CUERPO);

    assert.match(a, /^sha256=[0-9a-f]{64}$/);
    assert.equal(b, a, "mismo secreto, timestamp y cuerpo dan la misma firma");
  });

  it("acepta una firma recién hecha con el mismo secreto, timestamp y cuerpo", () => {
    reloj(T0);

    assert.equal(verifyWebhookSignature(SECRETO, firmar(T0), CUERPO), true);
  });

  it("rechaza si cambia un solo carácter del cuerpo, del secreto o de la firma", () => {
    reloj(T0);
    const headers = firmar(T0);

    assert.equal(verifyWebhookSignature(SECRETO, headers, `${CUERPO} `), false, "cuerpo alterado");
    assert.equal(verifyWebhookSignature(`${SECRETO}x`, headers, CUERPO), false, "secreto alterado");

    // Mismo largo (71 caracteres), un solo dígito hexadecimal distinto.
    const ultimo = headers.signature.at(-1);
    const alterada = `${headers.signature.slice(0, -1)}${ultimo === "0" ? "1" : "0"}`;
    assert.equal(alterada.length, headers.signature.length);
    assert.equal(verifyWebhookSignature(SECRETO, { ...headers, signature: alterada }, CUERPO), false, "firma alterada");
  });

  it("rechaza los timestamps fuera de la ventana de 5 min y acepta el borde exacto", () => {
    reloj(T0);

    // La comprobación es `Math.abs(Date.now() - ts) > toleranceMs`, estricta: justo a 5 min
    // la firma sigue pasando y sólo se rechaza al pasarse por un milisegundo.
    assert.equal(verifyWebhookSignature(SECRETO, firmar(T0 - TOLERANCIA), CUERPO), true, "borde viejo exacto");
    assert.equal(verifyWebhookSignature(SECRETO, firmar(T0 - TOLERANCIA - 1), CUERPO), false, "viejo por 1 ms");
    assert.equal(verifyWebhookSignature(SECRETO, firmar(T0 + TOLERANCIA), CUERPO), true, "borde futuro exacto");
    assert.equal(verifyWebhookSignature(SECRETO, firmar(T0 + TOLERANCIA + 1), CUERPO), false, "futuro por 1 ms");
  });

  it("un timestamp que no es número regresa false sin lanzar", () => {
    reloj(T0);
    const firma = signPayload(SECRETO, "abc", CUERPO);

    assert.doesNotThrow(() => {
      assert.equal(verifyWebhookSignature(SECRETO, { signature: firma, timestamp: "abc" }, CUERPO), false);
      assert.equal(
        verifyWebhookSignature(SECRETO, { signature: signPayload(SECRETO, "NaN", CUERPO), timestamp: "NaN" }, CUERPO),
        false,
      );
    });
  });

  it("una firma de otro largo (truncada, vacía o con relleno) regresa false sin lanzar", () => {
    reloj(T0);
    const { signature, timestamp } = firmar(T0);

    // El chequeo de largo tiene que ir ANTES de `timingSafeEqual`: con buffers de distinto
    // tamaño esa función lanza, y aquí la entrada la elige quien llama.
    for (const firma of [signature.slice(0, 20), "", signature.slice(0, -1), `${signature}00`]) {
      assert.doesNotThrow(() => {
        assert.equal(
          verifyWebhookSignature(SECRETO, { signature: firma, timestamp }, CUERPO),
          false,
          `firma de ${firma.length} caracteres`,
        );
      });
    }
  });
});
