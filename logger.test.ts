// Pruebas de logger.ts: cada nivel sale por su canal de consola como una línea JSON.
//
// Los canales se espían con t.mock.method: el espía se restaura solo al terminar cada
// prueba, así que no ensucia el reporte de node:test ni las demás pruebas.

import { describe, it, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { log } from "./logger.js";

type Channel = "log" | "warn" | "error";

/** Espía los tres canales de consola y devuelve las líneas que recibió cada uno. */
function captureChannels(t: TestContext): Record<Channel, string[]> {
  const calls: Record<Channel, string[]> = { log: [], warn: [], error: [] };
  for (const channel of ["log", "warn", "error"] as const) {
    t.mock.method(console, channel, (line: string) => {
      calls[channel].push(line);
    });
  }
  return calls;
}

describe("log: canal por nivel", () => {
  it("error sale por console.error y no toca los otros canales", (t) => {
    const calls = captureChannels(t);
    log("error", "billing", "cobro fallido");
    assert.equal(calls.error.length, 1);
    assert.equal(calls.log.length, 0);
    assert.equal(calls.warn.length, 0);
  });

  it("warn sale por console.warn y no toca los otros canales", (t) => {
    const calls = captureChannels(t);
    log("warn", "webhook", "reintento");
    assert.equal(calls.warn.length, 1);
    assert.equal(calls.log.length, 0);
    assert.equal(calls.error.length, 0);
  });

  it("info sale por console.log y no toca los otros canales", (t) => {
    const calls = captureChannels(t);
    log("info", "cron", "tarea corrida");
    assert.equal(calls.log.length, 1);
    assert.equal(calls.warn.length, 0);
    assert.equal(calls.error.length, 0);
  });
});

describe("log: forma de la línea", () => {
  it("cada línea es JSON válido con ts, level, component y msg", (t) => {
    const calls = captureChannels(t);
    log("info", "auth", "sesión iniciada");
    const entry = JSON.parse(calls.log[0]);
    assert.equal(entry.level, "info");
    assert.equal(entry.component, "auth");
    assert.equal(entry.msg, "sesión iniciada");
    assert.equal(typeof entry.ts, "string");
  });

  it("ts es una fecha ISO exacta (no un formato parecido)", (t) => {
    const calls = captureChannels(t);
    log("info", "server", "arranque");
    const { ts } = JSON.parse(calls.log[0]);
    assert.equal(new Date(ts).toISOString(), ts);
  });

  it("sin datos extra, la línea tiene exactamente las cuatro llaves base", (t) => {
    const calls = captureChannels(t);
    log("info", "process", "listo");
    const keys = Object.keys(JSON.parse(calls.log[0])).sort();
    assert.deepEqual(keys, ["component", "level", "msg", "ts"]);
  });

  it("emite exactamente una línea por llamada", (t) => {
    const calls = captureChannels(t);
    log("warn", "dmarc", "reporte tardío");
    assert.equal(calls.warn.length, 1);
    assert.equal(calls.warn[0].includes("\n"), false);
  });
});

describe("log: datos extra", () => {
  it("los datos extra aparecen en el mismo objeto, al mismo nivel", (t) => {
    const calls = captureChannels(t);
    log("info", "cron", "lote", { jobId: 7, ok: true, retries: 0 });
    const entry = JSON.parse(calls.log[0]);
    assert.equal(entry.jobId, 7);
    assert.equal(entry.ok, true);
    assert.equal(entry.retries, 0);
    assert.equal(entry.component, "cron");
  });
});
