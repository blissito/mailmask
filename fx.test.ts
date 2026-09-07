// Tipo de cambio USD→MXN.
//
// Vivía en una variable de entorno con respaldo 21 cuando el real era 16.89: nadie
// actualiza un número así, y sobre él se calculaba el precio de todos los dominios.
//
// Lo que se fija aquí es lo que puede costar dinero: que una lectura absurda no llegue a
// cotizar, y que se cotice sobre el peor tipo reciente y no sobre el de este segundo —el
// monto de un PreApproval de MercadoPago no se puede cambiar después, así que un dominio
// cotizado en un mínimo pasajero se cobraría bajo costo durante años.

import { describe, it, before, beforeEach } from "node:test";
import assert from "node:assert/strict";

describe("tipo de cambio", () => {
  // deno-lint-ignore no-explicit-any
  let fx: any, sqlite: any;
  const original = globalThis.fetch;

  before(async () => {
    fx = await import("./fx.ts");
    ({ sqlite } = await import("./pg.ts"));
  });

  beforeEach(() => {
    sqlite.prepare("DELETE FROM fx_rates").run();
    globalThis.fetch = original;
  });

  const responder = (cuerpo: unknown, ok = true) => {
    globalThis.fetch = (async () =>
      new Response(JSON.stringify(cuerpo), {
        status: ok ? 200 : 500,
        headers: { "content-type": "application/json" },
      })) as typeof fetch;
  };

  const sembrar = (rate: number, diasAtras: number) =>
    sqlite.prepare("INSERT INTO fx_rates (pair, rate, source, fetched_at) VALUES ('USD/MXN', ?, 'test', ?)")
      .run(rate, new Date(Date.now() - diasAtras * 864e5).toISOString());

  it("guarda una lectura válida", async () => {
    responder({ rates: { MXN: 16.89 } });
    const l = await fx.actualizarTipoDeCambio();
    assert.equal(l.rate, 16.89);
    assert.equal(fx.ultimaLectura().rate, 16.89);
  });

  it("descarta valores absurdos en vez de regalar los dominios", async () => {
    // Una API que contesta 1 no está dando un tipo de cambio; usarlo vendería un `.io` de
    // $71 USD en $85 MXN.
    for (const malo of [1, 0, -5, 900, null, "veinte"]) {
      responder({ rates: { MXN: malo } });
      assert.equal(await fx.actualizarTipoDeCambio(), null, `aceptó ${malo}`);
    }
    assert.equal(fx.ultimaLectura(), null, "guardó una lectura mala");
  });

  it("una fuente caída no rompe nada", async () => {
    globalThis.fetch = (async () => { throw new Error("sin red"); }) as typeof fetch;
    assert.equal(await fx.actualizarTipoDeCambio(), null);
  });

  it("cotiza sobre el máximo de los últimos 30 días, no sobre el de hoy", async () => {
    sembrar(19.5, 20);   // dentro de la ventana
    sembrar(16.2, 1);    // hoy, más barato
    // Cotizar con 16.2 dejaría la renovación fija por años en un mínimo pasajero.
    assert.equal(fx.tipoDeCambio(), 19.5);
  });

  it("lo de hace más de 30 días ya no cuenta", async () => {
    sembrar(25, 200);
    sembrar(17, 2);
    assert.equal(fx.tipoDeCambio(), 17);
  });

  it("sin ninguna lectura usa el respaldo, que es alto a propósito", () => {
    assert.ok(fx.tipoDeCambio() >= 16, "el respaldo no puede quedar bajo");
  });

  it("avisa cuando el dato se hace viejo", () => {
    assert.equal(fx.lecturaRancia(), true, "sin lecturas debe considerarse rancio");
    sembrar(17, 3);
    assert.equal(fx.lecturaRancia(), true);
    sqlite.prepare("DELETE FROM fx_rates").run();
    sembrar(17, 0);
    assert.equal(fx.lecturaRancia(), false);
  });

  it("el precio de venta sigue al tipo de cambio", async () => {
    const { precioDeTransferencia } = await import("./tld-pricing.ts");
    sembrar(17, 1);
    const barato = await precioDeTransferencia(".design");

    sqlite.prepare("DELETE FROM fx_rates").run();
    sembrar(25, 1);
    const caro = await precioDeTransferencia(".design");

    if (barato && caro) {
      assert.ok(caro.transferMxnCents > barato.transferMxnCents, "el precio no siguió al tipo de cambio");
    }
  });
});
