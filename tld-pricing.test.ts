// Precio de transferencia (`tld-pricing.ts`), con AWS y el tipo de cambio mockeados.
//
// El número que sale de aquí se cobra en un PreApproval de MercadoPago que ya no se puede
// cambiar: si se calcula bajo, se vende bajo costo durante todos los años de la renovación.
// Por eso los montos esperados van como literales hechos a mano (51 USD → 1229 MXN) y no
// reimplementando la fórmula — una prueba que copia la lógica pasa siempre y no prueba nada.
//
// Dos trampas del módulo, y de ahí el orden de este archivo:
//   · `cache` es un Map a nivel de módulo y `fx.js` se importa de forma ESTÁTICA: `mock.module`
//     va antes de importar `tld-pricing.ts`, y cada caso usa un TLD distinto para no heredar
//     el precio (ni el «no hay precio») del caso anterior.
//   · Un precio de 0 SÍ queda en caché (se guarda antes de descartar el cero), pero un `null`
//     o una excepción no: eso cambia qué se le pregunta a AWS en la siguiente llamada.

import { describe, it, before, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";

/** El tipo de cambio se mockea a un valor redondo: así el monto esperado se calcula a mano. */
const FX_MXN_POR_USD = 20;

interface PrecioAws { transferUsdCents: number; renewUsdCents: number }

const consultas: string[] = [];
let respuestaAws: (tld: string) => PrecioAws | null = () => null;

describe("precio de transferencia", () => {
  // deno-lint-ignore no-explicit-any
  let mod: any;

  before(async () => {
    mock.module("./fx.ts", { namedExports: { tipoDeCambio: () => FX_MXN_POR_USD } });
    mock.module("./route53.ts", {
      namedExports: {
        listTldPrice: async (tld: string) => {
          consultas.push(tld);
          return respuestaAws(tld);
        },
      },
    });
    mod = await import("./tld-pricing.ts");
  });

  beforeEach(() => {
    consultas.length = 0;
    respuestaAws = () => null;
  });

  it("un TLD de la tabla curada manda y no consulta AWS", async () => {
    const { TLD_PRICES } = await import("./db.ts");
    respuestaAws = () => { throw new Error("no debió preguntarle a AWS"); };

    const com = await mod.precioDeTransferencia(".com");

    assert.equal(com.curado, true);
    // El precio curado es de `TLD_PRICES`, no una copia: si mañana cambia la tabla, esto lo ve.
    assert.equal(com.transferMxnCents, TLD_PRICES[".com"].transferMxnCents);
    assert.equal(com.transferUsdCents, TLD_PRICES[".com"].transferUsdCents);
    assert.equal(com.renewMxnCents, TLD_PRICES[".com"].renewMxnCents);
    assert.equal(consultas.length, 0, "la tabla curada no debe ir a AWS");
  });

  it("acepta el TLD curado con punto y en mayúsculas", async () => {
    const sinPunto = await mod.precioDeTransferencia("com");
    const gritando = await mod.precioDeTransferencia(".COM");

    assert.equal(sinPunto.curado, true);
    assert.equal(gritando.curado, true);
    assert.equal(sinPunto.transferMxnCents, gritando.transferMxnCents);
    assert.equal(consultas.length, 0);
  });

  it("un TLD fuera de la tabla se cotiza con el precio vivo de AWS", async () => {
    // 64 USD × 20 = 1280 MXN; 1.2× = 1536 gana al piso (1340) → 1536 → 153.9 → 1539 MXN = 153900.
    respuestaAws = () => ({ transferUsdCents: 6400, renewUsdCents: 6400 });

    const r = await mod.precioDeTransferencia(".pruebacaro");

    assert.equal(r.curado, false);
    assert.equal(r.tld, ".pruebacaro");
    assert.equal(r.transferUsdCents, 6400);
    assert.equal(r.transferMxnCents, 153900);
    assert.equal(consultas.length, 1);
  });

  it("con costo chico manda el piso de 60 MXN, no el margen", async () => {
    // 6.30 USD × 20 = 126 MXN; 1.2× = 151.2 pierde contra 126 + 60 = 186 → 18.6 → 189 MXN.
    // El piso existe porque a 1.2× un TLD de $3 USD deja menos que la comisión de MercadoPago.
    respuestaAws = () => ({ transferUsdCents: 630, renewUsdCents: 630 });

    const r = await mod.precioDeTransferencia(".pruebabarato");

    assert.equal(r.transferMxnCents, 18900);
  });

  it("con costo grande manda el margen de 1.2×", async () => {
    // 51 USD × 20 = 1020 MXN; 1.2× = 1224 gana al piso (1080) → 122.4 → 1229 MXN.
    respuestaAws = () => ({ transferUsdCents: 5100, renewUsdCents: 5100 });

    const r = await mod.precioDeTransferencia(".pruebagrande");

    assert.equal(r.transferMxnCents, 122900);
    // El cruce está en 300 MXN de costo (aquí el piso son 1080): a partir de ahí gana el margen.
    assert.ok(r.transferMxnCents > 108000, "se quedó por debajo del piso");
  });

  it("los dos lados del cruce margen/piso", async () => {
    // El cruce es costo = 300 MXN (usdCents = 1500): abajo gana +60, arriba gana ×1.2.
    // Los dos costos se eligen para que el precio NO caiga exacto en una decena: cuando cae,
    // entra el bug del redondeo y la prueba fijaría el defecto como esperado (ver los `todo`).
    respuestaAws = () => ({ transferUsdCents: 1040, renewUsdCents: 1040 });   // 208 MXN de costo
    const chico = await mod.precioDeTransferencia(".pruebacrucebajo");
    // 208 × 1.2 = 249.6 pierde contra 208 + 60 = 268 → 26.8 → 269 MXN.
    assert.equal(chico.transferMxnCents, 26900);

    respuestaAws = () => ({ transferUsdCents: 2100, renewUsdCents: 2100 });   // 420 MXN de costo
    const grande = await mod.precioDeTransferencia(".pruebacrucealto");
    // 420 × 1.2 = 504 manda sobre 480 → 50.4 → 509 MXN.
    assert.equal(grande.transferMxnCents, 50900);
    assert.ok(grande.transferMxnCents > 48000, "el margen quedó por debajo del piso");
  });

  it("redondea hacia arriba a decenas menos uno", async () => {
    // 12.34 USD × 20 = 246.8 MXN; 1.2× = 296.16 pierde contra 306.8 → 30.68 → 31 → 309 MXN.
    respuestaAws = () => ({ transferUsdCents: 1234, renewUsdCents: 1234 });

    const r = await mod.precioDeTransferencia(".pruebaredondeo");

    assert.equal(r.transferMxnCents, 30900);
    assert.ok(r.transferMxnCents > 30680, "redondeó hacia abajo del precio calculado");
  });

  it("nunca vende por debajo del piso de 60 MXN", { todo: "bug conocido: cuando el precio calculado cae exacto en una decena, el -1 del redondeo lo baja 1 MXN del piso (costo $200 → 259 MXN en vez de 260)" }, async () => {
    // 10 USD × 20 = 200 MXN; el piso manda: 200 + 60 = 260 MXN.
    respuestaAws = () => ({ transferUsdCents: 1000, renewUsdCents: 1000 });

    const r = await mod.precioDeTransferencia(".pruebapisonexacto");

    // Hoy devuelve 25900: Math.ceil(260/10)*10 - 1 = 259, un peso abajo del piso.
    assert.ok(r.transferMxnCents >= 26000, `bajó del piso: ${r.transferMxnCents}`);
  });

  it("nunca vende por debajo del margen de 1.2×", { todo: "bug conocido: 400 MXN de costo × 1.2 = 480, exacto en decena, y el -1 del redondeo lo deja en 479 MXN (misma causa que el piso)" }, async () => {
    // 20 USD × 20 = 400 MXN; el margen manda: 400 × 1.2 = 480 MXN.
    respuestaAws = () => ({ transferUsdCents: 2000, renewUsdCents: 2000 });

    const r = await mod.precioDeTransferencia(".pruebamargennexacto");

    // Hoy devuelve 47900: no pierde contra el piso (460), pero sí contra el ×1.2 prometido.
    assert.ok(r.transferMxnCents >= 48000, `bajó del margen: ${r.transferMxnCents}`);
  });

  it("la renovación cae al precio de transferencia si AWS no da uno", async () => {
    // AWS no cotiza renovación (0): se usa la transferencia, ni gratis ni null.
    respuestaAws = () => ({ transferUsdCents: 5100, renewUsdCents: 0 });

    const r = await mod.precioDeTransferencia(".pruebasinrenovacion");

    assert.equal(r.renewUsdCents, 5100);
    assert.equal(r.renewMxnCents, 122900);
    assert.equal(r.renewMxnCents, r.transferMxnCents);
  });

  it("la caché evita preguntarle a AWS dos veces el mismo TLD", async () => {
    respuestaAws = () => ({ transferUsdCents: 6400, renewUsdCents: 6400 });

    const primera = await mod.precioDeTransferencia(".pruebacache");
    const segunda = await mod.precioDeTransferencia(".pruebacache");

    assert.equal(consultas.length, 1, "la segunda llamada volvió a consultar AWS");
    assert.deepEqual(segunda, primera);
  });

  it("«.App» y «app» son el mismo TLD (y comparten caché)", async () => {
    respuestaAws = () => ({ transferUsdCents: 2000, renewUsdCents: 2000 });

    const conPunto = await mod.precioDeTransferencia(".App");
    const sinPunto = await mod.precioDeTransferencia("app");

    assert.equal(conPunto.tld, ".app");
    assert.deepEqual(sinPunto, conPunto);
    // Si no se normalizara la clave, la segunda habría vuelto a preguntar.
    assert.equal(consultas.length, 1);
  });

  it("la caché vence a las 24 h", async () => {
    const ahoraReal = Date.now;
    const t0 = Date.now();
    try {
      respuestaAws = () => ({ transferUsdCents: 6400, renewUsdCents: 6400 });
      Date.now = () => t0;

      await mod.precioDeTransferencia(".pruebacaduca");
      assert.equal(consultas.length, 1);

      Date.now = () => t0 + 24 * 3600_000 - 1;   // un milisegundo antes: sigue viva
      await mod.precioDeTransferencia(".pruebacaduca");
      assert.equal(consultas.length, 1, "venció antes de las 24 h");

      Date.now = () => t0 + 24 * 3600_000 + 1;   // ya pasó: vuelve a preguntar
      await mod.precioDeTransferencia(".pruebacaduca");
      assert.equal(consultas.length, 2, "no volvió a consultar AWS al vencer");
    } finally {
      Date.now = ahoraReal;
    }
  });

  it("un TLD que AWS no tiene se queda sin precio, y sin cachear el hueco", async () => {
    respuestaAws = () => null;

    assert.equal(await mod.precioDeTransferencia(".pruebanulo"), null);
    assert.equal(await mod.precioDeTransferencia(".pruebanulo"), null);
    // Un `null` no se guarda: la siguiente llamada vuelve a preguntar.
    assert.equal(consultas.length, 2);
  });

  it("un precio de cero es «AWS no lo ofrece», no una ganga", async () => {
    respuestaAws = () => ({ transferUsdCents: 0, renewUsdCents: 0 });

    assert.equal(await mod.precioDeTransferencia(".pruebacerogratis"), null);
    // Cero SÍ queda en caché (se guarda antes de descartarlo): la segunda no va a AWS.
    assert.equal(await mod.precioDeTransferencia(".pruebacerogratis"), null);
    assert.equal(consultas.length, 1);
  });

  it("si AWS falla, la transferencia se queda sin precio y no se cachea", async () => {
    respuestaAws = () => { throw new Error("AWS caído"); };

    assert.equal(await mod.precioDeTransferencia(".pruebaexcepcion"), null);
    assert.equal(await mod.precioDeTransferencia(".pruebaexcepcion"), null);
    // La excepción se descarta con un aviso, pero no se guarda: el siguiente intento reintenta.
    assert.equal(consultas.length, 2);
  });
});
