// GET /api/fx: el tipo de cambio que /pricing muestra en dólares. Lee la última lectura
// (`ultimaLectura`), no el máximo de 30 días con el que se cotiza (`tipoDeCambio`): un precio
// en pantalla no se cobra, así que no necesita el peor caso. Ficha: docs/agents/precios-usd.md
import { test, mock, before } from "node:test";
import assert from "node:assert/strict";

type Lectura = { rate: number; fetchedAt: string; source: string };
let lectura: Lectura | null = null;
// deno-lint-ignore no-explicit-any
let app: any;

before(async () => {
  const real = await import("./fx.ts");
  mock.module("./fx.ts", {
    namedExports: {
      ...real,
      ultimaLectura: () => lectura,
      // Si la ruta cotizara con el máximo, devolvería 99: no debe hacerlo.
      tipoDeCambio: () => 99,
    },
  });
  ({ app } = await import("./main.ts"));
});

const pedir = () => app.handle(new Request("http://localhost/api/fx"));

test("devuelve la última lectura y no el tipo con el que se cotiza", async () => {
  lectura = { rate: 17.4, fetchedAt: "2026-10-22T10:00:00.000Z", source: "open.er-api.com" };
  const res = await pedir();
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { rate: 17.4, fetchedAt: "2026-10-22T10:00:00.000Z" });
});

test("se puede cachear una hora", async () => {
  lectura = { rate: 17.4, fetchedAt: "2026-10-22T10:00:00.000Z", source: "open.er-api.com" };
  const res = await pedir();
  assert.equal(res.headers.get("cache-control"), "public, max-age=3600");
});

test("sin ninguna lectura responde 404 para que la página se quede en MXN", async () => {
  lectura = null;
  const res = await pedir();
  // Una ruta inexistente también da 404: el cuerpo es lo que demuestra que la ruta existe.
  assert.equal(res.status, 404);
  assert.deepEqual(await res.json(), { error: "sin tipo de cambio" });
});
