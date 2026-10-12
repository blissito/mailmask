// Modo preview: el interruptor y las compuertas.
//
// Lo que se fija aquí es que `PREVIEW=1` signifique exactamente "este proceso no toca AWS ni
// cobra", y que sin la variable nada cambie. Lo que los guardas cortan de verdad se prueba
// en `preview-guards.test.ts`; el arranque completo, en `preview-boot.test.ts`.

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";

import {
  PreviewDeshabilitado,
  assertNoPreview,
  debeArrancarEfectos,
  debeProgramar,
  esPreview,
} from "./preview.ts";

const original = process.env.PREVIEW;

describe("modo preview: el interruptor", () => {
  afterEach(() => {
    if (original === undefined) delete process.env.PREVIEW;
    else process.env.PREVIEW = original;
  });

  it("sólo PREVIEW=1 lo enciende", () => {
    delete process.env.PREVIEW;
    assert.equal(esPreview(), false, "sin la variable no hay preview");
    process.env.PREVIEW = "0";
    assert.equal(esPreview(), false, "PREVIEW=0 no es preview");
    process.env.PREVIEW = "true";
    assert.equal(esPreview(), false, "sólo el 1 enciende el modo: un 'true' de más no lo activa");
    process.env.PREVIEW = "1";
    assert.equal(esPreview(), true);
  });

  it("sin PREVIEW, assertNoPreview deja pasar", () => {
    delete process.env.PREVIEW;
    assert.doesNotThrow(() => assertNoPreview("ses"));
  });

  it("en preview, assertNoPreview lanza con el servicio y el motivo en el mensaje", () => {
    process.env.PREVIEW = "1";
    assert.throws(
      () => assertNoPreview("mercadopago"),
      (err: unknown) => {
        assert.ok(err instanceof PreviewDeshabilitado, "lanza PreviewDeshabilitado");
        assert.equal(err.servicio, "mercadopago");
        assert.match(err.message, /deshabilitado en preview/);
        return true;
      },
    );
  });
});

describe("modo preview: las funciones puras", () => {
  it("debeProgramar: sólo el servidor, nunca en preview", () => {
    assert.equal(debeProgramar(true, false), true);
    assert.equal(debeProgramar(true, true), false, "una preview no programa crons");
    assert.equal(debeProgramar(false, false), false);
    assert.equal(debeProgramar(false, true), false);
  });

  it("debeArrancarEfectos: los arranques con efectos no corren en preview", () => {
    assert.equal(debeArrancarEfectos(true, false), true);
    assert.equal(debeArrancarEfectos(true, true), false, "una preview no repara SES/SNS ni backfillea");
    assert.equal(debeArrancarEfectos(false, false), false);
    assert.equal(debeArrancarEfectos(false, true), false);
  });
});
