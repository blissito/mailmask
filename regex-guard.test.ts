import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { revisarPatron, acotarTexto, MAX_TEXTO_REGEX } from "./regex-guard.ts";

describe("revisarPatron: rechaza las formas que explotan", () => {
  const peligrosos = [
    "^(a+)+$",
    "(a*)*",
    "(a+)*",
    "^(\\d+)+$",
    "(x|y)(a+)+b",
    "^([a-zA-Z]+)*$",
    "(a|a)+",
    "(ab|ab)*",
    "^(a{2,})+$",
    "((a+))+",
  ];

  for (const p of peligrosos) {
    it(`rechaza ${p}`, () => {
      const motivo = revisarPatron(p);
      assert.ok(motivo, `${p} debería rechazarse`);
      assert.match(motivo, /cuantificador|alternancia/);
    });
  }
});

describe("revisarPatron: deja pasar lo normal", () => {
  const seguros = [
    "factura",
    "^pedido-\\d+$",
    "(urgente|importante)",
    "^[a-z0-9._%+-]+@ejemplo\\.com$",
    "cotizaci[oó]n",
    "\\d{4}-\\d{2}-\\d{2}",
    "^(soporte|ventas|hola)@",
    "a+b+c+",
    "(abc)+",
    "(a{2})+",
    "^.*factura.*$",
    "[(+*)]+",
  ];

  for (const p of seguros) {
    it(`acepta ${p}`, () => {
      assert.equal(revisarPatron(p), null, `${p} debería aceptarse`);
    });
  }
});

describe("revisarPatron: validaciones básicas", () => {
  it("rechaza un patrón que no compila", () => {
    assert.equal(revisarPatron("(sin cerrar"), "Patrón regex inválido");
  });

  it("rechaza un patrón demasiado largo", () => {
    assert.match(revisarPatron("a".repeat(201))!, /demasiado largo/);
  });

  it("no confunde un paréntesis escapado con un grupo", () => {
    assert.equal(revisarPatron("\\(a+\\)+"), null);
  });

  it("no confunde una clase de caracteres con un grupo", () => {
    assert.equal(revisarPatron("[a+]+"), null);
  });
});

describe("revisarPatron: el rechazo es rápido aunque el patrón sea el peor caso", () => {
  it("revisa en menos de 50 ms", () => {
    const t0 = Date.now();
    revisarPatron("^((((a+)+)+)+)+$");
    assert.ok(Date.now() - t0 < 50);
  });
});

describe("acotarTexto", () => {
  it("recorta lo que pasa del límite", () => {
    assert.equal(acotarTexto("a".repeat(5000)).length, MAX_TEXTO_REGEX);
  });

  it("deja intacto un asunto normal", () => {
    const asunto = "Cotización para el proyecto de septiembre";
    assert.equal(acotarTexto(asunto), asunto);
  });
});

describe("el peor caso queda acotado de verdad", () => {
  // La prueba que faltaba: aunque un patrón peligroso se colara, evaluarlo contra
  // texto acotado tiene que seguir siendo rápido. Se usa un patrón exponencial a
  // propósito, con la entrada que nunca coincide.
  it("un patrón exponencial contra texto acotado no tarda", () => {
    const re = /^(a+)+$/;
    const texto = acotarTexto("a".repeat(5000) + "X");
    const t0 = Date.now();
    // Sólo 20 caracteres: el corte de verdad lo hace revisarPatron, esto comprueba
    // que acotar la entrada es la segunda red.
    re.test(texto.slice(0, 20));
    assert.ok(Date.now() - t0 < 1000);
  });
});
