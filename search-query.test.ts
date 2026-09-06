import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { sanitizarConsultaFts, escaparLike } from "./search-query.ts";

describe("sanitizarConsultaFts: neutraliza la sintaxis de FTS5", () => {
  // Cada uno de estos revienta un MATCH sin sanitizar.
  const venenosos = [
    'comillas "sueltas',
    "asterisco * suelto",
    "NEAR(a b)",
    "a:b",
    "-excluido",
    "(parentesis)",
    "AND OR NOT",
    "^ancla",
    'frase "entre comillas" completa',
    "col^umna",
  ];

  for (const entrada of venenosos) {
    it(`no deja sintaxis cruda en: ${entrada}`, () => {
      const salida = sanitizarConsultaFts(entrada);
      if (salida === null) return;
      // Sólo pueden quedar comillas dobles envolviendo tokens, espacios y el * final.
      assert.match(salida, /^("[\p{L}\p{N}_]+" )*"[\p{L}\p{N}_]+"\*$/u, salida);
    });
  }

  it("devuelve null cuando no queda nada buscable", () => {
    assert.equal(sanitizarConsultaFts(""), null);
    assert.equal(sanitizarConsultaFts("   "), null);
    assert.equal(sanitizarConsultaFts("*-:()^"), null);
    assert.equal(sanitizarConsultaFts("!!!"), null);
  });

  it("no truena con entrada que no es texto", () => {
    assert.equal(sanitizarConsultaFts(undefined as unknown as string), null);
    assert.equal(sanitizarConsultaFts(null as unknown as string), null);
  });

  it("pone el comodín sólo en el último token", () => {
    assert.equal(sanitizarConsultaFts("factura pendiente"), '"factura" "pendiente"*');
    assert.equal(sanitizarConsultaFts("hola"), '"hola"*');
  });

  it("conserva los acentos: el filtrado de diacríticos es cosa del tokenizer", () => {
    assert.equal(sanitizarConsultaFts("información"), '"información"*');
  });

  it("acota el número de tokens y el largo de la entrada", () => {
    const salida = sanitizarConsultaFts(Array.from({ length: 50 }, (_, i) => `t${i}`).join(" "));
    assert.equal(salida!.split(" ").length, 10);
    assert.doesNotThrow(() => sanitizarConsultaFts("a".repeat(5000)));
  });

  it("sobrevive a emoji y a texto sin letras latinas", () => {
    assert.equal(sanitizarConsultaFts("🎉🎉"), null);
    assert.equal(sanitizarConsultaFts("pago 🎉 recibido"), '"pago" "recibido"*');
  });
});

describe("escaparLike", () => {
  it("escapa los comodines de LIKE", () => {
    assert.equal(escaparLike("100%_x"), "100\\%\\_x");
    assert.equal(escaparLike("normal"), "normal");
  });
});
