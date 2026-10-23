import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { decodeEncodedWords } from "./forwarding.ts";

describe("decodeEncodedWords", () => {
  it("decodifica Q y B, y deja el texto normal igual", () => {
    assert.equal(decodeEncodedWords("=?UTF-8?Q?H=C3=A9ctor_BlisS?= <fixtergeek@gmail.com>"), "Héctor BlisS <fixtergeek@gmail.com>");
    assert.equal(decodeEncodedWords("=?utf-8?B?wqFIb2xhIG11bmRvIQ==?="), "¡Hola mundo!");
    assert.equal(decodeEncodedWords("Prueba normal"), "Prueba normal");
  });
  it("une palabras codificadas seguidas sin el espacio de en medio", () => {
    assert.equal(decodeEncodedWords("=?UTF-8?Q?Ma=C3=B1ana?= =?UTF-8?Q?_s=C3=AD?="), "Mañana sí");
  });
});
