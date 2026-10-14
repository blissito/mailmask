// Funciones puras que no tenían prueba propia: `stripHeaders` (quita las firmas DKIM tras
// reescribir el From) y los ayudantes de nombres de Route 53 que deciden si una hosted zone
// ya existe. Un error en `stripHeaders` rompe el reenvío o mutila el cuerpo; un error en
// `normalizeZoneName` hace que se cree una segunda zona para el mismo dominio.

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { stripHeaders } from "./ses.ts";
import { unescapeRecordName, normalizeZoneName } from "./route53.ts";

describe("stripHeaders", () => {
  it("quita un DKIM-Signature plegado entero y deja el cuerpo byte a byte igual", () => {
    const raw =
      "From: ana@origen.com\r\n" +
      "DKIM-Signature: v=1; a=rsa-sha256; d=origen.com;\r\n" +
      " s=sel1; h=from:subject;\r\n" +
      "\tb=AbC123==\r\n" +
      "Subject: hola\r\n" +
      "\r\n" +
      "Cuerpo\r\nlínea 2\r\n";
    const esperado =
      "From: ana@origen.com\r\n" +
      "Subject: hola\r\n" +
      "\r\n" +
      "Cuerpo\r\nlínea 2\r\n";
    assert.equal(stripHeaders(raw, ["DKIM-Signature"]), esperado);
  });

  it("quita el encabezado aunque venga en minúsculas", () => {
    const raw = "From: ana@origen.com\r\ndkim-signature: v=1; b=xyz\r\nSubject: hola\r\n\r\ncuerpo";
    assert.equal(
      stripHeaders(raw, ["DKIM-Signature"]),
      "From: ana@origen.com\r\nSubject: hola\r\n\r\ncuerpo",
    );
  });

  it("no toca un renglón DKIM-Signature que vive dentro del cuerpo", () => {
    const raw = "From: ana@origen.com\r\nSubject: x\r\n\r\nDKIM-Signature: esto es texto del cuerpo\r\nmás";
    assert.equal(stripHeaders(raw, ["DKIM-Signature"]), raw);
  });

  it("quita varios encabezados en una sola llamada", () => {
    const raw =
      "DKIM-Signature: v=1; b=a\r\n" +
      "ARC-Seal: i=1; cv=none\r\n" +
      "From: ana@origen.com\r\n" +
      "\r\n" +
      "cuerpo";
    assert.equal(
      stripHeaders(raw, ["DKIM-Signature", "ARC-Seal"]),
      "From: ana@origen.com\r\n\r\ncuerpo",
    );
  });

  it("conserva X-DKIM-Signature-Foo y DKIM-Signature-Foo: el prefijo incluye los dos puntos", () => {
    const raw =
      "X-DKIM-Signature-Foo: a\r\n" +
      "DKIM-Signature-Foo: b\r\n" +
      "From: ana@origen.com\r\n" +
      "\r\n" +
      "cuerpo";
    assert.equal(stripHeaders(raw, ["DKIM-Signature"]), raw);
  });

  it("un mensaje sólo con encabezados (sin línea en blanco) sale sin el encabezado y sin cuerpo agregado", () => {
    const raw = "From: ana@origen.com\r\nDKIM-Signature: v=1; b=a";
    assert.equal(stripHeaders(raw, ["DKIM-Signature"]), "From: ana@origen.com");
  });

  it("con entrada de \\n fija el comportamiento actual: el bloque de encabezados sale con \\r\\n y el separador y el cuerpo quedan como venían", () => {
    // No es un comportamiento deseado: sólo se fija para que un cambio se note. Si parece un
    // bug, se abre un issue aparte; no se corrige en este pedido.
    const raw = "From: ana@origen.com\nDKIM-Signature: v=1; b=a\nSubject: hola\n\ncuerpo";
    assert.equal(
      stripHeaders(raw, ["DKIM-Signature"]),
      "From: ana@origen.com\r\nSubject: hola\n\ncuerpo",
    );
  });
});

describe("unescapeRecordName", () => {
  it("convierte el escape octal de Route 53 (\\052 = *) y conserva el punto final", () => {
    assert.equal(unescapeRecordName("\\052.ejemplo.com."), "*.ejemplo.com.");
  });

  it("un nombre sin escapes pasa igual", () => {
    assert.equal(unescapeRecordName("ejemplo.com."), "ejemplo.com.");
  });
});

describe("normalizeZoneName", () => {
  it("desescapa, quita el punto final y baja a minúsculas", () => {
    assert.equal(normalizeZoneName("\\052.Ejemplo.COM."), "*.ejemplo.com");
  });

  it("un nombre sin escapes ni mayúsculas sólo pierde el punto final", () => {
    assert.equal(normalizeZoneName("ejemplo.com."), "ejemplo.com");
  });
});
