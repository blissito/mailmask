import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { encodeHeader, normalizeAddress } from "./ses.ts";

describe("encodeHeader (RFC 2047)", () => {
  it("deja pasar ASCII sin tocar", () => {
    assert.equal(encodeHeader("Hello world"), "Hello world");
  });

  it("codifica acentos", () => {
    const out = encodeHeader("Cotización");
    assert.match(out, /^=\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=$/);
    const b64 = out.slice("=?UTF-8?B?".length, -2);
    assert.equal(Buffer.from(b64, "base64").toString("utf8"), "Cotización");
  });

  it("codifica emoji", () => {
    const out = encodeHeader("Gracias 🎉");
    const b64 = out.slice("=?UTF-8?B?".length, -2);
    assert.equal(Buffer.from(b64, "base64").toString("utf8"), "Gracias 🎉");
  });

  it("no re-codifica lo que ya viene encoded", () => {
    const already = "=?UTF-8?B?Q290aXphY2nDs24=?=";
    assert.equal(encodeHeader(already), already);
  });

  it("vacío se queda vacío", () => {
    assert.equal(encodeHeader(""), "");
  });
});

// La inyección de headers permitía colar un Bcc: desde el asunto.
describe("encodeHeader — inyección de headers", () => {
  it("elimina CRLF de un asunto ASCII", () => {
    const out = encodeHeader("Hola\r\nBcc: victima@evil.com");
    assert.ok(!out.includes("\r"), "no debe quedar CR");
    assert.ok(!out.includes("\n"), "no debe quedar LF");
    assert.equal(out, "Hola Bcc: victima@evil.com");
  });

  it("un asunto con acentos y CRLF queda encoded en una sola línea", () => {
    const out = encodeHeader("Cotización\nBcc: victima@evil.com");
    assert.ok(!/[\r\n]/.test(out));
    assert.match(out, /^=\?UTF-8\?B\?/);
  });

  it("elimina LF suelto", () => {
    assert.ok(!/[\r\n]/.test(encodeHeader("a\nb")));
  });
});

describe("normalizeAddress", () => {
  it("extrae la dirección de un display name", () => {
    assert.equal(normalizeAddress("Brenda Pérez <brenda@example.com>"), "brenda@example.com");
  });

  it("deja una dirección pelada igual", () => {
    assert.equal(normalizeAddress("brenda@example.com"), "brenda@example.com");
  });

  it("normaliza a minúsculas para que matchee la lista de supresión", () => {
    assert.equal(normalizeAddress("Brenda@Example.COM"), "brenda@example.com");
  });

  it("elimina CRLF", () => {
    assert.ok(!/[\r\n]/.test(normalizeAddress("a@b.com\r\nBcc: x@y.com")));
  });

  it("recorta espacios", () => {
    assert.equal(normalizeAddress("  brenda@example.com  "), "brenda@example.com");
  });
});
