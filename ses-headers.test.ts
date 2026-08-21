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

describe("encodeHeader — asuntos largos y passthrough", () => {
  it("parte un asunto largo en varios encoded-words plegados", () => {
    const long = "Cotización " + "á".repeat(300);
    const out = encodeHeader(long);
    for (const line of out.split("\r\n")) {
      // RFC 5322 topa la línea en 998; cada encoded-word en 75.
      assert.ok(line.trim().length <= 78, `línea de ${line.trim().length} chars: ${line.slice(0, 40)}`);
    }
    // El plegado usa CRLF + espacio, que es continuación válida, no inyección.
    for (const cont of out.split("\r\n").slice(1)) {
      assert.ok(cont.startsWith(" "), "cada continuación debe empezar con espacio");
    }
    const decoded = out.split(/\r\n\s+/)
      .map((w) => Buffer.from(w.slice("=?UTF-8?B?".length, -2), "base64").toString("utf8"))
      .join("");
    assert.equal(decoded, long, "debe poder reconstruirse igual");
  });

  it("no deja pasar bytes crudos pegados a un encoded-word", () => {
    // Antes bastaba con que el valor EMPEZARA con =? para devolverlo tal cual.
    const mixed = "=?UTF-8?Q?Pedido?= confirmado señor";
    const out = encodeHeader(mixed);
    // deno-lint-ignore no-control-regex
    assert.ok(!/[^\x00-\x7F]/.test(out), "no deben quedar bytes no-ASCII en el header");
  });

  it("sí deja pasar una cadena que es toda encoded-words", () => {
    const already = "=?UTF-8?B?Q290aXphY2nDs24=?= =?UTF-8?B?Q290aXphY2nDs24=?=";
    assert.equal(encodeHeader(already), already);
  });
});

// Regresión: `ALERT_FROM_EMAIL` en producción venía como "MailMask <noreply@...>",
// FROM_HEADER lo volvía a envolver y `normalizeAddress` devolvía "mailmask <noreply@..."
// sin cerrar. SES contestaba InvalidParameterValue "Missing '>'" y todo correo de
// plantilla —verificación de cuenta incluida— devolvía 500.
describe("normalizeAddress con display name anidado", () => {
  it("saca la dirección del grupo más interno", () => {
    assert.equal(
      normalizeAddress("MailMask <MailMask <noreply@mailmask.studio>>"),
      "noreply@mailmask.studio",
    );
  });

  it("sigue funcionando con un solo nivel y con dirección pelada", () => {
    assert.equal(normalizeAddress("MailMask <noreply@mailmask.studio>"), "noreply@mailmask.studio");
    assert.equal(normalizeAddress("noreply@mailmask.studio"), "noreply@mailmask.studio");
  });
});

describe("FROM_HEADER", () => {
  it("no envuelve dos veces si ALERT_FROM ya trae display name", async () => {
    const anterior = process.env.ALERT_FROM_EMAIL;
    process.env.ALERT_FROM_EMAIL = "MailMask <noreply@mailmask.studio>";
    const mod = await import(`./emails.ts?from-header-${Date.now()}`);
    assert.equal(mod.FROM_HEADER, "MailMask <noreply@mailmask.studio>");
    assert.equal(normalizeAddress(mod.FROM_HEADER), "noreply@mailmask.studio");
    if (anterior === undefined) delete process.env.ALERT_FROM_EMAIL;
    else process.env.ALERT_FROM_EMAIL = anterior;
  });

  it("envuelve una dirección pelada", async () => {
    const anterior = process.env.ALERT_FROM_EMAIL;
    process.env.ALERT_FROM_EMAIL = "noreply@mailmask.studio";
    const mod = await import(`./emails.ts?bare-${Date.now()}`);
    assert.equal(mod.FROM_HEADER, "MailMask <noreply@mailmask.studio>");
    if (anterior === undefined) delete process.env.ALERT_FROM_EMAIL;
    else process.env.ALERT_FROM_EMAIL = anterior;
  });
});
