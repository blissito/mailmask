// El MIME de un correo con imágenes incrustadas. Se prueba contra el mensaje crudo
// que se le entrega a SES porque es lo único que el destinatario ve de verdad: un
// `multipart/related` mal armado se manda sin error y llega roto.

import { describe, it, before, mock } from "node:test";
import assert from "node:assert/strict";

const enviados: string[] = [];
const destinatarios: string[][] = [];

describe("sendFromDomain con imágenes incrustadas", () => {
  // deno-lint-ignore no-explicit-any
  let sendFromDomain: any;

  before(async () => {
    // Se sustituye el SDK de AWS y no ses.ts: el cliente se crea de forma perezosa
    // dentro del módulo y no hay forma de alcanzarlo desde fuera. Así el mensaje
    // crudo se captura tal como se le entregaría a SES.
    mock.module("@aws-sdk/client-ses", {
      namedExports: {
        SESClient: class {
          // deno-lint-ignore no-explicit-any
          async send(cmd: any) {
            enviados.push(new TextDecoder().decode(cmd.RawMessage.Data));
            destinatarios.push(cmd.Destinations);
            return {};
          }
        },
        // deno-lint-ignore no-explicit-any
        SendRawEmailCommand: class { constructor(public input: any) { Object.assign(this, input); } },
      },
    });
    ({ sendFromDomain } = await import("./ses.ts"));
  });

  const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

  it("envuelve el alternative en un related y adjunta la imagen", async () => {
    await sendFromDomain("hola@dominio.com", "cliente@example.com", "Con foto", "texto plano", {
      html: '<p><img src="cid:abc.png" alt="foto" /></p>',
      inlineImages: [{ cid: "abc.png", contentType: "image/png", data: png, filename: "abc.png" }],
    });
    const raw = enviados[enviados.length - 1];

    assert.match(raw, /Content-Type: multipart\/related; type="multipart\/alternative"/);
    assert.match(raw, /Content-Type: multipart\/alternative/);
    // El Content-ID va entre ángulos; el HTML lo referencia sin ellos.
    assert.match(raw, /Content-ID: <abc\.png>/);
    assert.match(raw, /Content-Disposition: inline; filename="abc\.png"/);
    assert.match(raw, /Content-Type: image\/png/);
    // Las dos partes de texto siguen ahí: quitarlas rompería a quien lee en texto.
    assert.match(raw, /Content-Type: text\/plain; charset=UTF-8/);
    assert.match(raw, /Content-Type: text\/html; charset=UTF-8/);
  });

  it("sin imágenes conserva la estructura de siempre", async () => {
    await sendFromDomain("hola@dominio.com", "cliente@example.com", "Sin foto", "texto", {
      html: "<p>hola</p>",
    });
    const raw = enviados[enviados.length - 1];
    assert.match(raw, /Content-Type: multipart\/alternative/);
    assert.ok(!/multipart\/related/.test(raw), "no debe envolverse si no hay imágenes");
  });

  it("los adjuntos envuelven todo en multipart/mixed", async () => {
    await sendFromDomain("hola@dominio.com", "cliente@example.com", "Con PDF", "texto", {
      html: "<p>hola</p>",
      attachments: [{ filename: "cotización.pdf", contentType: "application/pdf", data: png }],
    });
    const raw = enviados[enviados.length - 1];
    assert.match(raw, /Content-Type: multipart\/mixed/);
    assert.match(raw, /Content-Type: application\/pdf/);
    assert.match(raw, /Content-Disposition: attachment/);
    // El nombre con tilde va codificado RFC 2047, si no llega roto.
    assert.match(raw, /filename="=\?UTF-8\?B\?/);
  });

  it("mixed y related conviven cuando hay adjunto e imagen", async () => {
    await sendFromDomain("hola@dominio.com", "cliente@example.com", "Ambos", "texto", {
      html: '<img src="cid:a.png" alt="a" />',
      inlineImages: [{ cid: "a.png", contentType: "image/png", data: png }],
      attachments: [{ filename: "doc.pdf", contentType: "application/pdf", data: png }],
    });
    const raw = enviados[enviados.length - 1];
    assert.match(raw, /Content-Type: multipart\/mixed/);
    assert.match(raw, /Content-Type: multipart\/related/);
    assert.match(raw, /Content-Type: multipart\/alternative/);
    assert.match(raw, /Content-ID: <a\.png>/);
  });

  it("sin adjuntos no envuelve en mixed: un mixed vacío hace aparecer un clip falso", async () => {
    await sendFromDomain("hola@dominio.com", "cliente@example.com", "Simple", "texto", { html: "<p>x</p>" });
    const raw = enviados[enviados.length - 1];
    assert.ok(!/multipart\/mixed/.test(raw));
    assert.ok(!/multipart\/related/.test(raw));
  });

  it("Cc va en los headers; Bcc NO, pero ambos reciben", async () => {
    await sendFromDomain("hola@dominio.com", "cliente@example.com", "Copias", "texto", {
      html: "<p>x</p>",
      cc: ["jefe@example.com"],
      bcc: ["oculto@example.com"],
    });
    const raw = enviados[enviados.length - 1];
    assert.match(raw, /^Cc: jefe@example\.com$/m);
    // Si el Bcc apareciera aquí, dejaría de ser oculto: es el fallo clásico.
    assert.ok(!/oculto@example\.com/.test(raw), "el Bcc no puede ir en el mensaje");
    assert.deepEqual(destinatarios[destinatarios.length - 1], [
      "cliente@example.com", "jefe@example.com", "oculto@example.com",
    ]);
  });

  it("rechaza el correo que excede el tope de SES en vez de dejar que falle allá", async () => {
    // SendRawEmail topa en 10 MB y base64 infla ~33%.
    const enorme = new Uint8Array(9 * 1024 * 1024);
    await assert.rejects(
      () =>
        sendFromDomain("hola@dominio.com", "cliente@example.com", "Pesado", "texto", {
          html: '<img src="cid:x.png" alt="x" />',
          inlineImages: [{ cid: "x.png", contentType: "image/png", data: enorme }],
        }),
      /tamaño máximo/,
    );
  });
});
