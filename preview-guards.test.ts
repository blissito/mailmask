// Los guardas de preview no viven en las rutas sino dentro de los clientes de AWS, y eso es
// a propósito: `getSesOutbound()` y `getRoute53Domains()` son la única puerta por la que
// pasan `emails.ts`, dmarc, `sendAlert` y `main.ts`, así que no hay caller nuevo que se
// cuele. Aquí se prueba esa puerta, con PREVIEW=1 y sin él.
//
// MercadoPago no usa el SDK de AWS (va por `fetch` y por su propio paquete), así que sus
// guardas son llamadas a `assertNoPreview` en las rutas: sus pruebas van por HTTP, en
// `preview-mp.test.ts`.

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";

import { PreviewDeshabilitado } from "./preview.ts";

const original = process.env.PREVIEW;

describe("guardas de preview: SES", () => {
  afterEach(() => {
    if (original === undefined) delete process.env.PREVIEW;
    else process.env.PREVIEW = original;
  });

  it("con PREVIEW=1 no se entrega el cliente de SES", async () => {
    process.env.PREVIEW = "1";
    const ses = await import("./ses.ts");
    await assert.rejects(ses.getSesOutbound(), (err: unknown) => err instanceof PreviewDeshabilitado);
    await assert.rejects(ses.getSesInbound(), (err: unknown) => err instanceof PreviewDeshabilitado);
  });

  it("con PREVIEW=1 un envío no sale: sendFromDomain lanza antes de tocar la red", async () => {
    process.env.PREVIEW = "1";
    const { sendFromDomain } = await import("./ses.ts");
    await assert.rejects(
      sendFromDomain("hola@dominio.test", "alguien@example.com", "Asunto", "Cuerpo"),
      (err: unknown) => {
        assert.ok(err instanceof PreviewDeshabilitado);
        assert.match(err.message, /deshabilitado en preview/);
        return true;
      },
    );
  });

  it("sin PREVIEW, el cliente de SES se construye", async () => {
    delete process.env.PREVIEW;
    const ses = await import("./ses.ts");
    assert.ok(await ses.getSesOutbound(), "sin PREVIEW el cliente existe");
  });
});

describe("guardas de preview: Route 53 Domains", () => {
  afterEach(() => {
    if (original === undefined) delete process.env.PREVIEW;
    else process.env.PREVIEW = original;
  });

  it("con PREVIEW=1 no se registra, ni transfiere, ni renueva un dominio", async () => {
    process.env.PREVIEW = "1";
    const r53 = await import("./route53.ts");
    await assert.rejects(r53.registerDomain("ejemplo.test"), (err: unknown) => err instanceof PreviewDeshabilitado);
    await assert.rejects(r53.transferDomain("ejemplo.test", "codigo-epp"), (err: unknown) => err instanceof PreviewDeshabilitado);
    await assert.rejects(r53.renewDomain("ejemplo.test", 2026), (err: unknown) => err instanceof PreviewDeshabilitado);
  });

  it("sin PREVIEW el guarda no interviene: el registro avanza hasta los datos del WHOIS", async () => {
    delete process.env.PREVIEW;
    const r53 = await import("./route53.ts");
    await assert.rejects(r53.registerDomain("ejemplo.test"), (err: unknown) => {
      assert.ok(!(err instanceof PreviewDeshabilitado), "sin PREVIEW la compuerta no es la que corta");
      return true;
    });
  });
});
