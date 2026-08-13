import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  TEMPLATE_FIXTURES,
  escHtml,
  money,
  shortDate,
  paymentConfirmation,
  chargeFailed,
  courtesyGranted,
  mesaInvite,
  expiryWarning,
} from "./emails.ts";

const NAMES = Object.keys(TEMPLATE_FIXTURES);

describe("Correos: contrato de toda plantilla", () => {
  for (const name of NAMES) {
    it(`${name} devuelve asunto, texto y html no vacíos`, () => {
      const e = TEMPLATE_FIXTURES[name]();
      assert.ok(e.subject.length > 0, "asunto");
      assert.ok(e.text.trim().length > 0, "texto");
      assert.ok(e.html.trim().length > 0, "html");
    });

    it(`${name} no mete asuntos multilínea`, () => {
      // Un \r\n aquí parte el header antes de llegar a encodeHeader.
      assert.doesNotMatch(TEMPLATE_FIXTURES[name]().subject, /[\r\n]/);
    });

    it(`${name} usa estilos inline, sin hojas de estilo ni clases`, () => {
      // Atrapa a quien pegue Tailwind: ningún cliente de correo lo va a aplicar.
      const html = TEMPLATE_FIXTURES[name]().html;
      assert.doesNotMatch(html, /<style[\s>]/i);
      assert.doesNotMatch(html, /\sclass=/i);
    });

    it(`${name} sobrevive a que bloqueen las imágenes`, () => {
      // Outlook bloquea las remotas por defecto y no hay adjuntos para inlinearlas, así
      // que toda imagen necesita texto alternativo y la marca no puede depender de ella:
      // el wordmark tiene que seguir en el HTML.
      const html = TEMPLATE_FIXTURES[name]().html;
      for (const img of html.match(/<img[^>]*>/gi) ?? []) {
        assert.match(img, /alt="[^"]+"/, `sin alt: ${img}`);
      }
      assert.ok(html.includes(">Mask<"), "el wordmark de texto sigue presente");
    });

    it(`${name} abre sus enlaces en pestaña nueva`, () => {
      // Un recibo abierto en Gmail web no debe sacar al lector de su bandeja.
      const html = TEMPLATE_FIXTURES[name]().html;
      for (const a of html.match(/<a [^>]*href="https?:[^"]*"[^>]*>/gi) ?? []) {
        assert.match(a, /target="_blank"/, `sin target: ${a}`);
        assert.match(a, /rel="noopener noreferrer"/, `sin rel: ${a}`);
      }
    });

    it(`${name} declara esquema claro`, () => {
      // Sin esto, la inversión forzada de Gmail-Android deja el correo gris sobre gris.
      assert.match(TEMPLATE_FIXTURES[name]().html, /name="color-scheme" content="light"/);
    });

    it(`${name} deja la versión de texto en pie`, () => {
      // sendFromDomain pone el texto primero en el multipart, así que tiene que
      // sostenerse solo. Si hay CTA en el html, la URL debe estar escrita completa.
      const e = TEMPLATE_FIXTURES[name]();
      const href = e.html.match(/<a href="(https?:\/\/[^"]+)"[^>]*>\s*<\/a>|display:block[^"]*"[^>]*>/);
      assert.ok(e.text.includes("MailMask"), "firma");
      if (href) {
        const url = e.html.match(/href="(https?:\/\/[^"]+)"/)?.[1];
        if (url && !url.startsWith("mailto:")) {
          assert.ok(e.text.includes("http"), "el texto trae al menos una URL completa");
        }
      }
    });
  }
});

describe("Correos: escapado", () => {
  it("escHtml neutraliza los cinco caracteres", () => {
    assert.equal(escHtml(`<a href="x">&'`), "&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
  });

  it("un dominio hostil no sobrevive al html", () => {
    // El dominio es entrada del usuario y se interpola en la invitación a Mesa.
    const malicioso = `a"><img src=x onerror=alert(1)>`;
    const e = mesaInvite({
      inviterEmail: "x@y.com", domain: malicioso, role: "agente",
      name: null, acceptUrl: "https://www.mailmask.studio/x",
    });
    // El único <img> del correo es el logo de la banda; la carga no puede agregar otro.
    const imgs = e.html.match(/<img[^>]*>/gi) ?? [];
    assert.equal(imgs.length, 1, "solo la mascarita");
    assert.ok(imgs[0].includes("logo.png"), "y es el logo, no la inyección");
    // La carga sigue apareciendo como texto plano, y eso está bien: lo que importa es
    // que no se escape del atributo ni abra una etiqueta.
    assert.ok(!e.html.includes(`"><img`), "no rompe el atributo");
    assert.ok(e.html.includes("&lt;img"), "queda escapado y visible");
  });

  it("un script en el nombre del add-on queda escapado", () => {
    const e = courtesyGranted({ addonLabel: "<script>alert(1)</script>", until: null });
    assert.ok(!e.html.includes("<script>"));
    assert.ok(e.html.includes("&lt;script&gt;"));
  });

  it("una inyección de header no llega al asunto", () => {
    const e = courtesyGranted({ addonLabel: "Dominio\r\nBcc: victima@x.com", until: null });
    assert.doesNotMatch(e.subject, /[\r\n]/);
    assert.ok(!e.subject.includes("Bcc:") || !/[\r\n]/.test(e.subject));
  });
});

describe("Correos: recibos", () => {
  const order = {
    number: "MM-2608-7F3A", amountCents: 4900, currency: "MXN",
    periodStart: "2026-08-13T00:00:00.000Z", periodEnd: "2026-09-12T00:00:00.000Z",
    mpPaymentId: "123456789", occurredAt: "2026-08-13T00:00:00.000Z",
  };

  it("el recibo trae monto, folio y periodo en ambas versiones", () => {
    // Justo lo que el correo viejo no decía.
    const e = paymentConfirmation({ plan: "basico", order, nextChargeAt: order.periodEnd });
    for (const version of [e.html, e.text]) {
      assert.ok(version.includes("49.00"), "monto");
      assert.ok(version.includes("MM-2608-7F3A"), "folio");
      assert.ok(version.includes("123456789"), "id de pago");
    }
  });

  it("dice Básico con acento", () => {
    const e = paymentConfirmation({ plan: "basico", order });
    assert.ok(e.subject.includes("Básico"));
    assert.ok(!e.subject.includes("Basico "), "no la versión sin acento");
  });

  it("hace visible el mes extra por referido", () => {
    const e = paymentConfirmation({ plan: "basico", order, nextChargeAt: order.periodEnd, referralBonusDays: 30 });
    assert.ok(e.html.includes("30 días extra"));
    assert.ok(e.text.includes("30 días extra"));
  });

  it("explica la factura sin prometer CFDI automático", () => {
    const e = paymentConfirmation({ plan: "basico", order });
    assert.ok(e.html.includes("CFDI"));
    assert.ok(e.html.includes("No es un CFDI"));
  });

  it("el cargo fallido dice la consecuencia concreta, no 'perderás el acceso'", () => {
    const e = chargeFailed({
      concept: "Plan Básico (mensual)", attemptedCents: 4900,
      accessUntil: "2026-09-02T00:00:00.000Z", reason: "Fondos insuficientes",
    });
    assert.ok(e.html.includes("dejan de reenviar correo"));
    assert.ok(e.text.includes("dejan de reenviar correo"));
    assert.ok(e.text.includes("2 de septiembre de 2026"), "la fecha hasta la que hay servicio");
  });
});

describe("Correos: cortesías", () => {
  it("dice que no se cobra, explícitamente", () => {
    const e = courtesyGranted({ addonLabel: "Dominio extra", until: "2027-12-31T00:00:00.000Z", listPriceCents: 9900 });
    assert.ok(e.html.includes("$0.00 MXN"));
    assert.ok(e.text.includes("No se te va a cobrar nada"));
  });

  it("sirve para un add-on que no existe en el catálogo", () => {
    const e = courtesyGranted({ addonLabel: "5 asientos", until: null });
    assert.ok(e.subject.includes("5 asientos"));
    assert.ok(e.html.includes("mientras tu plan esté activo"));
  });
});

describe("Correos: aviso de vencimiento", () => {
  it("con suscripción activa el tono es informativo", () => {
    // El asunto viejo asustaba a quien tenía el cobro automático en orden.
    const e = expiryWarning({ endDate: "2026-09-02T00:00:00.000Z", hasMpSubscription: true });
    assert.ok(e.subject.includes("se renueva"));
    assert.ok(!e.subject.includes("vence"));
  });

  it("sin suscripción avisa que se pierde el servicio", () => {
    const e = expiryWarning({ endDate: "2026-09-02T00:00:00.000Z", hasMpSubscription: false });
    assert.ok(e.subject.includes("vence"));
    assert.ok(e.html.includes("dejan de reenviar correo"));
  });
});

describe("Correos: formato", () => {
  it("el dinero lleva dos decimales y moneda", () => {
    assert.equal(money(4900), "$49.00 MXN");
    assert.equal(money(44900), "$449.00 MXN");
    assert.equal(money(0), "$0.00 MXN");
  });

  it("las fechas van en español", () => {
    assert.equal(shortDate("2026-08-13T12:00:00.000Z"), "13 de agosto de 2026");
  });

  it("una fecha inválida no revienta el correo", () => {
    assert.equal(shortDate("no-es-fecha"), "—");
    assert.equal(shortDate(null), "—");
  });
});
