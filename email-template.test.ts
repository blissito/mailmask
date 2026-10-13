// Lo que este archivo protege es la PLANTILLA de `email-template.ts`: el shell de
// tablas anidadas y la hoja de estilos. `email-html.test.ts` ya la roza, pero mira de
// refilón —que exista un `<p>` y que haya una tabla—: si alguien mueve el shell,
// renombra una clase sin dejar su regla o infla la hoja, nada falla y el golpe llega
// en el Outlook de Windows o en el "[Mensaje recortado]" de Gmail, que corta el
// `<head>` —y con él el `<style>`— pasados ~102 KB.
//
// Dos notas para quien venga después:
//   - `wrapEmailHtml` es puro: pega el cuerpo TAL CUAL, sin sanear ni escapar. Aquí se
//     prueba la FORMA del documento, no la lista blanca (eso es del otro archivo).
//   - El único camino público que hace wrap + juice con las opciones de producción es
//     `sanitizeEmailHtml`: `toEmailHtml` no se exporta, así que no hay atajo para ver
//     el inline sin pasar por la lista blanca.

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { EMAIL_STYLES, wrapEmailHtml } from "./email-template.js";
import { MAX_EMAIL_HTML_BYTES, appendSignature, renderEmailHtml, sanitizeEmailHtml } from "./email-html.js";

// Tope NUESTRO, no de Gmail: el shell vacío midió 4.7 KB el 13-oct-2026 (1.0 KB ya
// inlineado), así que 20 KB deja ~4x de margen y avisa si la plantilla empieza a
// engordar sola mucho antes de que el recorte de Gmail sea el problema de verdad.
const TOPE_DEL_SHELL_BYTES = 20_000;

/** La primera etiqueta del documento que casa con el patrón (o "" si no está). */
function etiquetaCon(html: string, patron: RegExp): string {
  return (html.match(patron) ?? [""])[0];
}

/** Etiquetas de apertura que traen `class=`: son las que juice tiene que resolver. */
function conClase(html: string): string[] {
  return [...html.matchAll(/<([a-z0-9]+)([^>]*\bclass="[^"]*"[^>]*)>/gi)].map((m) => m[0]);
}

/** Las clases sueltas que aparecen en el documento de salida, sin repetir. */
function clasesDe(html: string): string[] {
  const clases = new Set<string>();
  for (const tag of conClase(html)) {
    for (const clase of (tag.match(/class="([^"]*)"/)?.[1] ?? "").split(/\s+/)) {
      if (clase) clases.add(clase);
    }
  }
  return [...clases].sort();
}

// ~2 KB de markdown: un correo de verdad —encabezados, párrafos, lista, tabla, caja de
// color, imagen y firma—, no un "hola" de dos líneas.
const CUERPO_TIPICO = [
  "# Estado de tu pedido",
  "",
  "## Resumen",
  "",
  "El paquete salió el **martes** y llega el *jueves*. Puedes seguirlo en [la guía de envíos](https://ejemplo.com/guia?ref=correo&id=12345) o escribirnos a hola@ejemplo.com.",
  "",
  "Si la dirección no es la correcta, contesta este correo antes del miércoles y lo reprogramamos sin costo. El reembolso del envío exprés se aplica sólo cuando el retraso pasa de 48 horas, según lo que acordamos por teléfono el lunes por la tarde con la persona de atención a clientes.",
  "",
  "Mientras tanto, el equipo de logística revisa cada mañana los paquetes detenidos en aduana y avisa por este mismo medio cuando hace falta que mandes un documento o un comprobante de domicilio; si tu pedido cae ahí, ya no depende del repartidor sino de la revisión documental.",
  "",
  "Cualquier cambio de dirección después del envío tiene un costo de $150 más el retorno del paquete, porque la guía ya está pagada y el operador la cobra completa aunque el envío no se entregue en el primer intento.",
  "",
  "- El número de guía llega por correo aparte.",
  "- El repartidor toca dos veces y espera cinco minutos.",
  "- Si nadie contesta, el paquete se queda en la sucursal tres días.",
  "- Guarda el número de guía por si necesitas reclamar.",
  "- El seguro cubre hasta $2,000 por paquete.",
  "",
  "| Concepto | Precio | Nota |",
  "|---|---|---|",
  "| Diseño | $5,000 | incluye dos rondas de cambios |",
  "| Desarrollo | $12,000 | entrega en tres semanas |",
  "",
  "> [!NOTE]",
  "> El comprobante fiscal se emite con los datos de la cuenta, no con los que escribas en el formulario de contacto.",
  "",
  "> [!TIP]",
  "> Si vas a estar fuera de casa, deja instrucciones con quien reciba: el repartidor no puede entregar a un vecino sin autorización escrita tuya.",
  "",
  "Si el paquete llega dañado, tómale foto antes de abrirlo y responde a este correo con la imagen: con eso abrimos el reclamo con la paquetería el mismo día, sin que tengas que ir a ninguna sucursal.",
  "",
  "![Guía de envíos](https://mailmask.studio/api/img/0f2a1c3e-4b5d-6e7f-8a9b-0c1d2e3f4a5b.png)",
].join("\n");

const CON_FIRMA = appendSignature(
  CUERPO_TIPICO,
  "Ana López\nDiseñadora\nana@ejemplo.com\nhttps://ejemplo.com",
  "https://mailmask.studio/api/domain-logo/0f2a1c3e.png",
);

describe("wrapEmailHtml: el shell de tablas", () => {
  it("es un documento XHTML completo, con su charset", () => {
    const html = wrapEmailHtml("<p>x</p>");
    assert.match(html, /^<!DOCTYPE html PUBLIC "-\/\/W3C\/\/DTD XHTML 1\.0 Transitional\/\/EN"/);
    assert.match(html, /xmlns="http:\/\/www\.w3\.org\/1999\/xhtml"/);
    assert.match(html, /charset=UTF-8/i);
    assert.match(html, /<\/html>\s*$/);
  });

  it("deja el cuerpo dentro de wrapper → content (600) → celda del cuerpo", () => {
    const html = wrapEmailHtml("<p>MARCA</p>");
    const iWrapper = html.indexOf('<table class="email-wrapper"');
    const iContent = html.indexOf('<table class="email-content"');
    const iCelda = html.indexOf('<td class="email-body"');
    const iMarca = html.indexOf("MARCA");
    assert.ok(
      iWrapper > -1 && iContent > iWrapper && iCelda > iContent && iMarca > iCelda,
      "el anidado cambió: el cuerpo ya no va dentro de wrapper → content → celda",
    );
    assert.ok(iMarca < html.indexOf("</td>", iCelda), "el cuerpo se salió de la celda del cuerpo");
  });

  it("el wrapper centra el contenido y fija los anchos: lo único que Word entiende", () => {
    const html = wrapEmailHtml("<p>x</p>");
    const wrapper = etiquetaCon(html, /<table class="email-wrapper"[^>]*>/);
    assert.match(wrapper, /role="presentation"/, "sin role=presentation el lector anuncia la tabla como datos");
    assert.match(wrapper, /width="100%"/);
    assert.match(html, /<td align="center">/, "align=center es lo que centra en Word, que ignora margin: 0 auto");
    const content = etiquetaCon(html, /<table class="email-content"[^>]*>/);
    assert.match(content, /role="presentation"/);
    assert.match(content, /width="600"/, "sin el ancho fijo, Outlook muestra la tabla a tamaño de su ventana");
  });

  it("no toca el cuerpo: lo pega tal cual, sin escaparlo ni sanearlo", () => {
    const cuerpo = "<b>&amp;</b> y 1 < 2";
    const html = wrapEmailHtml(cuerpo);
    assert.ok(html.includes(cuerpo), "wrapEmailHtml alteró el cuerpo; el saneo es de email-html.ts");
    assert.ok(!html.includes("&lt;b&gt;"), "wrapEmailHtml escapó el cuerpo por su cuenta");
  });

  it("con el cuerpo vacío sigue siendo un documento completo", () => {
    const html = wrapEmailHtml("");
    assert.match(html, /<!DOCTYPE html/i);
    assert.match(html, /<td class="email-body">/);
    assert.match(html, /<\/html>\s*$/);
  });
});

describe("EMAIL_STYLES: la hoja que el motor de Word puede leer", () => {
  it("no usa nada que Word ignore o rompa", () => {
    assert.ok(!/display:\s*(flex|grid)/i.test(EMAIL_STYLES), "flex y grid no existen en el motor de Word");
    assert.ok(!/\bfloat\s*:/i.test(EMAIL_STYLES), "float no existe en el motor de Word");
    assert.ok(!/\bposition\s*:/i.test(EMAIL_STYLES), "position no existe en el motor de Word");
    assert.ok(!/calc\(/i.test(EMAIL_STYLES), "Word no evalúa calc()");
    assert.ok(
      !/\b(margin|padding|border|inset)-(inline|block)/i.test(EMAIL_STYLES),
      "las propiedades lógicas no llegan al motor de Word: usa width/height/margin/padding con lados explícitos",
    );
  });

  it("define las clases que usa el shell (una clase sin regla queda pelona tras juice)", () => {
    for (const clase of ["email-wrapper", "email-content", "email-body"]) {
      assert.ok(EMAIL_STYLES.includes(`.${clase}`), `.${clase} se usa en el shell y no tiene regla en la hoja`);
    }
  });

  it("el shell vacío no engorda solo", () => {
    const bytes = Buffer.byteLength(wrapEmailHtml(""));
    assert.ok(bytes < TOPE_DEL_SHELL_BYTES, `el shell vacío ya pesa ${bytes} bytes (tope ${TOPE_DEL_SHELL_BYTES})`);
  });
});

describe("la cadena real (sanitizeEmailHtml): wrap + juice", () => {
  // Tabla y las cinco cajas de color a propósito: son las clases que juice tiene que
  // resolver, y las que se quedan sin regla si alguien toca la hoja.
  const alertas = ["note", "tip", "important", "warning", "caution"]
    .map(
      (tipo) =>
        `<table class="alert alert-${tipo}"><tr><td class="alert-cell alert-cell-${tipo}">` +
        `<p class="alert-title alert-title-${tipo}">${tipo}</p><p>Dato</p></td></tr></table>`,
    )
    .join("");
  const { html } = sanitizeEmailHtml(
    '<h2>Sección</h2><p>Hola</p>' +
      '<table class="data"><tr><th>A</th></tr><tr><td>1</td></tr></table>' +
      alertas,
  );

  // El tipo de la caja va como gancho en la tabla (`class="alert alert-note"`) y NO tiene
  // regla propia a propósito: el color lo pintan `.alert-cell-<tipo>` y `.alert-title-<tipo>`.
  // Cualquier OTRA clase sin regla es una regla que se perdió: el elemento se queda con el
  // estilo que le presten sus otros selectores —o con ninguno— y nada lo avisa.
  const SIN_REGLA_A_PROPOSITO = /^alert-(note|tip|important|warning|caution)$/;

  it("no deja ningún <style>: Gmail se llevaría el formato al recortar el head", () => {
    assert.ok(!/<style[\s>]/i.test(html), "quedó un <style> en la salida");
  });

  it("no deja ninguna clase sin su estilo inline", () => {
    const conClases = conClase(html);
    // Sin esto la prueba pasaría vacía si un día el shell pierde sus clases.
    assert.ok(conClases.length >= 8, `el caso debe traer clases (shell, tabla y cajas) y trajo ${conClases.length}`);
    const pelonas = conClases.filter((tag) => !/\bstyle="/i.test(tag));
    assert.equal(pelonas.length, 0, `etiquetas con class y sin regla inline: ${pelonas.join(" | ")}`);
  });

  it("cada clase de la salida tiene su regla en EMAIL_STYLES", () => {
    const clases = clasesDe(html);
    assert.ok(clases.length >= 8, `el caso debe traer clases (shell, tabla y cajas) y trajo ${clases.length}`);
    // Un `style=` de otro selector no basta: al <p class="alert-title alert-title-note"> le
    // queda el estilo de `p.alert-title`, así que sin esta prueba se puede borrar la regla
    // del título de una caja y la suite sigue verde con el color perdido.
    const sinRegla = clases.filter(
      (clase) => !SIN_REGLA_A_PROPOSITO.test(clase) && !new RegExp(`\\.${clase}(?![\\w-])`).test(EMAIL_STYLES),
    );
    assert.deepEqual(sinRegla, [], `clases sin regla en la hoja: ${sinRegla.join(", ")}`);
  });

  it("el fondo, la tipografía y el color de la hoja llegan inlineados", () => {
    assert.match(etiquetaCon(html, /<body[^>]*>/), /background-color:\s*#faf6ee/i, "el body perdió el fondo de la hoja");
    assert.match(
      etiquetaCon(html, /<table class="email-wrapper"[^>]*>/),
      /background-color:\s*#faf6ee/i,
      "el wrapper perdió el fondo de la hoja",
    );
    const celda = etiquetaCon(html, /<td class="email-body"[^>]*>/);
    assert.match(celda, /font-family:[^"]*sans-serif/i, "la celda del cuerpo perdió la tipografía");
    assert.match(celda, /padding:\s*24px 12px/i, "la celda del cuerpo perdió el espaciado");
    assert.match(celda, /color:\s*#1c1917/i, "la celda del cuerpo perdió el color de texto");
    assert.match(
      etiquetaCon(html, /<table class="email-content"[^>]*>/),
      /max-width:\s*600px/i,
      "la tabla de contenido perdió el tope de ancho",
    );
  });

  it("el contenido del usuario cae dentro de la celda del cuerpo", () => {
    assert.match(html, /<td class="email-body"[^>]*>[\s\S]*?<p[^>]*>Hola<\/p>/);
  });
});

describe("tamaño de un correo típico", () => {
  it("cabe holgado bajo el límite de Gmail", () => {
    const markdownBytes = Buffer.byteLength(CON_FIRMA);
    assert.ok(markdownBytes >= 1_800, `el cuerpo de prueba se encogió a ${markdownBytes} bytes de markdown`);

    const { html } = renderEmailHtml(CON_FIRMA);
    const bytes = Buffer.byteLength(html);
    assert.ok(bytes < MAX_EMAIL_HTML_BYTES, `${bytes} bytes rebasan el límite de Gmail (${MAX_EMAIL_HTML_BYTES})`);
    // Margen medido: 8,130 bytes con 2,126 de markdown el 13-oct-2026. Un cuarto del
    // límite es el aviso temprano de que un correo típico empezó a crecer (plantilla o
    // CSS de más).
    assert.ok(bytes < MAX_EMAIL_HTML_BYTES / 4, `${bytes} bytes es más de un cuarto del límite de Gmail`);
  });
});
