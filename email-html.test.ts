// Lo que este archivo protege no es "que se vea bonito", sino dos cosas concretas
// que ya salieron mal antes:
//
//  1. Que el HTML de salida use sólo construcciones que el Outlook de Windows
//     entiende. Su motor es el de Word: flexbox, grid, float y position no
//     existen ahí. Y que no quede ningún <style>, porque Gmail recorta el head.
//  2. Que la parte text/plain sea texto de verdad. Antes se mandaba el marcado
//     crudo como texto plano y quien leyera en modo texto veía etiquetas.

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { renderEmailHtml, sanitizeEmailHtml, resolveEmailBody, extractInlineImages } from "./email-html.js";

describe("renderEmailHtml: compatibilidad con clientes de correo", () => {
  const { html } = renderEmailHtml(
    "# Hola\n\n## Sección\n\nTexto **fuerte** y *suave* con [link](https://ejemplo.com).\n\n- uno\n- dos\n\n![gato](https://ejemplo.com/gato.png)\n\n> cita\n\n---\n",
  );

  it("no emite layout que Word no entiende", () => {
    for (const prohibido of ["display:flex", "display: flex", "display:grid", "display: grid", "float:", "position:"]) {
      assert.ok(!html.includes(prohibido), `la salida no debe contener "${prohibido}"`);
    }
  });

  it("no deja <style>: Gmail recorta el head y se llevaría el formato", () => {
    assert.ok(!/<style[\s>]/i.test(html));
  });

  it("inlinea los estilos en su lugar", () => {
    assert.match(html, /<p style="[^"]*font-size:\s*16px/i);
  });

  it("estructura el layout en tablas", () => {
    assert.match(html, /<table[^>]*role="presentation"/i);
  });

  it("toda imagen lleva alt y width (Outlook bloquea imágenes por defecto)", () => {
    const imgs = html.match(/<img[^>]*>/gi) ?? [];
    assert.ok(imgs.length > 0, "el caso de prueba incluye una imagen");
    for (const img of imgs) {
      assert.match(img, /alt="/i, `sin alt: ${img}`);
      // Word ignora max-width y muestra la imagen a tamaño original.
      assert.match(img, /width="\d+"/i, `sin width numérico: ${img}`);
      // juice llegó a emitir height="auto", que Outlook lee como 0.
      assert.ok(!/height="auto"/i.test(img), `height inválido: ${img}`);
    }
  });

  it("conserva el contenido", () => {
    assert.match(html, /Secci[oó]n/);
    assert.match(html, /<strong/i);
    assert.match(html, /<li/i);
    assert.match(html, /<blockquote/i);
    assert.match(html, /href="https:\/\/ejemplo\.com"/);
  });
});

describe("renderEmailHtml: lista blanca", () => {
  it("no interpreta HTML crudo incrustado en el markdown", () => {
    const { html } = renderEmailHtml("Hola <script>alert(1)</script> y <iframe src=x></iframe>");
    assert.ok(!/<script/i.test(html));
    assert.ok(!/<iframe/i.test(html));
  });

  it("descarta esquemas que no son http, https ni mailto", () => {
    const { html } = renderEmailHtml("[clic](javascript:alert(1))\n\n[ok](https://ejemplo.com)");
    // El texto literal puede sobrevivir —markdown-it deja "[clic](javascript:…)"
    // como texto plano— y eso es inofensivo. Lo que no puede existir es un
    // atributo que lo ejecute.
    assert.ok(!/(href|src)="javascript:/i.test(html));
    assert.match(html, /href="https:\/\/ejemplo\.com"/);
  });

  it("marca los enlaces con rel=noopener", () => {
    const { html } = renderEmailHtml("[ir](https://ejemplo.com)");
    assert.match(html, /rel="noopener noreferrer"/);
  });

  it("enlaza URLs sueltas (el editor va con autolink apagado)", () => {
    const { html } = renderEmailHtml("Visita https://ejemplo.com para más");
    assert.match(html, /<a[^>]+href="https:\/\/ejemplo\.com"/);
  });
});

describe("bloques ricos: tabla y cajas de color", () => {
  it("la tabla sale con bordes y encabezado, no como texto", () => {
    const { html } = renderEmailHtml("| Concepto | Precio |\n|---|---|\n| Diseño | $5,000 |");
    assert.match(html, /<table class="data"/);
    assert.match(html, /<th[^>]*>Concepto<\/th>/);
    assert.match(html, /border: 1px solid/);
  });

  it("la caja de color se arma con tabla, no con div", () => {
    const { html } = renderEmailHtml("> [!WARNING]\n> Vence el viernes.");
    assert.ok(!/<div/i.test(html), "un div no pinta fondo ni borde de forma fiable en Word");
    assert.match(html, /<table class="alert alert-warning"/);
    assert.match(html, /Advertencia/, "el título va en español");
  });

  it("cada caja lleva bgcolor: Outlook ignora background-color en CSS", () => {
    for (const [tipo, fondo] of [["NOTE", "#eff6ff"], ["TIP", "#f0fdf4"], ["WARNING", "#fffbeb"], ["CAUTION", "#fef2f2"], ["IMPORTANT", "#faf5ff"]]) {
      const { html } = renderEmailHtml(`> [!${tipo}]\n> Contenido.`);
      const celda = (html.match(/<td class="alert-cell[^>]*>/) ?? [""])[0];
      assert.match(celda, new RegExp(`bgcolor="${fondo}"`), `${tipo} sin bgcolor`);
    }
  });

  it("en texto plano la caja se sigue leyendo", () => {
    const { text } = renderEmailHtml("> [!TIP]\n> Puedes pagar en línea.");
    assert.match(text, /Puedes pagar en línea/);
    assert.ok(!text.includes("<"));
  });
});

describe("parte text/plain", () => {
  it("el texto no lleva marcado", () => {
    const { text } = renderEmailHtml("**Hola** mundo\n\n- uno");
    assert.ok(!text.includes("<"), `no debe traer etiquetas: ${text}`);
  });

  it("difiere del HTML: es el bug que se arregló", () => {
    const { html, text } = renderEmailHtml("**Hola**");
    assert.notEqual(text, html);
    assert.match(html, /<strong/i);
  });

  it("del HTML crudo del SDK se deriva texto legible, no etiquetas", () => {
    const { text } = sanitizeEmailHtml("<p>Hola <b>mundo</b></p>");
    assert.ok(!text.includes("<"), `no debe traer etiquetas: ${text}`);
    assert.match(text, /Hola mundo/);
  });
});

describe("imágenes incrustadas (cid)", () => {
  const uuid = "0f2a1c3e-4b5d-6e7f-8a9b-0c1d2e3f4a5b.png";

  it("cambia la URL propia por cid y reporta la llave", () => {
    const { html } = renderEmailHtml(`![gato](https://mailmask.studio/api/img/${uuid})`);
    const out = extractInlineImages(html);
    assert.deepEqual(out.keys, [uuid]);
    assert.match(out.html, new RegExp(`src="cid:${uuid}"`));
    // Ninguna URL nuestra debe quedar: si queda, el cliente la pediría a la red.
    assert.ok(!out.html.includes("/api/img/"));
  });

  it("no toca imágenes de otros servidores", () => {
    const { html } = renderEmailHtml("![x](https://otro.com/foto.png)");
    const out = extractInlineImages(html);
    assert.deepEqual(out.keys, []);
    assert.match(out.html, /src="https:\/\/otro\.com\/foto\.png"/);
  });

  it("la misma imagen dos veces se adjunta una sola vez", () => {
    const { html } = renderEmailHtml(
      `![a](https://mailmask.studio/api/img/${uuid})\n\n![b](https://mailmask.studio/api/img/${uuid})`,
    );
    assert.deepEqual(extractInlineImages(html).keys, [uuid]);
  });

  it("sin imágenes no cambia nada", () => {
    const { html } = renderEmailHtml("Hola");
    const out = extractInlineImages(html);
    assert.deepEqual(out.keys, []);
    assert.equal(out.html, html);
  });
});

describe("resolveEmailBody: precedencia", () => {
  it("el markdown gana sobre el resto", () => {
    const out = resolveEmailBody({ markdown: "**a**", html: "<p>b</p>", body: "c" });
    assert.equal(out.text, "**a**");
    assert.match(out.html!, /<strong/i);
  });

  it("con html crudo y sin texto, deriva el texto en vez de repetir el marcado", () => {
    const out = resolveEmailBody({ html: "<p>Hola mundo</p>" });
    assert.ok(!out.text.includes("<"));
    assert.match(out.text, /Hola mundo/);
  });

  it("respeta el texto propio del cliente si lo manda", () => {
    const out = resolveEmailBody({ html: "<p>Hola</p>", body: "versión en texto" });
    assert.equal(out.text, "versión en texto");
  });

  it("sin markdown ni html se comporta como antes: sólo texto", () => {
    const out = resolveEmailBody({ body: "pelón" });
    assert.equal(out.text, "pelón");
    assert.equal(out.html, undefined);
  });
});
