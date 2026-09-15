import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { appendSignature, extractInlineImages, resolveEmailBody, DOMAIN_LOGO_PATH } from "./email-html.ts";
import { app } from "./main.ts";
import { createUser, createDomain, createConversation, addMessage, indexMessage, getIndexedBody } from "./db.ts";
import { signJwt, generateCsrfToken } from "./auth.ts";
import { ftsDisponible } from "./pg.ts";
import { clasificarErrorS3, degradedBodyState } from "./ses.ts";

const sufijo = () => Math.random().toString(36).slice(2, 10);
let ipN = 0;
const ipBase = `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
const nextIp = () => `${ipBase}.${ipN++ % 255}`;

const LOGO_URL = "https://www.mailmask.studio/api/domain-logo/11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222.png";

async function sesion(email: string) {
  return { email, cookie: `token=${await signJwt({ email })}`, csrf: generateCsrfToken() };
}

async function dominioNuevo() {
  const dueno = `logo-${sufijo()}@ejemplo.com`;
  await createUser(dueno, "hash");
  const dom = await createDomain(dueno, `${sufijo()}.ejemplo.com`, ["dkim"], `v-${sufijo()}`);
  return { dom, sesion: await sesion(dueno) };
}

function subir(domainId: string, s: { cookie: string; csrf: string }, bytes: Uint8Array, tipo: string, nombre = "logo.png") {
  const fd = new FormData();
  fd.append("file", new File([bytes as BlobPart], nombre, { type: tipo }));
  return app.fetch(new Request(`http://localhost/api/domains/${domainId}/logo`, {
    method: "POST",
    headers: {
      "x-forwarded-for": nextIp(),
      cookie: `${s.cookie}; csrf_token=${s.csrf}`,
      "x-csrf-token": s.csrf,
    },
    body: fd,
  }));
}

describe("Logo de la firma", () => {
  it("🔴 el logo NO se convierte en cid: — por eso no lo borra el envío", () => {
    // extractInlineImages sólo reconoce /api/img/<uuid>.<ext>. Si el logo cayera
    // en ese regex, se adjuntaría al correo y discardSentImages lo borraría de S3
    // al primer envío: la firma quedaría rota para siempre a partir del segundo.
    const html = `<p>Hola</p><img src="${LOGO_URL}"><img src="https://x/api/img/33333333-3333-3333-3333-333333333333.png">`;
    const { keys, html: reescrito } = extractInlineImages(html);
    assert.equal(keys.length, 1, "sólo la imagen del compositor se vuelve cid:");
    assert.equal(keys[0], "33333333-3333-3333-3333-333333333333.png");
    assert.ok(reescrito.includes(LOGO_URL), "la URL del logo sale intacta");
    assert.equal(reescrito.includes(`cid:22222222`), false);
  });

  it("pega el logo arriba de la firma, en markdown", () => {
    const salida = appendSignature("Hola", "Brenda Ruiz", LOGO_URL);
    assert.ok(salida.includes(`![](${LOGO_URL})`));
    assert.ok(salida.indexOf(LOGO_URL) < salida.indexOf("Brenda Ruiz"), "el logo va antes del texto");
  });

  it("sin logo se comporta igual que antes", () => {
    assert.equal(appendSignature("Hola", "Brenda"), "Hola\n\n---\n\nBrenda");
    assert.equal(appendSignature("Hola", null, null), "Hola");
  });

  it("acepta logo sin texto de firma", () => {
    const salida = appendSignature("Hola", "", LOGO_URL);
    assert.ok(salida.includes(`![](${LOGO_URL})`));
  });

  it("el logo se renderiza angosto, no a los 600px del cuerpo", () => {
    // Sin esto heredaría el ancho del correo y saldría un logo enorme.
    const html = resolveEmailBody({ markdown: appendSignature("Hola", "Brenda", LOGO_URL) }).html ?? "";
    assert.ok(html.includes(DOMAIN_LOGO_PATH));
    assert.ok(/width="200"/.test(html), `esperaba width=200, salió: ${html.slice(0, 400)}`);
  });

  it("una imagen normal del cuerpo sigue a 600px", () => {
    const html = resolveEmailBody({ markdown: "![](https://ejemplo.com/foto.png)" }).html ?? "";
    assert.ok(/width="600"/.test(html));
  });
});

describe("Subida del logo", () => {
  const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

  it("rechaza GIF: animado en cada correo no", async () => {
    const { dom, sesion: s } = await dominioNuevo();
    const res = await subir(dom.id, s, png, "image/gif", "logo.gif");
    assert.equal(res.status, 415);
  });

  it("rechaza un tipo fuera de la lista blanca", async () => {
    const { dom, sesion: s } = await dominioNuevo();
    assert.equal((await subir(dom.id, s, png, "image/svg+xml", "logo.svg")).status, 415);
  });

  it("rechaza más de 500 KB", async () => {
    const { dom, sesion: s } = await dominioNuevo();
    const grande = new Uint8Array(600 * 1024);
    assert.equal((await subir(dom.id, s, grande, "image/png")).status, 413);
  });

  it("un correo ajeno no puede subir logo a un dominio que no es suyo", async () => {
    const { dom } = await dominioNuevo();
    const intruso = `intruso-${sufijo()}@ejemplo.com`;
    await createUser(intruso, "hash");
    const res = await subir(dom.id, await sesion(intruso), png, "image/png");
    assert.equal(res.status, 404);
  });
});

describe("Servir el logo", () => {
  it("una llave inválida o con .. devuelve 404 sin tocar S3", async () => {
    const rutas = [
      "/api/domain-logo/no-es-uuid/22222222-2222-2222-2222-222222222222.png",
      "/api/domain-logo/11111111-1111-1111-1111-111111111111/..%2F..%2Finbound%2Fx",
      "/api/domain-logo/11111111-1111-1111-1111-111111111111/archivo.txt",
      "/api/domain-logo/11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222.gif",
    ];
    for (const ruta of rutas) {
      const res = await app.fetch(new Request(`http://localhost${ruta}`));
      assert.equal(res.status, 404, ruta);
    }
  });
});

describe("Rescate del cuerpo desde el índice", () => {
  it("devuelve el texto indexado y null para lo que no está", async (t) => {
    if (!ftsDisponible) return t.skip("sin FTS5");
    const { dom } = await dominioNuevo();
    const conv = await createConversation({
      domainId: dom.id,
      from: "cliente@fuera.com",
      to: `hola@${dom.domain}`,
      subject: "Cotización",
      status: "open",
      priority: "normal",
      lastMessageAt: new Date().toISOString(),
      messageCount: 1,
      tags: [],
      threadReferences: [],
    });
    const msg = await addMessage({
      conversationId: conv.id,
      from: "cliente@fuera.com",
      direction: "inbound",
      createdAt: new Date().toISOString(),
    });
    indexMessage({
      messageId: msg.id,
      conversationId: conv.id,
      domainId: dom.id,
      from: "cliente@fuera.com",
      subject: "Cotización",
      text: "Adjunto la cotización del proyecto.",
    });

    // Es el plan B cuando el objeto de S3 ya no existe: el cuerpo del entrante
    // no se guarda en messages a propósito, así que sin esto se pierde entero.
    assert.equal(getIndexedBody(msg.id), "Adjunto la cotización del proyecto.");
    assert.equal(getIndexedBody("no-existe"), null);
  });
});

describe("Clasificación de errores de S3", () => {
  it("separa 'ya no existe' de 'no tenemos permiso'", () => {
    // Los tres desenlaces llegan al usuario como mensajes distintos: uno es
    // definitivo, otro se reintenta. Antes los tres decían "error".
    assert.equal(clasificarErrorS3({ name: "NoSuchKey", $metadata: { httpStatusCode: 404 } }), "NOT_FOUND");
    assert.equal(clasificarErrorS3({ $metadata: { httpStatusCode: 404 } }), "NOT_FOUND");
    assert.equal(clasificarErrorS3({ name: "NotFound" }), "NOT_FOUND");
    assert.equal(clasificarErrorS3({ name: "AccessDenied", $metadata: { httpStatusCode: 403 } }), "DENIED");
    assert.equal(clasificarErrorS3({ name: "TimeoutError" }), "OTHER");
    assert.equal(clasificarErrorS3(new Error("red caída")), "OTHER");
  });

  it("un NOT_FOUND pasada la retención de 90 días es 'expired', antes es una pérdida", () => {
    // El bucket borra inbound/ a los 90 días a propósito (lifecycle). Perder un
    // correo de ayer es otra cosa y debe seguir saliendo como error.
    const hace = (dias: number) => new Date(Date.now() - dias * 86_400_000).toISOString();
    assert.equal(degradedBodyState("NOT_FOUND", hace(91), true), "expired");
    assert.equal(degradedBodyState("NOT_FOUND", hace(91), false), "expired_gone");
    assert.equal(degradedBodyState("NOT_FOUND", hace(1), true), "index");
    assert.equal(degradedBodyState("NOT_FOUND", hace(1), false), "gone");
    assert.equal(degradedBodyState("DENIED", hace(200), true), "error");
    assert.equal(degradedBodyState("OTHER", hace(1), false), "error");
  });
});
