// Firma, cita del mensaje anterior, Cc/Cco y adjuntos, sobre el envío real de la
// Bandeja. Va aparte de compose-flow porque necesita su propio mock de ses.ts.

import { describe, it, before, mock } from "node:test";
import assert from "node:assert/strict";

const suffix = Date.now();
const sent: { to: string; body: string; opts?: Record<string, any> }[] = [];

describe("Bandeja: firma, cita, copias y adjuntos", () => {
  // deno-lint-ignore no-explicit-any
  let app: any;
  // deno-lint-ignore no-explicit-any
  let dbmod: any;
  const email = `extras-${suffix}@example.com`;
  let cookie = "";
  let csrf = "";
  let domainId = "";
  let conversationId = "";

  before(async () => {
    const realSes = await import("./ses.ts");
    mock.module("./ses.ts", {
      namedExports: {
        ...realSes,
        sendFromDomain: async (_f: string, to: string, _s: string, body: string, opts?: Record<string, any>) => {
          sent.push({ to, body, opts });
          return `<stub-${crypto.randomUUID()}@test>`;
        },
        // Sin AWS: el adjunto se sirve desde memoria.
        getEmailFileFromS3: async () => ({ body: new Uint8Array([1, 2, 3]), contentType: "application/pdf" }),
        deleteEmailFileFromS3: async () => {},
        getEmailImageFromS3: async () => null,
      },
    });

    ({ app } = await import("./main.ts"));
    dbmod = await import("./db.ts");
    const { sqlite } = await import("./pg.ts");
    const { hashPassword } = await import("./auth.ts");

    sqlite.prepare("DELETE FROM rate_limits").run();
    dbmod.createUser(email, await hashPassword("password123"));
    await dbmod.updateUserSubscription(email, {
      plan: "freelancer",
      status: "active",
      mpSubscriptionId: `sub-extras-${suffix}`,
      currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString(),
    });

    const loginRes = await app.fetch(new Request("http://localhost/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json", "x-forwarded-for": "10.7.7.7" },
      body: JSON.stringify({ email, password: "password123" }),
    }));
    for (const sc of loginRes.headers.getSetCookie?.() ?? []) {
      const t = sc.match(/(?:^|[\s,])token=([^;,]+)/);
      if (t) cookie = `token=${t[1]}`;
      const c = sc.match(/csrf_token=([^;,]+)/);
      if (c) csrf = c[1];
    }
    await loginRes.body?.cancel();

    const dom = dbmod.createDomain(email, `extras-${suffix}.com`, ["dk"], "vf");
    domainId = dom.id;
    sqlite.prepare("UPDATE domains SET verified = 1 WHERE id = ?").run(domainId);
    dbmod.createAlias(domainId, "hola", ["destino@example.com"]);

    const conv = dbmod.createConversation({
      domainId, from: "cliente@example.com", to: `hola@extras-${suffix}.com`,
      subject: "Pregunta", status: "open", priority: "normal",
      lastMessageAt: new Date().toISOString(), messageCount: 1, tags: [],
      threadReferences: ["<orig@example.com>"],
    });
    conversationId = conv.id;
    dbmod.addMessage({
      conversationId: conv.id, from: "cliente@example.com",
      body: "¿Cuánto cuesta el logotipo?", html: "",
      direction: "inbound", createdAt: "2026-08-18T10:00:00.000Z", messageId: "<orig@example.com>",
    });
  });

  const reply = (extra: Record<string, unknown> = {}) =>
    app.fetch(new Request(`http://localhost/api/bandeja/conversations/${conversationId}/reply`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": `10.7.7.${Math.floor(Math.random() * 200) + 10}`,
        cookie: `${cookie}; csrf_token=${csrf}`,
        "x-csrf-token": csrf,
      },
      body: JSON.stringify({ domainId, markdown: "Cuesta $5,000.", ...extra }),
    }));

  it("la firma sale en el HTML y también en el texto plano", async () => {
    dbmod.updateDomain(domainId, { signature: "**Brenda**" });
    const res = await reply();
    assert.equal(res.status, 200);
    await res.body?.cancel();

    const last = sent[sent.length - 1];
    // En texto plano importa igual: sin esto, quien lee en modo texto ve un correo
    // sin firmar.
    assert.match(last.body, /\*\*Brenda\*\*/);
    assert.match(last.opts?.html, /<strong[^>]*>Brenda<\/strong>/);
  });

  it("cita el último mensaje recibido, y se puede desactivar", async () => {
    const conCita = await reply();
    await conCita.body?.cancel();
    assert.match(sent[sent.length - 1].body, /> ¿Cuánto cuesta el logotipo\?/);
    assert.match(sent[sent.length - 1].body, /escribió:/);

    const sinCita = await reply({ quote: false });
    await sinCita.body?.cancel();
    assert.ok(!/logotipo/.test(sent[sent.length - 1].body));
  });

  it("Cc y Cco llegan a sendFromDomain; las direcciones inválidas se descartan", async () => {
    const res = await reply({ cc: ["jefe@example.com", "no-es-correo"], bcc: ["oculto@example.com"] });
    await res.body?.cancel();
    const last = sent[sent.length - 1];
    assert.deepEqual(last.opts?.cc, ["jefe@example.com"]);
    assert.deepEqual(last.opts?.bcc, ["oculto@example.com"]);
  });

  it("el adjunto viaja con el correo", async () => {
    const res = await reply({
      attachments: [{ key: "0f2a1c3e-4b5d-6e7f-8a9b-0c1d2e3f4a5b", filename: "cotización.pdf", contentType: "application/pdf" }],
    });
    await res.body?.cancel();
    const files = sent[sent.length - 1].opts?.attachments;
    assert.equal(files?.length, 1);
    assert.equal(files[0].filename, "cotización.pdf");
    // El tipo sale del objeto guardado, no de lo que dijo el cliente.
    assert.equal(files[0].contentType, "application/pdf");
  });

  it("una llave de adjunto con formato inválido se ignora en vez de romper el envío", async () => {
    const res = await reply({ attachments: [{ key: "../otro", filename: "x.pdf", contentType: "application/pdf" }] });
    assert.equal(res.status, 200);
    await res.body?.cancel();
    assert.equal(sent[sent.length - 1].opts?.attachments, undefined);
  });
});
