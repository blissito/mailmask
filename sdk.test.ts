// Contrato entre el SDK publicado y el servidor.
//
// Existe porque el SDK 0.1.4 salió a npm con rutas que no existían (`/aliases`
// cuando el servidor expone `/alias`, `/bulk-send` cuando es `/send-bulk`) y con
// un campo `fromLocal` que el servidor nunca leyó: todo correo salía desde
// `noreply@` sin avisar. Nada de eso lo veía la suite, que siempre pegó a las
// rutas a mano. Aquí se ejercita el SDK REAL contra la app REAL.
//
// Va aparte, como compose-flow.test.ts, porque el mock de ses.ts tiene que
// instalarse antes de que main.ts lo cargue — de ahí los imports dinámicos.
import { describe, it, before, mock } from "node:test";
import assert from "node:assert/strict";

import { MailMask, MailMaskError, verifyWebhookSignature } from "./sdk/src/index.js";

const suffix = Date.now();
// deno-lint-ignore no-explicit-any
const enviados: { from: string; to: string; subject: string; opts?: any }[] = [];
// "S3" en memoria para los adjuntos.
const archivos = new Map<string, { body: Uint8Array; contentType: string }>();

// Estado que "SES" reporta. Los tests lo mueven para simular que la identidad
// desapareció de la cuenta, que es lo que le pasó a brendago.design.
const ses = { verified: true, dkimVerified: true, respondio: true };

describe("SDK ↔ servidor: contrato", () => {
  // deno-lint-ignore no-explicit-any
  let app: any;
  // deno-lint-ignore no-explicit-any
  let dbmod: any;
  // deno-lint-ignore no-explicit-any
  let sqlite: any;

  const email = `sdk-${suffix}@example.com`;
  const dominio = `sdk-${suffix}.com`;
  let mm: MailMask;
  let sinEnvios: MailMask;
  let dev: MailMask;
  const devEmail = `sdk-dev-${suffix}@example.com`;
  let devDomainId = "";
  let domainId = "";

  before(async () => {
    const realSes = await import("./ses.ts");
    mock.module("./ses.ts", {
      namedExports: {
        ...realSes,
        // deno-lint-ignore no-explicit-any
        sendFromDomain: async (from: string, to: string, subject: string, _body: string, opts?: any) => {
          enviados.push({ from, to, subject, opts });
          return { messageId: `<stub-${crypto.randomUUID()}@test>`, sesMessageId: `ses-${crypto.randomUUID()}` };
        },
        putEmailFileToS3: async (key: string, body: Uint8Array, contentType: string) => { archivos.set(key, { body, contentType }); },
        getEmailFileFromS3: async (key: string) => archivos.get(key) ?? null,
        deleteEmailFileFromS3: async (key: string) => { archivos.delete(key); },
        checkDomainStatus: async () => ({ ...ses }),
        // domains.create pide a SES la identidad y la regla de recepción.
        verifyDomain: async () => ({ verificationToken: "tok", dkimTokens: ["d1", "d2", "d3"] }),
        createReceiptRule: async () => undefined,
        deleteReceiptRule: async () => undefined,
        deleteConfigurationSet: async () => undefined,
        deleteDomainIdentity: async () => undefined,
      },
    });

    ({ app } = await import("./main.ts"));
    dbmod = await import("./db.ts");
    ({ sqlite } = await import("./pg.ts"));
    sqlite.prepare("DELETE FROM rate_limits").run();

    // El SDK habla con la app en proceso: mismo camino HTTP real (headers,
    // validación, auth) sin abrir un puerto.
    const comoFetch = (async (url: string | URL | Request, init?: RequestInit) =>
      app.fetch(new Request(url as string, init))) as unknown as typeof fetch;

    const alta = async (correo: string, conEnvios: boolean, plan = "basico") => {
      dbmod.createUser(correo, await (await import("./auth.ts")).hashPassword("password123"));
      await dbmod.updateUserSubscription(correo, {
        plan,
        status: "active",
        mpSubscriptionId: `sub-${correo}`,
        currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString(),
      });
      if (conEnvios) {
        const addon = dbmod.createAddon(correo, "sends100");
        dbmod.updateAddon(addon.id, {
          status: "active",
          currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString(),
        });
      }
      const { plaintextKey } = await dbmod.createApiKey(correo, "sdk-test");
      return new MailMask({ apiKey: plaintextKey, baseUrl: "http://localhost", fetch: comoFetch });
    };

    mm = await alta(email, true);

    const dom = dbmod.createDomain(email, dominio, ["dkim1"], "verify1");
    domainId = dom.id;
    sqlite.prepare("UPDATE domains SET verified = 1 WHERE id = ?").run(domainId);

    const otro = `sdk-noenvios-${suffix}@example.com`;
    sinEnvios = await alta(otro, false);

    // Básico no tiene reglas ni SMTP: para probar esos recursos hace falta Developer.
    dev = await alta(devEmail, false, "developer");
    const devDom = dbmod.createDomain(devEmail, `sdk-dev-${suffix}.com`, ["dk"], "vf");
    devDomainId = devDom.id;
    sqlite.prepare("UPDATE domains SET verified = 1 WHERE id = ?").run(devDomainId);
  });

  it("la llave que emite el servidor autentica en el SDK", async () => {
    const dominios = await mm.domains.list();
    assert.ok(dominios.some((d) => d.id === domainId), "el dominio de la cuenta no aparece");
  });

  it("aliases: los cuatro métodos existen (el SDK pegaba a /aliases, que es 404)", async () => {
    const creado = await mm.aliases.create(domainId, {
      alias: "hola",
      destinations: ["brenda@example.com"],
    });
    assert.equal(creado.alias, "hola");
    assert.deepEqual(creado.destinations, ["brenda@example.com"]);

    const lista = await mm.aliases.list(domainId);
    assert.ok(lista.some((a) => a.alias === "hola"));

    await mm.aliases.update(domainId, "hola", { enabled: false });
    assert.equal((await mm.aliases.list(domainId)).find((a) => a.alias === "hola")?.enabled, false);
    await mm.aliases.update(domainId, "hola", { enabled: true });

    await mm.aliases.create(domainId, { alias: "temporal", destinations: ["x@example.com"] });
    await mm.aliases.delete(domainId, "temporal");
    assert.ok(!(await mm.aliases.list(domainId)).some((a) => a.alias === "temporal"));
  });

  it("send con `from` sale del alias pedido, no de noreply", async () => {
    enviados.length = 0;
    const res = await mm.send.send(domainId, {
      from: "hola",
      to: "cliente@example.com",
      subject: "Pedido nuevo",
      html: "<p>Gracias</p>",
    });
    assert.ok(res.messageId, "sin messageId");
    assert.equal(enviados.length, 1);
    assert.equal(enviados[0].from, `hola@${dominio}`);
  });

  it("fromName viaja como display name", async () => {
    enviados.length = 0;
    await mm.send.send(domainId, {
      from: "hola",
      fromName: "Libretas",
      to: "cliente@example.com",
      subject: "Con nombre",
      html: "<p>hey</p>",
    });
    assert.equal(enviados[0].from, `Libretas <hola@${dominio}>`);
  });

  it("sin `from` cae en noreply, que es el default documentado", async () => {
    enviados.length = 0;
    await mm.send.send(domainId, {
      to: "cliente@example.com",
      subject: "Sin remitente",
      body: "texto plano",
    });
    assert.equal(enviados[0].from, `noreply@${dominio}`);
  });

  it("un alias inactivo no puede ser remitente", async () => {
    await mm.aliases.update(domainId, "hola", { enabled: false });
    await assert.rejects(
      () => mm.send.send(domainId, { from: "hola", to: "a@example.com", subject: "x", html: "<p>x</p>" }),
      (err: MailMaskError) => err.status === 400
    );
    await mm.aliases.update(domainId, "hola", { enabled: true });
  });

  it("sin add-on de envíos el SDK recibe 403, no un error opaco", async () => {
    const dom = dbmod.createDomain(`sdk-noenvios-${suffix}@example.com`, `noenvios-${suffix}.com`, ["dk"], "vf");
    sqlite.prepare("UPDATE domains SET verified = 1 WHERE id = ?").run(dom.id);
    await assert.rejects(
      () => sinEnvios.send.send(dom.id, { to: "a@example.com", subject: "x", body: "x" }),
      (err: MailMaskError) => err.status === 403 && /add-on/i.test(err.message)
    );
  });

  it("bulk: el jobId que devuelve bulkSend es el que lee bulkStatus", async () => {
    const job = await mm.send.bulkSend(domainId, {
      from: "hola",
      recipients: ["a@example.com", "b@example.com"],
      subject: "Newsletter",
      html: "<p>hola</p>",
    });
    assert.ok(job.jobId, "bulkSend no devolvió jobId");
    const estado = await mm.send.bulkStatus(domainId, job.jobId);
    assert.equal(estado.id, job.jobId);
    assert.equal(estado.totalRecipients, 2);
    assert.equal(typeof estado.skippedSuppressed, "number");
  });

  it("verify vuelve a preguntarle a SES aunque la base diga que sí", async () => {
    // El bug: con `verified` en la base, la ruta devolvía true sin consultar.
    // Así, un dominio borrado de SES seguía reportándose sano y nadie se
    // enteraba de que llevaba meses sin poder enviar.
    ses.verified = false;
    try {
      const res = await mm.domains.verify(domainId);
      assert.equal(res.verified, false, "verify siguió afirmando que está verificado");
      const guardado = await mm.domains.get(domainId);
      assert.equal(guardado.verified, false, "la bandera de la base no se corrigió");
    } finally {
      ses.verified = true;
      await mm.domains.verify(domainId);
    }
  });

  it("si no se puede consultar a SES, no se desverifica nada", async () => {
    ses.respondio = false;
    ses.verified = false;
    try {
      const res = await mm.domains.verify(domainId);
      assert.equal(res.stale, true, "no marcó la respuesta como último estado conocido");
      assert.equal(res.verified, true, "bajó la bandera por una consulta fallida");
      assert.equal((await mm.domains.get(domainId)).verified, true);
    } finally {
      ses.respondio = true;
      ses.verified = true;
    }
  });

  it("logs y api-keys responden por el camino del SDK", async () => {
    assert.ok(Array.isArray(await mm.logs.list(domainId)));
    assert.ok(Array.isArray(await mm.apiKeys.list()));
  });

  it("domains.get y health no son 404", async () => {
    assert.equal((await mm.domains.get(domainId)).id, domainId);
    assert.ok(await mm.domains.health(domainId));
  });

  it("send acepta `markdown` como cuerpo", async () => {
    enviados.length = 0;
    const res = await mm.send.send(domainId, { to: "a@example.com", subject: "md", markdown: "# Hola" });
    assert.equal(res.ok, true);
    assert.equal(enviados.length, 1);
  });

  it("rules: los cuatro métodos, y un regex peligroso responde 400", async () => {
    const regla = await dev.rules.create(devDomainId, {
      field: "from",
      match: "contains",
      value: "@newsletter.com",
      action: "forward",
      target: "news@example.com",
    });
    assert.ok(regla.id);
    assert.ok((await dev.rules.list(devDomainId)).some((r) => r.id === regla.id));

    const editada = await dev.rules.update(devDomainId, regla.id, { enabled: false });
    assert.equal(editada.enabled, false);

    await assert.rejects(
      () => dev.rules.create(devDomainId, { field: "subject", match: "regex", value: "(a+)+$", action: "discard" }),
      (err: MailMaskError) => err.status === 400
    );

    // `discard` no necesita target
    const sinTarget = await dev.rules.create(devDomainId, { field: "subject", match: "equals", value: "spam", action: "discard" });
    assert.equal(sinTarget.action, "discard");

    await dev.rules.delete(devDomainId, regla.id);
    assert.ok(!(await dev.rules.list(devDomainId)).some((r) => r.id === regla.id));
  });

  it("logs.list manda `limit` al servidor", async () => {
    for (const n of [1, 2]) {
      dbmod.addLog({ domainId, timestamp: new Date().toISOString(), from: "a@x.com", to: `hola@${dominio}`, subject: `log ${n}`, status: "forwarded", forwardedTo: "b@x.com", sizeBytes: 10 });
    }
    assert.ok((await mm.logs.list(domainId)).length >= 2);
    assert.equal((await mm.logs.list(domainId, { limit: 1 })).length, 1);
  });

  it("smtp: list y revoke existen (create pega a IAM, no se prueba aquí)", async () => {
    assert.deepEqual(await dev.smtp.list(devDomainId), []);
    await assert.rejects(
      () => dev.smtp.revoke(devDomainId, "no-existe"),
      (err: MailMaskError) => err.status === 404
    );
    // Básico no tiene SMTP relay: 403, no un error opaco
    await assert.rejects(
      () => mm.smtp.create(domainId, "x"),
      (err: MailMaskError) => err.status === 403 && /Developer/.test(err.message)
    );
  });

  it("domains.create y delete", async () => {
    const { domain } = await dev.domains.create(`nuevo-${suffix}.com`);
    assert.equal(domain.domain, `nuevo-${suffix}.com`);
    assert.equal((await dev.domains.get(domain.id)).id, domain.id);
    const res = await dev.domains.delete(domain.id);
    assert.equal(res.ok, true);
    await assert.rejects(() => dev.domains.get(domain.id), (err: MailMaskError) => err.status === 404);
  });

  it("apiKeys.create devuelve la llave una vez y revoke la invalida", async () => {
    const nueva = await mm.apiKeys.create("rotacion");
    assert.ok(nueva.key.startsWith("mk_"));
    assert.ok(nueva.keyPrefix);
    assert.ok((await mm.apiKeys.list()).some((k) => k.id === nueva.id));
    assert.equal((await mm.apiKeys.revoke(nueva.id)).ok, true);
    assert.ok(!(await mm.apiKeys.list()).some((k) => k.id === nueva.id));
  });

  it("cc, bcc e inReplyTo llegan a SES", async () => {
    enviados.length = 0;
    await mm.send.send(domainId, {
      to: "a@example.com", subject: "copias", html: "<p>x</p>",
      cc: ["b@example.com"], bcc: ["c@example.com"], inReplyTo: "<orig@x>", references: "<orig@x>",
    });
    assert.deepEqual(enviados[0].opts.cc, ["b@example.com"]);
    assert.deepEqual(enviados[0].opts.bcc, ["c@example.com"]);
    assert.equal(enviados[0].opts.inReplyTo, "<orig@x>");
  });

  it("adjunto: upload → send lo manda y lo borra de S3", async () => {
    enviados.length = 0;
    const up = await mm.attachments.upload(domainId, {
      filename: "factura.pdf", contentType: "application/pdf", data: new TextEncoder().encode("%PDF-1.4 fake"),
    });
    assert.ok(up.key);
    assert.ok(archivos.has(up.key));
    await mm.send.send(domainId, { to: "a@example.com", subject: "con adjunto", body: "va", attachments: [up] });
    assert.equal(enviados[0].opts.attachments[0].filename, "factura.pdf");
    assert.equal(enviados[0].opts.attachments[0].contentType, "application/pdf");
    assert.ok(!archivos.has(up.key), "el adjunto debió borrarse tras enviarse");
  });

  it("un .exe no se puede subir", async () => {
    await assert.rejects(
      () => mm.attachments.upload(domainId, { filename: "virus.exe", contentType: "application/octet-stream", data: new Uint8Array([1]) }),
      (err: MailMaskError) => err.status === 415
    );
  });

  it("idempotencia: la misma clave no reenvía ni consume cuota", async () => {
    enviados.length = 0;
    const antes = dbmod.getSendCount(domainId);
    const key = `pedido-${crypto.randomUUID()}`;
    const a = await mm.send.send(domainId, { to: "a@example.com", subject: "idem", body: "x" }, { idempotencyKey: key });
    const b = await mm.send.send(domainId, { to: "a@example.com", subject: "idem", body: "x" }, { idempotencyKey: key });
    assert.equal(a.messageId, b.messageId);
    assert.equal(enviados.length, 1);
    assert.equal(dbmod.getSendCount(domainId), antes + 1);
    await assert.rejects(
      () => mm.send.send(domainId, { to: "a@example.com", subject: "idem", body: "x" }, { idempotencyKey: "k".repeat(129) }),
      (err: MailMaskError) => err.status === 400
    );
  });

  it("supresión: add bloquea el envío con 422, remove lo libera", async () => {
    const victima = `rebotado-${suffix}@example.com`;
    const added = await mm.suppressions.add(domainId, victima);
    assert.equal(added.reason, "manual");
    assert.ok((await mm.suppressions.list(domainId)).some((s) => s.email === victima));
    await assert.rejects(
      () => mm.send.send(domainId, { to: victima, subject: "x", body: "x" }),
      (err: MailMaskError) => err.status === 422
    );
    // También en copia
    await assert.rejects(
      () => mm.send.send(domainId, { to: "ok@example.com", cc: [victima], subject: "x", body: "x" }),
      (err: MailMaskError) => err.status === 422
    );
    assert.equal((await mm.suppressions.remove(domainId, victima)).ok, true);
    await mm.send.send(domainId, { to: victima, subject: "x", body: "x" });
    await assert.rejects(() => mm.suppressions.remove(domainId, victima), (err: MailMaskError) => err.status === 404);
  });

  it("webhooks: Developer crea, Básico recibe 403, URL privada 400", async () => {
    await assert.rejects(
      () => mm.webhooks.create(domainId, { url: "https://example.com/hook", events: ["email.sent"] }),
      (err: MailMaskError) => err.status === 403
    );
    await assert.rejects(
      () => dev.webhooks.create(devDomainId, { url: "https://127.0.0.1/hook", events: ["email.sent"] }),
      (err: MailMaskError) => err.status === 400
    );
    await assert.rejects(
      () => dev.webhooks.create(devDomainId, { url: "http://example.com/hook", events: ["email.sent"] }),
      (err: MailMaskError) => err.status === 400 && /https/.test(err.message)
    );
    await assert.rejects(
      // deno-lint-ignore no-explicit-any
      () => dev.webhooks.create(devDomainId, { url: "https://example.com/hook", events: ["email.exploded" as any] }),
      (err: MailMaskError) => err.status === 400
    );
    const wh = await dev.webhooks.create(devDomainId, { url: "https://example.com/hook", events: ["email.sent", "email.bounced"] });
    assert.ok(wh.secret.startsWith("whsec_"));
    const listado = await dev.webhooks.list(devDomainId);
    assert.ok(listado.some((w) => w.id === wh.id));
    // deno-lint-ignore no-explicit-any
    assert.equal((listado[0] as any).secret, undefined, "el secreto no debe salir en el listado");
    const off = await dev.webhooks.update(devDomainId, wh.id, { enabled: false });
    assert.equal(off.enabled, false);
    assert.equal((await dev.webhooks.delete(devDomainId, wh.id)).ok, true);
  });

  it("un evento delivery de SES dispara email.delivered sin suprimir nada", async () => {
    const wh = await dev.webhooks.create(devDomainId, { url: "https://receptor.example.com/delivered", events: ["email.delivered"] });
    const { registrarEventoSes } = await import("./main.ts");
    const webhooks = await import("./webhooks.ts");
    const r = await registrarEventoSes({
      eventType: "Delivery",
      mail: { source: `hola@sdk-dev-${suffix}.com`, messageId: "m-1", commonHeaders: { subject: "hey" } },
      delivery: { recipients: ["a@example.com"], smtpResponse: "250 OK", processingTimeMillis: 812 },
    });
    assert.equal(r.suppressed, 0);
    assert.equal((await dev.suppressions.list(devDomainId)).length, 0);
    const got: string[] = [];
    await webhooks.deliverPending(50, (async (_u: unknown, init?: RequestInit) => { got.push(String(init!.body)); return new Response("", { status: 200 }); }) as unknown as typeof fetch);
    const ev = got.map((b) => JSON.parse(b)).find((p) => p.event === "email.delivered");
    assert.ok(ev, "no llegó email.delivered");
    assert.equal(ev.data.recipient, "a@example.com");
    assert.equal(ev.data.smtpResponse, "250 OK");
    await dev.webhooks.delete(devDomainId, wh.id);
  });

  it("webhooks: la entrega lleva firma válida y reintenta si falla", async () => {
    const wh = await dev.webhooks.create(devDomainId, { url: "https://receptor.example.com/mailmask", events: ["email.sent"] });
    const webhooks = await import("./webhooks.ts");

    // email.sent lo emite la ruta /send. Developer no tiene add-on pero su plan trae sends.
    await dev.send.send(devDomainId, { to: "a@example.com", subject: "evento", body: "x" });
    // ping explícito
    const t = await dev.webhooks.test(devDomainId, wh.id);
    assert.ok(t.deliveryId);

    const recibidos: { url: string; headers: Record<string, string>; body: string }[] = [];
    let responder = 200;
    const fakeFetch = (async (url: string | URL | Request, init?: RequestInit) => {
      recibidos.push({ url: String(url), headers: init!.headers as Record<string, string>, body: String(init!.body) });
      return new Response("", { status: responder });
    }) as unknown as typeof fetch;

    const r1 = await webhooks.deliverPending(50, fakeFetch);
    assert.ok(r1.delivered >= 2, `esperaba al menos 2 entregas, hubo ${r1.delivered}`);
    const ping = recibidos.find((r) => r.headers["x-mailmask-event"] === "ping")!;
    assert.ok(ping, "no llegó el ping");
    assert.equal(ping.url, "https://receptor.example.com/mailmask");
    assert.equal(await verifyWebhookSignature(wh.secret, { signature: ping.headers["x-mailmask-signature"], timestamp: ping.headers["x-mailmask-timestamp"] }, ping.body), true);
    assert.equal(await verifyWebhookSignature("otro-secreto", { signature: ping.headers["x-mailmask-signature"], timestamp: ping.headers["x-mailmask-timestamp"] }, ping.body), false);
    const sent = recibidos.find((r) => r.headers["x-mailmask-event"] === "email.sent")!;
    assert.equal(JSON.parse(sent.body).data.to, "a@example.com");

    // Fallo → queda pendiente con reintento futuro
    responder = 500;
    await dev.webhooks.test(devDomainId, wh.id);
    const r2 = await webhooks.deliverPending(50, fakeFetch);
    assert.equal(r2.retried, 1);
    const entregas = await dev.webhooks.deliveries(devDomainId, wh.id);
    const pendiente = entregas.find((d) => d.status === "pending")!;
    assert.equal(pendiente.attempts, 1);
    assert.equal(pendiente.lastStatusCode, 500);
    assert.ok(pendiente.nextAt > new Date().toISOString());
    assert.ok(entregas.filter((d) => d.status === "delivered").length >= 2);
  });

  it("los envíos por API quedan en logs y el evento de SES los mueve a entregado/rebotado", async () => {
    const res = await mm.send.send(domainId, { to: "acuse@example.com", subject: "con acuse", body: "x" });
    assert.ok(res.sesMessageId, "send debe devolver el id de SES");
    const fila = () => mm.logs.list(domainId).then((ls) => ls.find((l) => l.sesMessageId === res.sesMessageId)!);
    assert.equal((await fila()).status, "sent");

    const { registrarEventoSes } = await import("./main.ts");
    await registrarEventoSes({ eventType: "Delivery", mail: { messageId: res.sesMessageId, source: `noreply@${dominio}` }, delivery: { recipients: ["acuse@example.com"], smtpResponse: "250 OK" } });
    assert.equal((await fila()).status, "delivered");

    await registrarEventoSes({ eventType: "Bounce", mail: { messageId: res.sesMessageId, source: `noreply@${dominio}` }, bounce: { bounceType: "Permanent", bounceSubType: "General", bouncedRecipients: [{ emailAddress: "acuse@example.com", diagnosticCode: "550 5.1.1" }] } });
    const rebotada = await fila();
    assert.equal(rebotada.status, "bounced");
    assert.match(rebotada.error ?? "", /550/);
    // y el destinatario quedó suprimido
    assert.ok((await mm.suppressions.list(domainId)).some((s) => s.email === "acuse@example.com"));
    await mm.suppressions.remove(domainId, "acuse@example.com");
  });
});
