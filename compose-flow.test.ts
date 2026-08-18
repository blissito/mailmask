// El camino feliz de "redactar" necesita que SES responda, y en los tests AWS_ENDPOINT_URL
// apunta a un puerto muerto. Este archivo va aparte porque el mock del módulo tiene que
// instalarse ANTES de que main.ts cargue ses.ts — por eso main.ts se importa dinámicamente.
import { describe, it, before, mock } from "node:test";
import assert from "node:assert/strict";

const suffix = Date.now();
const sent: { from: string; to: string; subject: string; body: string; opts?: Record<string, unknown> }[] = [];

describe("Bandeja: redactar — camino feliz", () => {
  // deno-lint-ignore no-explicit-any
  let app: any;
  // deno-lint-ignore no-explicit-any
  let dbmod: any;
  let sqlite: ReturnType<typeof import("./pg.ts").sqlite.prepare> extends never ? never : import("better-sqlite3").Database;
  const email = `composeok-${suffix}@example.com`;
  let cookie = "";
  let csrf = "";
  let domainId = "";

  before(async () => {
    const realSes = await import("./ses.ts");
    mock.module("./ses.ts", {
      namedExports: {
        ...realSes,
        // El 4º argumento es la parte text/plain. Se captura porque durante meses fue
        // `(textBody ?? html)`: al mandar sólo HTML, el marcado crudo viajaba como
        // texto plano y quien leyera en modo texto veía etiquetas.
        sendFromDomain: async (from: string, to: string, subject: string, body: string, opts?: Record<string, unknown>) => {
          sent.push({ from, to, subject, body, opts });
          return `<stub-${crypto.randomUUID()}@test>`;
        },
      },
    });

    ({ app } = await import("./main.ts"));
    dbmod = await import("./db.ts");
    ({ sqlite } = await import("./pg.ts"));
    const { hashPassword } = await import("./auth.ts");

    sqlite.prepare("DELETE FROM rate_limits").run();
    dbmod.createUser(email, await hashPassword("password123"));
    await dbmod.updateUserSubscription(email, {
      plan: "basico",
      status: "active",
      mpSubscriptionId: `sub-composeok-${suffix}`,
      currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString(),
    });
    const addon = dbmod.createAddon(email, "sends100");
    dbmod.updateAddon(addon.id, { status: "active", currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString() });

    const loginRes = await app.fetch(new Request("http://localhost/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json", "x-forwarded-for": "10.9.9.9" },
      body: JSON.stringify({ email, password: "password123" }),
    }));
    for (const sc of loginRes.headers.getSetCookie?.() ?? []) {
      const t = sc.match(/(?:^|[\s,])token=([^;,]+)/);
      if (t && !cookie) cookie = `token=${t[1]}`;
      const c = sc.match(/csrf_token=([^;,]+)/);
      if (c && !csrf) csrf = c[1];
    }
    await loginRes.body?.cancel();

    const dom = dbmod.createDomain(email, `composeok-${suffix}.com`, ["dk"], "vf");
    domainId = dom.id;
    sqlite.prepare("UPDATE domains SET verified = 1 WHERE id = ?").run(domainId);
    dbmod.createAlias(domainId, "hola", ["destino@example.com"]);
  });

  const compose = (over: Record<string, unknown> = {}) =>
    app.fetch(new Request("http://localhost/api/bandeja/conversations", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": `10.9.9.${Math.floor(Math.random() * 200) + 10}`,
        cookie: `${cookie}; csrf_token=${csrf}`,
        "x-csrf-token": csrf,
      },
      body: JSON.stringify({
        domainId, to: "cliente@example.com", subject: "Cotización",
        body: "Hola, va la propuesta.", fromAlias: "hola", ...over,
      }),
    }));

  it("crea la conversación con la convención invertida y el messageId en threadRefs", async () => {
    const before_ = dbmod.getSendCount(domainId);
    const res = await compose();
    assert.equal(res.status, 201);
    const data = await res.json();

    const conv = dbmod.getConversation(domainId, data.conversationId);
    // from = contacto externo, to = nuestro alias. Invertirlo rompería renderList,
    // el filtro de alias y el remitente del reply posterior (conv.to.split("@")[0]).
    assert.equal(conv.from, "cliente@example.com");
    assert.equal(conv.to, `hola@composeok-${suffix}.com`);
    assert.equal(conv.messageCount, 1);
    assert.equal(conv.status, "open");
    // Lo que engancha la respuesta del contacto en este mismo hilo.
    assert.deepEqual(conv.threadReferences, [data.messageId]);

    const msgs = dbmod.listMessages(conv.id);
    assert.equal(msgs.length, 1);
    assert.equal(msgs[0].direction, "outbound");
    assert.equal(msgs[0].from, `hola@composeok-${suffix}.com`);

    // El primer mensaje del hilo no lleva In-Reply-To/References.
    const last = sent[sent.length - 1];
    assert.equal(last.from, `hola@composeok-${suffix}.com`);
    assert.equal(last.to, "cliente@example.com");
    assert.equal(last.opts?.inReplyTo, undefined);
    assert.equal(last.opts?.references, undefined);

    assert.equal(dbmod.getSendCount(domainId), before_ + 1, "debe consumir exactamente un envío");
  });

  it("el reply posterior sale desde el mismo alias", async () => {
    const res = await compose({ subject: "Segundo hilo" });
    const { conversationId } = await res.json();

    const replyRes = await app.fetch(new Request(`http://localhost/api/bandeja/conversations/${conversationId}/reply`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": "10.9.9.77",
        cookie: `${cookie}; csrf_token=${csrf}`,
        "x-csrf-token": csrf,
      },
      body: JSON.stringify({ domainId, body: "seguimiento" }),
    }));
    assert.equal(replyRes.status, 200);
    await replyRes.body?.cancel();

    const last = sent[sent.length - 1];
    assert.equal(last.from, `hola@composeok-${suffix}.com`, "el reply debe salir del alias, no de noreply@");
    assert.equal(last.to, "cliente@example.com");
    assert.match(last.subject, /^Re: /);
    assert.ok(last.opts?.inReplyTo, "el reply sí debe referenciar el mensaje anterior");
  });

  it("con markdown, la parte de texto es texto y la de HTML es HTML", async () => {
    const res = await compose({
      subject: "Con formato",
      body: undefined,
      markdown: "Hola **Brenda**\n\n- uno\n- dos",
    });
    assert.equal(res.status, 201);
    await res.body?.cancel();

    const last = sent[sent.length - 1];
    // La parte text/plain no puede llevar marcado: es lo que lee quien tiene el
    // cliente en modo texto.
    assert.ok(!last.body.includes("<"), `la parte de texto trae etiquetas: ${last.body}`);
    assert.match(last.body, /Hola \*\*Brenda\*\*/);

    const html = last.opts?.html as string;
    assert.ok(html, "debe ir una parte text/html");
    assert.notEqual(html, last.body, "las dos partes no pueden ser idénticas");
    assert.match(html, /<strong/i);
    assert.match(html, /<li/i);
    // Outlook renderiza con el motor de Word: sin flexbox ni grid.
    assert.ok(!/display:\s*(flex|grid)/i.test(html));
    // Gmail recorta el head en mensajes largos y se llevaría el <style>.
    assert.ok(!/<style[\s>]/i.test(html));
  });

  it("con html crudo se deriva el texto plano en vez de repetir el marcado", async () => {
    const res = await compose({
      subject: "Desde el SDK",
      body: undefined,
      html: "<p>Hola <b>mundo</b></p>",
    });
    assert.equal(res.status, 201);
    await res.body?.cancel();

    const last = sent[sent.length - 1];
    assert.ok(!last.body.includes("<"), `la parte de texto trae etiquetas: ${last.body}`);
    assert.match(last.body, /Hola mundo/);
  });

  it("responder no consume la cuota de envíos", async () => {
    const res = await compose({ subject: "Tercer hilo" });
    const { conversationId } = await res.json();
    const afterCompose = dbmod.getSendCount(domainId);

    const replyRes = await app.fetch(new Request(`http://localhost/api/bandeja/conversations/${conversationId}/reply`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": "10.9.9.78",
        cookie: `${cookie}; csrf_token=${csrf}`,
        "x-csrf-token": csrf,
      },
      body: JSON.stringify({ domainId, body: "otra respuesta" }),
    }));
    assert.equal(replyRes.status, 200);
    await replyRes.body?.cancel();

    // La Bandeja se vende incluida: responder no debe gastar el add-on.
    assert.equal(dbmod.getSendCount(domainId), afterCompose);
  });
});
