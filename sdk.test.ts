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

import { MailMask, MailMaskError } from "./sdk/src/index.js";

const suffix = Date.now();
const enviados: { from: string; to: string; subject: string }[] = [];

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
  let domainId = "";

  before(async () => {
    const realSes = await import("./ses.ts");
    mock.module("./ses.ts", {
      namedExports: {
        ...realSes,
        sendFromDomain: async (from: string, to: string, subject: string) => {
          enviados.push({ from, to, subject });
          return `<stub-${crypto.randomUUID()}@test>`;
        },
        checkDomainStatus: async () => ({ ...ses }),
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

    const alta = async (correo: string, conEnvios: boolean) => {
      dbmod.createUser(correo, await (await import("./auth.ts")).hashPassword("password123"));
      await dbmod.updateUserSubscription(correo, {
        plan: "basico",
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
});
