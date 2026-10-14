// Reconciliación de add-ons `pending` contra MercadoPago (addon-sync.ts).
//
// Es la red de seguridad del 13-ago-2026: la clienta pagó, MP dejó el preapproval
// `authorized` y nunca avisó por webhook, así que la cuenta siguió sin poder enviar. Lo que
// este archivo fija es que la reconciliación activa lo que MP confirma UNA vez —no dos— y
// que no toca nada cuando MP duda, cuando contesta mal o cuando el webhook se adelantó.
//
// Nada sale a la red: `./emails.ts` va doblado con `mock.module` (el `sendTemplate` de
// verdad manda por SES, que en pruebas apunta a `localhost:1`, y eso dispara `sendAlert`) y
// `fetch` es una tabla. `addon-sync.ts` se importa en caliente dentro de `before()`: es lo
// único que hace que los dobles lo intercepten (docs/agents/pruebas-mocks.md).

import { describe, it, before, beforeEach, afterEach, mock } from "node:test";
import assert from "node:assert/strict";

/** Los recibos que la corrida quiso mandar: aquí sólo se cuentan. */
const recibos: { to: string; subject: string }[] = [];
const sendTemplate = async (to: string, email: { subject: string }): Promise<string> => {
  recibos.push({ to, subject: email.subject });
  return "<recibo@test>";
};

/** Lo que MercadoPago contesta por preapproval. Un id que no está en la tabla da 404. */
interface RespuestaMp {
  status?: string;
  amount?: number;
  currency?: string;
  dateCreated?: string;
  /** Si viene, la consulta falla con ese HTTP (`ok: false`) en vez de contestar JSON. */
  http?: number;
}
const mp = new Map<string, RespuestaMp>();
/** Las URLs que se consultaron de verdad, en orden. */
const consultadas: string[] = [];
/** Qué hacer justo cuando llega una consulta (la carrera con el webhook). */
let alConsultar: ((preapprovalId: string) => void) | null = null;

const MP = "https://api.mercadopago.com/preapproval/";

const fetchFalso = async (url: unknown): Promise<Response> => {
  const destino = String(url);
  if (!destino.startsWith(MP)) throw new Error(`fetch inesperado en la prueba: ${destino}`);
  consultadas.push(destino);
  const id = decodeURIComponent(destino.slice(MP.length));
  alConsultar?.(id);
  const r = mp.get(id);
  if (!r) return new Response("{}", { status: 404 });
  // Fiel a la verdad: un HTTP de error NO lanza, contesta. Lanzar aquí ejercería el `catch`
  // externo de la corrida, que es otro camino.
  if (r.http) return new Response("boom", { status: r.http });
  return new Response(
    JSON.stringify({
      status: r.status,
      auto_recurring:
        r.amount === undefined ? undefined : { transaction_amount: r.amount, currency_id: r.currency ?? "MXN" },
      date_created: r.dateCreated,
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
};

const DIA = 864e5;
/** El fin de periodo se calcula con `setDate(+35)` en hora local: este margen cubre zona y DST. */
const MARGEN = 3600_000;

describe("addon-sync: reconciliación de add-ons pendientes", () => {
  // deno-lint-ignore no-explicit-any
  let DB: any, sync: any, sqlite: any;

  before(async () => {
    const emailsReales = await import("./emails.ts");
    mock.module("./emails.ts", { namedExports: { ...emailsReales, sendTemplate } });
    DB = await import("./db.ts");
    sqlite = (await import("./pg.ts")).sqlite;
    sync = await import("./addon-sync.ts");
  });

  beforeEach(() => {
    recibos.length = 0;
    consultadas.length = 0;
    mp.clear();
    alConsultar = null;
    mock.method(globalThis, "fetch", fetchFalso);
    // La base es UNA para toda la suite y `reconcilePendingAddons` barre la tabla entera, no
    // «los tuyos»: los add-ons que deja `pending` un caso anterior se volverían a consultar
    // en el siguiente. Se apagan aquí para que cada caso vea sólo lo suyo.
    sqlite
      .prepare("UPDATE addons SET status = 'expired' WHERE status = 'pending' AND mp_preapproval_id IS NOT NULL")
      .run();
  });

  afterEach(() => {
    mock.restoreAll();
  });

  /** Un add-on `pending` con su preapproval y con dueño propio (la base es compartida). */
  function pendiente(kind = "storage50") {
    const email = `addon-sync-${crypto.randomUUID().slice(0, 8)}@test.com`;
    DB.createUser(email, "x");
    const addon = DB.createAddon(email, kind);
    const mpId = `mp-${crypto.randomUUID()}`;
    DB.updateAddon(addon.id, { mpPreapprovalId: mpId });
    return { email, addonId: addon.id, mpId, kind };
  }

  const consultasA = (mpId: string) => consultadas.filter((u) => u.endsWith(`/preapproval/${mpId}`)).length;
  const recibosDe = (email: string) => recibos.filter((r) => r.to === email);
  const ordenesDe = (addonId: string) => DB.listOrdersForSubject("addon", addonId);

  it("un add-on que MP reporta autorizado queda activo 35 días, con una orden y su recibo", async () => {
    const x = pendiente();
    const dateCreated = "2026-08-13T17:04:11.000Z";
    mp.set(x.mpId, { status: "authorized", amount: 49, currency: "MXN", dateCreated });

    const antes = Date.now();
    await sync.reconcilePendingAddons();
    const despues = Date.now();

    const addon = DB.getAddonById(x.addonId);
    assert.equal(addon.status, "active");
    const fin = new Date(addon.currentPeriodEnd).getTime();
    assert.ok(
      fin >= antes + 35 * DIA - MARGEN && fin <= despues + 35 * DIA + MARGEN,
      `el periodo tiene que ser de 35 días, no ${addon.currentPeriodEnd}`,
    );

    const orden = DB.getOrderByEventKey(`addon-activate:${x.addonId}`);
    assert.ok(orden, "el add-on activado tiene que dejar su asiento en el libro mayor");
    assert.equal(orden.amountCents, 4900, "el monto lo manda MP, no el catálogo");
    assert.equal(orden.currency, "MXN");
    assert.equal(orden.subject, "addon");
    assert.equal(orden.subjectId, x.addonId);
    assert.equal(orden.listPriceCents, addon.priceCents);
    assert.equal(orden.periodEnd, addon.currentPeriodEnd);
    assert.equal(orden.mpPreapprovalId, x.mpId);
    assert.equal(orden.mpStatus, "authorized");
    assert.equal(orden.occurredAt, dateCreated, "el asiento se fecha cuando MP lo creó");
    assert.equal(ordenesDe(x.addonId).length, 1, "una sola orden por add-on");
    assert.equal(recibosDe(x.email).length, 1, "un solo recibo");
  });

  it("si MP dice otro estado o contesta 500, sigue pendiente y sin orden ni recibo", async () => {
    const pausado = pendiente();
    mp.set(pausado.mpId, { status: "paused" });
    const enCurso = pendiente();
    mp.set(enCurso.mpId, { status: "pending" });
    const roto = pendiente();
    mp.set(roto.mpId, { http: 500 });

    await sync.reconcilePendingAddons();

    for (const x of [pausado, enCurso, roto]) {
      assert.equal(DB.getAddonById(x.addonId).status, "pending", `sigue pendiente: ${x.mpId}`);
      assert.equal(DB.getOrderByEventKey(`addon-activate:${x.addonId}`), null, `sin orden: ${x.mpId}`);
      assert.equal(ordenesDe(x.addonId).length, 0, `sin asiento: ${x.mpId}`);
      assert.equal(recibosDe(x.email).length, 0, `sin recibo: ${x.mpId}`);
    }
  });

  it("si el webhook lo activó mientras se consultaba, no le cambia nada", async () => {
    const x = pendiente();
    mp.set(x.mpId, { status: "authorized", amount: 49, currency: "MXN" });
    const delWebhook = new Date(Date.now() + 10 * DIA).toISOString();
    // El webhook gana la carrera entre la respuesta de MP y la relectura del add-on.
    alConsultar = (id) => {
      if (id === x.mpId) DB.updateAddon(x.addonId, { status: "active", currentPeriodEnd: delWebhook });
    };

    await sync.reconcilePendingAddons();

    const addon = DB.getAddonById(x.addonId);
    assert.equal(addon.status, "active");
    assert.equal(addon.currentPeriodEnd, delWebhook, "el periodo que puso el webhook queda intacto");
    assert.equal(ordenesDe(x.addonId).length, 0, "el cobro lo asentó el webhook: aquí no hay asiento");
    assert.equal(recibosDe(x.email).length, 0, "y el recibo también lo mandó él");
  });

  it("si ya existe la orden del webhook, activa pero no crea otra ni manda otro recibo", async () => {
    const x = pendiente();
    mp.set(x.mpId, { status: "authorized", amount: 49, currency: "MXN" });
    // El webhook llegó primero y asentó el cobro con la MISMA eventKey; el add-on se quedó
    // `pending` porque a él le tocó otra cosa. `recordOrder` es la compuerta.
    const previa = DB.recordOrder({
      userEmail: x.email,
      kind: "charge",
      subject: "addon",
      subjectId: x.addonId,
      subjectKey: x.kind,
      description: "Add-on +50 GB de buzón",
      amountCents: 4900,
      currency: "MXN",
      eventKey: `addon-activate:${x.addonId}`,
    });
    assert.ok(previa, "la orden previa tiene que existir");

    await sync.reconcilePendingAddons();

    assert.equal(DB.getAddonById(x.addonId).status, "active", "el servicio sí se da: el webhook no activó nada");
    assert.equal(ordenesDe(x.addonId).length, 1, "recordOrder devuelve null: no hay segundo asiento");
    assert.equal(DB.getOrderByEventKey(`addon-activate:${x.addonId}`).id, previa.id);
    assert.equal(recibosDe(x.email).length, 0, "el recibo ya salió con el webhook");
  });

  it("correrla dos veces seguidas deja una sola orden y no vuelve a consultar ese add-on", async () => {
    const x = pendiente();
    mp.set(x.mpId, { status: "authorized", amount: 49, currency: "MXN" });

    await sync.reconcilePendingAddons();
    const trasLaPrimera = consultasA(x.mpId);
    await sync.reconcilePendingAddons();

    assert.equal(trasLaPrimera, 1);
    assert.equal(consultasA(x.mpId), 1, "ya no está `pending`: la segunda corrida ni lo mira");
    assert.equal(ordenesDe(x.addonId).length, 1);
    assert.equal(recibosDe(x.email).length, 1);
  });

  it("sin token de MercadoPago no consulta nada ni toca el add-on", async () => {
    const x = pendiente();
    mp.set(x.mpId, { status: "authorized", amount: 49, currency: "MXN" });
    const guardado = process.env.MP_ACCESS_TOKEN;
    try {
      delete process.env.MP_ACCESS_TOKEN;
      await sync.reconcilePendingAddons();
    } finally {
      if (guardado === undefined) delete process.env.MP_ACCESS_TOKEN;
      else process.env.MP_ACCESS_TOKEN = guardado;
    }

    assert.equal(consultadas.length, 0, "ni siquiera se asoma a MP");
    assert.equal(DB.getAddonById(x.addonId).status, "pending");
    assert.equal(DB.getOrderByEventKey(`addon-activate:${x.addonId}`), null);
    assert.equal(recibosDe(x.email).length, 0);
  });
});
