import { describe, it, before } from "node:test";
import assert from "node:assert/strict";

import {
  getUser,
  getUserPlanLimits,
  createAddon,
  updateAddon,
  getAddonById,
  getAddonByMpId,
  listEffectiveAddons,
  ADDONS,
  PLANS,
} from "./db.ts";
import { sqlite } from "./pg.ts";

const FUTURE = new Date(Date.now() + 30 * 864e5).toISOString();
const PAST = new Date(Date.now() - 864e5).toISOString();

function seedUser(email: string, plan: string) {
  sqlite
    .prepare(
      "INSERT OR REPLACE INTO users (email,password_hash,created_at,sub_plan,sub_status,sub_period_end) VALUES (?,?,?,?,?,?)",
    )
    .run(email, "x", new Date().toISOString(), plan, "active", FUTURE);
}

function limitsOf(email: string) {
  return getUserPlanLimits(getUser(email)!);
}

describe("Add-ons: límites", () => {
  const basico = `addon-basico-${crypto.randomUUID()}@test.com`;
  const free = `addon-free-${crypto.randomUUID()}@test.com`;

  before(() => {
    seedUser(basico, "basico");
    seedUser(free, "freelancer");
  });

  it("básico sin add-on no puede enviar", () => {
    const l = limitsOf(basico);
    assert.equal(l.sends, 0);
    assert.equal(l.sendsUnlocked, false);
    assert.equal(l.domains, 1);
  });

  it("un add-on pending todavía no otorga nada", () => {
    const a = createAddon(basico, "sends100");
    const l = limitsOf(basico);
    assert.equal(l.sendsUnlocked, false);
    updateAddon(a.id, { status: "expired" }); // limpieza
  });

  it("add-on de envíos activo desbloquea y fija el tope", () => {
    const a = createAddon(basico, "sends100");
    updateAddon(a.id, { status: "active", currentPeriodEnd: FUTURE });
    const l = limitsOf(basico);
    assert.equal(l.sends, 100);
    assert.equal(l.sendsUnlocked, true);
    updateAddon(a.id, { status: "expired" });
  });

  it("add-ons de dominio se acumulan", () => {
    const d1 = createAddon(basico, "domain");
    const d2 = createAddon(basico, "domain");
    updateAddon(d1.id, { status: "active", currentPeriodEnd: FUTURE });
    updateAddon(d2.id, { status: "active", currentPeriodEnd: FUTURE });
    assert.equal(limitsOf(basico).domains, PLANS.basico.domains + 2);
    updateAddon(d1.id, { status: "expired" });
    updateAddon(d2.id, { status: "expired" });
  });

  it("un add-on menor nunca reduce los envíos del plan", () => {
    const a = createAddon(free, "sends25");
    updateAddon(a.id, { status: "active", currentPeriodEnd: FUTURE });
    const l = limitsOf(free);
    assert.equal(l.sends, PLANS.freelancer.sends, "Math.max debe conservar los 200 del plan");
    assert.equal(l.sendsUnlocked, true);
    updateAddon(a.id, { status: "expired" });
  });

  it("cancelado sigue valiendo hasta terminar el periodo pagado", () => {
    const a = createAddon(basico, "sends25");
    updateAddon(a.id, { status: "cancelled", currentPeriodEnd: FUTURE });
    assert.equal(limitsOf(basico).sendsUnlocked, true);

    updateAddon(a.id, { currentPeriodEnd: PAST });
    assert.equal(limitsOf(basico).sendsUnlocked, false, "vencido ya no otorga");
    updateAddon(a.id, { status: "expired" });
  });

  it("sin plan base los add-ons no otorgan nada", () => {
    const orphan = `addon-orphan-${crypto.randomUUID()}@test.com`;
    seedUser(orphan, "basico");
    sqlite.prepare("UPDATE users SET sub_period_end = ? WHERE email = ?").run(PAST, orphan);
    const a = createAddon(orphan, "sends100");
    updateAddon(a.id, { status: "active", currentPeriodEnd: FUTURE });
    const l = limitsOf(orphan);
    assert.equal(l.sends, 0);
    assert.equal(l.sendsUnlocked, false);
    assert.equal(l.domains, 0);
  });
});

describe("Add-ons: lookup y precios", () => {
  const email = `addon-lookup-${crypto.randomUUID()}@test.com`;

  before(() => seedUser(email, "basico"));

  it("se encuentra por id y por preapproval de MP", () => {
    const a = createAddon(email, "domain");
    assert.equal(getAddonById(a.id)?.kind, "domain");

    const mpId = `mp-${crypto.randomUUID()}`;
    updateAddon(a.id, { status: "active", mpPreapprovalId: mpId, currentPeriodEnd: FUTURE });
    assert.equal(getAddonByMpId(mpId)?.id, a.id);
  });

  it("guarda el precio del catálogo", () => {
    const a = createAddon(email, "sends100");
    assert.equal(a.priceCents, ADDONS.sends100.price);
    assert.equal(a.status, "pending");
    updateAddon(a.id, { status: "expired" });
  });

  it("listEffectiveAddons ignora pending y expired", () => {
    const p = createAddon(email, "sends25");
    const e = createAddon(email, "sends25");
    updateAddon(e.id, { status: "expired" });
    const kinds = listEffectiveAddons(email).map((x) => x.id);
    assert.ok(!kinds.includes(p.id), "pending no cuenta");
    assert.ok(!kinds.includes(e.id), "expired no cuenta");
  });
});

// La regresión que más duele: un preapproval de add-on de $49 tiene el mismo monto que
// el plan básico. Si el webhook no sale por la rama de add-on, el fallback por monto lo
// activaría como plan y sobrescribiría subPlan/subMpId del usuario.
describe("Add-ons: aislamiento del webhook", () => {
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  it("el external_reference de add-on no se confunde con guest checkout", () => {
    const ref = `addon:${crypto.randomUUID()}`;
    assert.ok(ref.startsWith("addon:"));
    assert.equal(UUID_RE.test(ref), false, "no debe entrar por el path de guest");
    assert.ok(!ref.includes("@"), "no debe parecer un email");
  });

  it("el reason del add-on no dispara la detección de plan", () => {
    for (const kind of Object.keys(ADDONS) as (keyof typeof ADDONS)[]) {
      const reason = `MailMask — Add-on ${ADDONS[kind].label}`;
      assert.equal(reason.match(/Plan (\w+)/i), null, `"${reason}" no debe contener "Plan X"`);
    }
  });

  it("el add-on de envíos cuesta lo mismo que el plan básico", () => {
    // Documenta por qué la rama temprana del webhook es obligatoria y no una optimización.
    assert.equal(ADDONS.sends25.price, PLANS.basico.price);
  });
});

// La lista de supresión se llavea en minúsculas al escribir y al leer: SES entrega los
// bounces con las mayúsculas originales y SQLite compara sensible a mayúsculas.
describe("Supresión: matching insensible a mayúsculas", () => {
  it("un email guardado con mayúsculas se detecta en minúsculas", async () => {
    const { addSuppression, isSuppressed, createDomain, createUser } = await import("./db.ts");
    const email = `supp-${crypto.randomUUID()}@test.com`;
    createUser(email, "x");
    const dom = createDomain(email, `supp-${Date.now()}.com`, ["dk"], "vf");

    addSuppression(dom.id, "Cliente.VIP@Empresa.com", "bounce:Permanent");
    assert.equal(isSuppressed(dom.id, "cliente.vip@empresa.com"), true);
    assert.equal(isSuppressed(dom.id, "Cliente.VIP@Empresa.com"), true);
    assert.equal(isSuppressed(dom.id, "  CLIENTE.VIP@EMPRESA.COM  "), true);
    assert.equal(isSuppressed(dom.id, "otro@empresa.com"), false);
  });
});

/**
 * El buzón IMAP es un add-on por dominio con una bolsa de almacenamiento COMPARTIDA
 * entre todos los buzones de ese dominio, y buzones ilimitados. Es el diferenciador
 * aplicado al correo: Google cobra por persona, ForwardEmail por buzón, MailMask por
 * dominio. Ningún plan lo incluye, a propósito — meter un recurso sin medidor en una
 * cuota fija ya salió caro una vez, y por eso existe `monthlyForwards`.
 */
describe("Add-on de buzón IMAP", () => {
  const sinAddon = `buzon-sin-${crypto.randomUUID()}@test.com`;
  const conUno = `buzon-uno-${crypto.randomUUID()}@test.com`;
  const conDos = `buzon-dos-${crypto.randomUUID()}@test.com`;
  const equipo = `buzon-equipo-${crypto.randomUUID()}@test.com`;

  const GB = 1024 * 1024 * 1024;

  before(() => {
    seedUser(sinAddon, "basico");
    seedUser(conUno, "basico");
    seedUser(conDos, "basico");
    seedUser(equipo, "equipo");

    for (const email of [conUno, conDos]) {
      const a = createAddon(email, "mailbox");
      updateAddon(a.id, { status: "active", currentPeriodEnd: FUTURE });
    }
    const extra = createAddon(conDos, "mailbox");
    updateAddon(extra.id, { status: "active", currentPeriodEnd: FUTURE });
  });

  it("sin el add-on no hay buzones, ni en Básico ni en Equipo", () => {
    assert.equal(limitsOf(sinAddon).mailboxes, false);
    assert.equal(limitsOf(sinAddon).mailboxBytes, 0);
    // Equipo tampoco lo incluye: el almacenamiento crece solo y nunca baja.
    assert.equal(limitsOf(equipo).mailboxes, false);
    assert.equal(limitsOf(equipo).mailboxBytes, 0);
  });

  it("un add-on da 10 GB", () => {
    const l = limitsOf(conUno);
    assert.equal(l.mailboxes, true);
    assert.equal(l.mailboxBytes, 10 * GB);
  });

  it("es acumulable: dos add-ons son 20 GB", () => {
    assert.equal(limitsOf(conDos).mailboxBytes, 20 * GB);
  });

  it("cuesta $99 y está en el catálogo a la venta", () => {
    assert.equal(ADDONS.mailbox.price, 99_00);
    assert.equal(ADDONS.mailbox.mailboxBytes, 10 * GB);
  });

  it("con el plan vencido no quedan buzones habilitados", () => {
    // El add-on sigue vivo pero el plan base no: el cron lo congela con 30 días de
    // gracia. Lo que NO puede pasar es que siga contando como capacidad disponible.
    const vencido = `buzon-vencido-${crypto.randomUUID()}@test.com`;
    sqlite.prepare(
      "INSERT OR REPLACE INTO users (email,password_hash,created_at,sub_plan,sub_status,sub_period_end) VALUES (?,?,?,?,?,?)",
    ).run(vencido, "x", new Date().toISOString(), "basico", "active", PAST);
    const a = createAddon(vencido, "mailbox");
    updateAddon(a.id, { status: "active", currentPeriodEnd: FUTURE });

    assert.equal(limitsOf(vencido).mailboxes, false);
    assert.equal(limitsOf(vencido).mailboxBytes, 0);
  });
});
