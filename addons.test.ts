import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import {
  getUser,
  createUser,
  createDomain,
  createAddon,
  updateAddon,
  getAddonById,
  getAddonByMpId,
  listEffectiveAddons,
  listEffectiveAddonsForDomain,
  derechosDeDominio,
  derechosPorDominioId,
  createCourtesyAddon,
  updateUserSubscription,
  ADDONS,
  ADDONS_FOR_SALE,
  DOMINIO_ACTIVADO,
  DOMINIO_GRATIS,
} from "./db.ts";
import { sqlite } from "./pg.ts";

const FUTURE = new Date(Date.now() + 30 * 864e5).toISOString();
const PAST = new Date(Date.now() - 864e5).toISOString();
const GB = 1024 * 1024 * 1024;

/** Cuenta gratis, sin nada. Es el caso NORMAL desde el 7-sep-2026, no el de castigo. */
function cuenta(prefijo: string) {
  const email = `${prefijo}-${crypto.randomUUID()}@test.com`;
  createUser(email, "x");
  return email;
}
function dominio(email: string, nombre = `d-${crypto.randomUUID().slice(0, 8)}.test`) {
  return createDomain(email, nombre, ["dk"], "vf");
}
function activar(email: string, domainId: string) {
  const a = createAddon(email, "domain", domainId);
  updateAddon(a.id, { status: "active", currentPeriodEnd: FUTURE });
  return a;
}
const derechos = (domainId: string) => derechosPorDominioId(domainId)!;

/**
 * Todas las cuentas son gratis y se compran tres cosas por dominio, todas a $99. Lo que
 * este archivo fija es la tabla de precios en código: quién reenvía, quién envía, quién
 * tiene equipo y buzones, y que el 2.º dominio sin pagar es el único que se frena.
 */
describe("Derechos por dominio: gratis", () => {
  it("el primer dominio es gratis y reenvía", () => {
    const email = cuenta("free");
    const d = dominio(email);
    const r = derechos(d.id);
    assert.equal(r.esGratis, true);
    assert.equal(r.activado, false);
    assert.equal(r.bloqueado, false, "el gratis NUNCA se bloquea");
    assert.equal(r.aliases, DOMINIO_GRATIS.aliases);
    assert.equal(r.forwardPerHour, DOMINIO_GRATIS.forwardPerHour);
    assert.equal(r.monthlyForwards, DOMINIO_GRATIS.monthlyForwards);
  });

  it("responde desde la Bandeja pero no inicia correo", () => {
    const email = cuenta("free");
    const r = derechos(dominio(email).id);
    assert.equal(r.mesaActions, true);
    assert.equal(r.sends, 0);
    assert.equal(r.sendsUnlocked, false);
    assert.equal(r.mailboxes, false);
    assert.equal(r.agentes, 0);
    assert.equal(r.rules, false);
    assert.equal(r.webhooks, false);
    assert.equal(r.smtpRelay, false);
    assert.equal(r.api, true, "la API es para todos");
  });

  it("la Bandeja del gratis muestra 7 días y el registro dura 7", () => {
    const email = cuenta("free");
    const r = derechos(dominio(email).id);
    assert.equal(r.retencionDias, 7);
    assert.equal(r.logDays, 7);
  });

  it("el 2.º dominio sin pagar queda bloqueado; el 1.º sigue gratis", () => {
    const email = cuenta("free");
    const d1 = dominio(email);
    // created_at es la llave del "más antiguo": se separa un ms para que el orden sea real.
    sqlite.prepare("UPDATE domains SET created_at = ? WHERE id = ?").run(PAST, d1.id);
    const d2 = dominio(email);
    assert.equal(derechos(d1.id).esGratis, true);
    assert.equal(derechos(d2.id).bloqueado, true);
    assert.equal(derechos(d2.id).esGratis, false);
  });
});

describe("Derechos por dominio: activado ($99)", () => {
  it("activar desbloquea todo para ESE dominio y sólo ése", () => {
    const email = cuenta("act");
    const d1 = dominio(email);
    sqlite.prepare("UPDATE domains SET created_at = ? WHERE id = ?").run(PAST, d1.id);
    const d2 = dominio(email);
    activar(email, d2.id);

    const r = derechos(d2.id);
    assert.equal(r.activado, true);
    assert.equal(r.bloqueado, false);
    assert.equal(r.sends, DOMINIO_ACTIVADO.sends);
    assert.equal(r.sendsUnlocked, true);
    assert.equal(r.mailboxes, true);
    assert.equal(r.mailboxBytes, DOMINIO_ACTIVADO.mailboxBytes);
    assert.equal(r.agentes, null, "personas ilimitadas");
    assert.equal(r.aliases, DOMINIO_ACTIVADO.aliases);
    assert.equal(r.retencionDias, null, "historial completo");
    assert.equal(r.logDays, DOMINIO_ACTIVADO.logDays);
    assert.equal(r.rules && r.webhooks && r.smtpRelay, true);

    // El primero sigue siendo el gratis: activar el 2.º no le regala nada al 1.º.
    assert.equal(derechos(d1.id).esGratis, true);
    assert.equal(derechos(d1.id).activado, false);
  });

  it("+50 GB y +100 envíos se acumulan sobre el dominio activado", () => {
    const email = cuenta("act");
    const d = dominio(email);
    activar(email, d.id);
    for (const k of ["storage50", "storage50", "sends100"] as const) {
      const a = createAddon(email, k, d.id);
      updateAddon(a.id, { status: "active", currentPeriodEnd: FUTURE });
    }
    const r = derechos(d.id);
    assert.equal(r.mailboxBytes, DOMINIO_ACTIVADO.mailboxBytes + 100 * GB);
    assert.equal(r.sends, DOMINIO_ACTIVADO.sends + 100);
  });

  it("un add-on de otro dominio no cuenta aquí", () => {
    const email = cuenta("act");
    const d1 = dominio(email);
    sqlite.prepare("UPDATE domains SET created_at = ? WHERE id = ?").run(PAST, d1.id);
    const d2 = dominio(email);
    activar(email, d1.id);
    const s = createAddon(email, "storage50", d1.id);
    updateAddon(s.id, { status: "active", currentPeriodEnd: FUTURE });
    assert.equal(derechos(d2.id).bloqueado, true);
    assert.equal(derechos(d2.id).mailboxBytes, 0);
  });

  it("pending no otorga; cancelado vale hasta el fin del periodo pagado", () => {
    const email = cuenta("act");
    const d = dominio(email);
    const a = createAddon(email, "domain", d.id);
    assert.equal(derechos(d.id).activado, false, "pending");
    updateAddon(a.id, { status: "cancelled", currentPeriodEnd: FUTURE });
    assert.equal(derechos(d.id).activado, true, "cancelado con periodo vigente");
    updateAddon(a.id, { currentPeriodEnd: PAST });
    assert.equal(derechos(d.id).activado, false, "vencido");
  });

  it("una cortesía de dominio activa exactamente igual que una compra", () => {
    const email = cuenta("act");
    const d = dominio(email);
    const { addon, order } = createCourtesyAddon({ userEmail: email, kind: "domain", domainId: d.id, currentPeriodEnd: FUTURE, grantedBy: "test" });
    assert.equal(addon.isCourtesy, true);
    assert.equal(addon.domainId, d.id);
    assert.equal(order?.listPriceCents, ADDONS.domain.price);
    assert.equal(derechos(d.id).activado, true);
  });
});

/**
 * Nadie que pague hoy paga más: mientras la suscripción vieja siga vigente (MP le sigue
 * cobrando lo de antes), TODOS sus dominios cuentan como activados, con los topes nuevos.
 */
describe("Derechos por dominio: suscripción legado", () => {
  it("un plan viejo vigente activa todos los dominios del dueño", () => {
    const email = cuenta("leg");
    updateUserSubscription(email, { plan: "basico", status: "active", currentPeriodEnd: FUTURE });
    const d1 = dominio(email);
    const d2 = dominio(email);
    for (const d of [d1, d2]) {
      const r = derechos(d.id);
      assert.equal(r.activado, true);
      assert.equal(r.legado, true);
      assert.equal(r.bloqueado, false);
    }
  });

  it("un add-on legado sin dominio (sends25) suma en todos sus dominios", () => {
    const email = cuenta("leg");
    updateUserSubscription(email, { plan: "basico", status: "active", currentPeriodEnd: FUTURE });
    const a = createAddon(email, "sends25");
    updateAddon(a.id, { status: "active", currentPeriodEnd: FUTURE });
    assert.equal(a.domainId, undefined);
    assert.equal(derechos(dominio(email).id).sends, DOMINIO_ACTIVADO.sends + 25);
  });

  it("con el plan vencido vuelve a la regla normal: el 1.º gratis, el 2.º bloqueado", () => {
    const email = cuenta("leg");
    updateUserSubscription(email, { plan: "basico", status: "active", currentPeriodEnd: PAST });
    const d1 = dominio(email);
    sqlite.prepare("UPDATE domains SET created_at = ? WHERE id = ?").run(PAST, d1.id);
    const d2 = dominio(email);
    assert.equal(derechos(d1.id).esGratis, true);
    assert.equal(derechos(d2.id).bloqueado, true);
  });
});

describe("Add-ons: lookup y catálogo", () => {
  const email = `addon-lookup-${crypto.randomUUID()}@test.com`;
  let domainId = "";
  before(() => { createUser(email, "x"); domainId = dominio(email).id; });

  it("se encuentra por id y por preapproval de MP", () => {
    const a = createAddon(email, "domain", domainId);
    assert.equal(getAddonById(a.id)?.kind, "domain");
    const mpId = `mp-${crypto.randomUUID()}`;
    updateAddon(a.id, { status: "active", mpPreapprovalId: mpId, currentPeriodEnd: FUTURE });
    assert.equal(getAddonByMpId(mpId)?.id, a.id);
  });

  it("guarda el precio del catálogo y el dominio", () => {
    const a = createAddon(email, "sends100", domainId);
    assert.equal(a.priceCents, ADDONS.sends100.price);
    assert.equal(a.domainId, domainId);
    assert.equal(a.status, "pending");
    updateAddon(a.id, { status: "expired" });
  });

  it("los tres a la venta cuestan lo mismo: un solo número en toda la página", () => {
    assert.deepEqual([...ADDONS_FOR_SALE], ["domain", "storage50", "sends100"]);
    for (const k of ADDONS_FOR_SALE) assert.equal(ADDONS[k].price, 99_00);
  });

  it("listEffectiveAddons(ForDomain) ignora pending y expired", () => {
    const p = createAddon(email, "storage50", domainId);
    const e = createAddon(email, "storage50", domainId);
    updateAddon(e.id, { status: "expired" });
    const ids = listEffectiveAddonsForDomain(domainId).map((x) => x.id);
    assert.ok(!ids.includes(p.id) && !ids.includes(e.id));
    assert.ok(!listEffectiveAddons(email).map((x) => x.id).includes(p.id));
  });

  it("un kind desconocido no se puede crear", () => {
    assert.throws(() => createAddon(email, "gratis", domainId), /desconocido/);
  });
});

// Los tres add-ons a la venta cuestan $99. Si el webhook no sale por la rama `addon:`,
// el fallback por monto podría activar un PLAN legado: por eso ese fallback ya no conoce
// el 99, y por eso el `reason` nunca dice "Plan".
describe("Add-ons: aislamiento del webhook", () => {
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  it("el external_reference de add-on no se confunde con guest checkout", () => {
    const ref = `addon:${crypto.randomUUID()}`;
    assert.ok(ref.startsWith("addon:"));
    assert.equal(UUID_RE.test(ref), false);
    assert.ok(!ref.includes("@"));
  });
  it("el reason del add-on no dispara la detección de plan", () => {
    for (const kind of ADDONS_FOR_SALE) {
      const reason = `MailMask — ${ADDONS[kind].label} · ejemplo.com`;
      assert.equal(reason.match(/Plan (\w+)/i), null, `"${reason}" no debe contener "Plan X"`);
    }
  });
});

// La lista de supresión se llavea en minúsculas al escribir y al leer: SES entrega los
// bounces con las mayúsculas originales y SQLite compara sensible a mayúsculas.
describe("Supresión: matching insensible a mayúsculas", () => {
  it("un email guardado con mayúsculas se detecta en minúsculas", async () => {
    const { addSuppression, isSuppressed } = await import("./db.ts");
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
