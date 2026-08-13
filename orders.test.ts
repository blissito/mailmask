import { describe, it, before } from "node:test";
import assert from "node:assert/strict";

import {
  recordOrder,
  listOrders,
  getLastOrder,
  getOrderByNumber,
  generateOrderNumber,
  chargeEventKey,
  createCourtesyAddon,
  getUserPlanLimits,
  getUser,
  listEffectiveAddons,
  PLANS,
  planLabel,
} from "./db.ts";
import { sqlite } from "./pg.ts";

const FUTURE = new Date(Date.now() + 30 * 864e5).toISOString();

function seedUser(email: string, plan = "basico") {
  sqlite
    .prepare(
      "INSERT OR REPLACE INTO users (email,password_hash,created_at,sub_plan,sub_status,sub_period_end) VALUES (?,?,?,?,?,?)",
    )
    .run(email, "x", new Date().toISOString(), plan, "active", FUTURE);
}

describe("Libro mayor: idempotencia", () => {
  const email = `order-idem-${crypto.randomUUID()}@test.com`;
  before(() => seedUser(email));

  it("la misma eventKey solo inserta una vez", () => {
    const key = `test:${crypto.randomUUID()}`;
    const first = recordOrder({
      userEmail: email, kind: "charge", subject: "plan",
      description: "Plan Básico", amountCents: 4900, eventKey: key,
    });
    const second = recordOrder({
      userEmail: email, kind: "charge", subject: "plan",
      description: "Plan Básico", amountCents: 4900, eventKey: key,
    });

    assert.ok(first, "el primer insert devuelve la fila");
    // Este null es lo que impide que un reintento de MercadoPago mande tres correos.
    assert.equal(second, null, "el duplicado devuelve null");
    assert.equal(listOrders(email).filter((o) => o.eventKey === key).length, 1);
  });

  it("eventKeys distintas insertan filas distintas", () => {
    const before = listOrders(email).length;
    recordOrder({ userEmail: email, kind: "charge", subject: "plan", description: "A", eventKey: `a:${crypto.randomUUID()}` });
    recordOrder({ userEmail: email, kind: "charge", subject: "plan", description: "B", eventKey: `b:${crypto.randomUUID()}` });
    assert.equal(listOrders(email).length, before + 2);
  });
});

describe("Libro mayor: chargeEventKey", () => {
  it("el mismo payload da la misma clave", () => {
    const ap = { id: 123, status: "processed", payment: { id: 999, status: "approved" } };
    assert.equal(chargeEventKey(ap), chargeEventKey({ ...ap }));
  });

  it("un rechazo y su reintento aprobado dan claves distintas", () => {
    // Si compartieran clave, el reintento exitoso se tragaría en silencio y el cliente
    // pagaría sin que se le extienda el periodo.
    const rechazado = { id: 123, status: "processed", payment: { id: 999, status: "rejected" } };
    const aprobado = { id: 124, status: "processed", payment: { id: 1000, status: "approved" } };
    assert.notEqual(chargeEventKey(rechazado), chargeEventKey(aprobado));
  });

  it("sin payment cae al status del authorized payment", () => {
    assert.equal(chargeEventKey({ id: 7, status: "recycling" }), "ap:7:recycling:0");
  });
});

describe("Libro mayor: folios y listado", () => {
  const email = `order-list-${crypto.randomUUID()}@test.com`;
  before(() => seedUser(email));

  it("el folio tiene forma dictable por teléfono", () => {
    assert.match(generateOrderNumber(new Date("2026-08-13T00:00:00Z")), /^MM-2608-[0-9A-F]{4}$/);
  });

  it("el folio es recuperable y único", () => {
    const o = recordOrder({
      userEmail: email, kind: "charge", subject: "plan",
      description: "Plan Básico", amountCents: 4900, eventKey: `num:${crypto.randomUUID()}`,
    })!;
    assert.equal(getOrderByNumber(o.number)?.id, o.id);
  });

  it("lista de la más reciente a la más vieja y respeta el límite", () => {
    for (let i = 0; i < 3; i++) {
      recordOrder({
        userEmail: email, kind: "charge", subject: "plan",
        description: `Cargo ${i}`, amountCents: 100 * i, eventKey: `ord:${crypto.randomUUID()}`,
      });
    }
    const all = listOrders(email);
    assert.ok(all.length >= 4);
    for (let i = 1; i < all.length; i++) {
      assert.ok(all[i - 1].createdAt >= all[i].createdAt, "orden descendente");
    }
    assert.equal(listOrders(email, { limit: 2 }).length, 2);
    assert.equal(getLastOrder(email)?.id, all[0].id);
  });
});

describe("Cortesías", () => {
  const email = `courtesy-${crypto.randomUUID()}@test.com`;
  before(() => seedUser(email, "basico"));

  it("otorga add-on y asiento en el libro mayor", () => {
    const { addon, order } = createCourtesyAddon({
      userEmail: email, kind: "domain", currentPeriodEnd: FUTURE,
      note: "compensación", grantedBy: "test",
    });

    assert.equal(addon.source, "courtesy");
    assert.equal(addon.isCourtesy, true);
    assert.equal(addon.status, "active");
    // El precio de la fila es 0 porque de ahí sale el "+$99/mes" del dashboard...
    assert.equal(addon.priceCents, 0);
    // ...pero el valor del regalo no se pierde: vive en el asiento.
    assert.equal(order?.kind, "courtesy");
    assert.equal(order?.amountCents, 0);
    assert.equal(order?.listPriceCents, 9900);
    assert.equal(order?.grantedBy, "test");
  });

  it("otorga exactamente el mismo cupo que un add-on pagado", () => {
    // Fija la afirmación de que getUserPlanLimits no distingue regalo de compra. Si
    // alguien "arregla" eso, las cortesías dejan de servir para lo único que existen.
    const limits = getUserPlanLimits(getUser(email)!);
    assert.equal(limits.domains, PLANS.basico.domains + 1);
  });

  it("un kind futuro desconocido no revienta y no otorga cupo de más", () => {
    const otro = `courtesy-future-${crypto.randomUUID()}@test.com`;
    seedUser(otro, "basico");
    const { addon } = createCourtesyAddon({
      userEmail: otro, kind: "seats5", currentPeriodEnd: FUTURE,
      label: "5 asientos", listPriceCents: 19900,
    });
    assert.equal(addon.kind as string, "seats5");
    assert.equal(listEffectiveAddons(otro).length, 1);

    const limits = getUserPlanLimits(getUser(otro)!);
    assert.equal(limits.domains, PLANS.basico.domains, "un kind desconocido no da dominios");
    assert.equal(limits.sendsUnlocked, false);
  });
});

describe("Etiquetas de plan", () => {
  it("acentúa el plan básico", () => {
    // Salía "Basico" de charAt(0).toUpperCase(), en correos y dashboard.
    assert.equal(planLabel("basico"), "Básico");
  });

  it("cubre los planes legados", () => {
    assert.equal(planLabel("pro"), "Pro");
    assert.equal(planLabel("agencia"), "Agencia");
  });

  it("degrada sin romper", () => {
    assert.equal(planLabel(undefined), "Sin plan");
    assert.equal(planLabel("garbage"), "Sin plan");
  });
});
