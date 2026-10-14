import { describe, it, before } from "node:test";
import assert from "node:assert/strict";

import { app } from "./main.ts";
import { recordOrder, type Order } from "./db.ts";
import { sqlite } from "./pg.ts";
import { signJwt } from "./auth.ts";

const get = (path: string, cookie?: string) =>
  app.fetch(new Request(`http://localhost${path}`, { headers: cookie ? { cookie } : {} }));

function seedUser(email: string) {
  sqlite.prepare("INSERT OR REPLACE INTO users (email,password_hash,created_at) VALUES (?,?,?)")
    .run(email, "x", new Date().toISOString());
}

describe("/recibo/:folio", () => {
  const owner = `recibo-${crypto.randomUUID()}@test.com`;
  const stranger = `recibo-otro-${crypto.randomUUID()}@test.com`;
  let order: Order;

  before(() => {
    seedUser(owner);
    seedUser(stranger);
    order = recordOrder({
      userEmail: owner, kind: "charge", subject: "addon",
      description: "Activación anual <b>kandey</b>", amountCents: 158800,
      eventKey: `recibo:${crypto.randomUUID()}`, mpPaymentId: "123456789",
    })!;
  });

  it("sin sesión manda al login con next de vuelta al recibo", async () => {
    const res = await get(`/recibo/${order.number}`);
    assert.equal(res.status, 302);
    assert.equal(res.headers.get("location"), `/login?next=${encodeURIComponent(`/recibo/${order.number}`)}`);
  });

  it("la dueña lo ve imprimible, con el HTML escapado", async () => {
    const res = await get(`/recibo/${order.number}`, `token=${await signJwt({ email: owner })}`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("cache-control") ?? "", /no-store/);
    const html = await res.text();
    assert.ok(html.includes(order.number));
    assert.ok(html.includes("$1,588.00 MXN"));
    assert.ok(html.includes("MercadoPago 123456789"));
    assert.ok(html.includes("&lt;b&gt;kandey"));
    assert.ok(!html.includes("<b>kandey"));
  });

  it("muestra el dominio del add-on y el periodo completo", async () => {
    const domainId = crypto.randomUUID();
    const addonId = crypto.randomUUID();
    sqlite.prepare("INSERT INTO domains (id, domain, owner_email, verified, verification_token, created_at) VALUES (?,?,?,0,?,?)")
      .run(domainId, `recibo-${domainId.slice(0, 8)}.mx`, owner, "tok", new Date().toISOString());
    sqlite.prepare("INSERT INTO addons (id, user_email, kind, status, price_cents, created_at, domain_id) VALUES (?,?,?,?,?,?,?)")
      .run(addonId, owner, "domain", "active", 9900, new Date().toISOString(), domainId);
    const o = recordOrder({
      userEmail: owner, kind: "charge", subject: "addon", subjectId: addonId, subjectKey: "domain",
      description: "Dominio activado", amountCents: 9900, eventKey: `recibo:${crypto.randomUUID()}`,
      occurredAt: "2026-10-05T12:00:00.000Z", periodEnd: "2027-10-10T12:00:00.000Z",
    })!;
    const html = await (await get(`/recibo/${o.number}`, `token=${await signJwt({ email: owner })}`)).text();
    assert.ok(html.includes(`recibo-${domainId.slice(0, 8)}.mx`));
    assert.ok(html.includes("5 de octubre de 2026 – 10 de octubre de 2027"));
    assert.ok(html.includes("Vigencia del servicio"));
  });

  it("otra cuenta recibe 404, igual que un folio inexistente", async () => {
    const cookie = `token=${await signJwt({ email: stranger })}`;
    assert.equal((await get(`/recibo/${order.number}`, cookie)).status, 404);
    assert.equal((await get(`/recibo/MM-0000-NOPE`, cookie)).status, 404);
  });
});
