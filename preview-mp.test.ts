// MercadoPago en preview, por HTTP: es donde vive la compuerta, porque estas llamadas no
// pasan por el SDK de AWS y no las atrapa ningún cliente compartido.
//
// Se prueba el camino corto a cada llamada real: iniciar un cobro (la renovación anual de un
// dominio, que crea un `preApproval`) y cancelarlo (`/api/billing/cancel`, que hace el PUT a
// `/preapproval`). Los dos tienen que contestar 503 con el motivo, no un 500 genérico — y
// ninguno de los dos llega a MP.
//
// `PREVIEW=1` se fija antes de importar la app (los imports son dinámicos a propósito).

process.env.PREVIEW = "1";

import { describe, it, before } from "node:test";
import assert from "node:assert/strict";

const email = `preview-mp-${crypto.randomUUID()}@test.com`;

describe("cobros en preview", () => {
  // deno-lint-ignore no-explicit-any
  let app: any, dbmod: any, sqlite: any;
  let cookie = "";
  let csrf = "";

  before(async () => {
    ({ app } = await import("./main.ts"));
    dbmod = await import("./db.ts");
    ({ sqlite } = await import("./pg.ts"));

    const { hashPassword } = await import("./auth.ts");
    dbmod.createUser(email, await hashPassword("password123"));

    const res = await app.fetch(new Request("http://localhost/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: "password123" }),
    }));
    // deno-lint-ignore no-explicit-any
    const galletas = (res.headers as any).getSetCookie?.() ?? [res.headers.get("set-cookie") ?? ""];
    cookie = galletas.map((c: string) => c.split(";")[0]).join("; ");
    csrf = /csrf_token=([^;]+)/.exec(cookie)?.[1] ?? "";
  });

  const post = (ruta: string, body: unknown) =>
    app.fetch(new Request(`http://localhost${ruta}`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie, "x-csrf-token": csrf },
      body: JSON.stringify(body),
    }));

  const dominioRegistrado = () => {
    const reg = dbmod.createDomainRegistration({
      domainName: `p${Math.random().toString(36).slice(2, 8)}.com`,
      ownerEmail: email,
      tld: "com",
      priceCents: 30000,
      awsCostCents: 1500,
      renewalPriceCents: 30000,
    });
    dbmod.updateDomainRegistration(reg.id, { status: "registered", expiresAt: "2028-01-01T00:00:00.000Z" });
    return dbmod.getDomainRegistration(reg.id);
  };

  it("iniciar la renovación anual devuelve 503 y no llega a MercadoPago", async () => {
    sqlite.prepare("DELETE FROM rate_limits").run();
    const reg = dominioRegistrado();
    const res = await post(`/api/domains/registrations/${reg.id}/renewal`, {});
    assert.equal(res.status, 503, "en preview el cobro no se inicia: 503, no 500");
    assert.match((await res.json()).error, /deshabilitado en preview/);
    assert.equal(dbmod.getDomainRegistration(reg.id).mpPreapprovalId ?? null, null, "no se guardó ningún preapproval");
  });

  it("cancelar la suscripción devuelve 503 y no llama al PUT de /preapproval", async () => {
    sqlite.prepare("DELETE FROM rate_limits").run();
    dbmod.updateUserSubscription(email, { plan: "basico", status: "active", mpSubscriptionId: "2c938084-0000", currentPeriodEnd: null });
    const res = await post("/api/billing/cancel", {});
    assert.equal(res.status, 503, "en preview no se cancela nada en MP");
    assert.match((await res.json()).error, /deshabilitado en preview/);
    assert.equal(dbmod.getUser(email).subscription?.status, "active", "la suscripción local no se toca");
  });
});
