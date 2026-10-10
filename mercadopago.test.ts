import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { MercadoPagoConfig, Preference, PreApproval } from "mercadopago";

// Contrato del SDK v3 con lo que mandamos desde main.ts (Preference de dominio y
// PreApproval de add-on/renovación): el cuerpo sale tal cual, con los montos intactos, y
// de la respuesta leemos `id` e `init_point`. El resto de las pruebas mockean el módulo
// entero; ésta es la que ejercita el SDK real, con `fetch` falso.
const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

function fakeFetch(reply: unknown) {
  const calls: { url: string; method?: string; headers: Record<string, string>; body: any }[] = [];
  globalThis.fetch = (async (url: any, init: any) => {
    calls.push({ url: String(url), method: init?.method, headers: init?.headers ?? {}, body: init?.body ? JSON.parse(init.body) : undefined });
    return new Response(JSON.stringify(reply), { status: 201, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return calls;
}

describe("mercadopago v3", () => {
  it("Preference.create manda items/unit_price/currency_id intactos y devuelve id e init_point", async () => {
    const calls = fakeFetch({ id: "pref-1", init_point: "https://mp.test/checkout" });
    const body = {
      items: [{ id: "r1", title: "Registro de dominio: a.com (1 año)", quantity: 1, unit_price: 249.5, currency_id: "MXN" }],
      payer: { email: "a@b.test" },
      external_reference: "domain-reg:r1",
      notification_url: "https://www.mailmask.studio/api/webhooks/mercadopago",
    };
    const res = await new Preference(new MercadoPagoConfig({ accessToken: "tok" })).create({ body });
    assert.equal(res.id, "pref-1");
    assert.equal(res.init_point, "https://mp.test/checkout");
    assert.match(calls[0].url, /api\.mercadopago\.com\/checkout\/preferences\/?$/);
    assert.equal(calls[0].method, "POST");
    assert.deepEqual(calls[0].body.items, body.items);
    assert.equal(calls[0].body.external_reference, "domain-reg:r1");
    assert.equal(calls[0].body.notification_url, body.notification_url);
    assert.match(JSON.stringify(calls[0].headers), /Bearer tok/);
  });

  it("PreApproval.create manda auto_recurring intacto y devuelve id e init_point", async () => {
    const calls = fakeFetch({ id: "pa-1", init_point: "https://mp.test/sub" });
    const auto_recurring = { frequency: 12, frequency_type: "months", transaction_amount: 990, currency_id: "MXN" };
    const res = await new PreApproval(new MercadoPagoConfig({ accessToken: "tok" })).create({
      body: { reason: "MailMask — Renovación anual · a.com", auto_recurring, payer_email: "a@b.test", back_url: "https://www.mailmask.studio/app", external_reference: "domain-renew:r1" } as any,
    });
    assert.equal(res.id, "pa-1");
    assert.equal(res.init_point, "https://mp.test/sub");
    assert.match(calls[0].url, /api\.mercadopago\.com\/preapproval\/?$/);
    assert.deepEqual(calls[0].body.auto_recurring, auto_recurring);
    assert.equal(calls[0].body.external_reference, "domain-renew:r1");
  });
});
