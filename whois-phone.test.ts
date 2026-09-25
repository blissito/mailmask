import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizePhone } from "./main.js";
import { threadRefsFor } from "./ses.js";

// Una clienta escribió "+525643868687" y el transfer-in la rechazó hasta agotar el rate limit.
test("normalizePhone acepta como la gente escribe el teléfono", () => {
  assert.equal(normalizePhone("+525643868687", "MX"), "+52.5643868687");
  assert.equal(normalizePhone("+52.5512345678", "MX"), "+52.5512345678");
  assert.equal(normalizePhone("+52 (55) 1234-5678", "MX"), "+52.5512345678");
  assert.equal(normalizePhone("55 1234 5678", "MX"), "+52.5512345678");
  assert.equal(normalizePhone("525512345678", "MX"), "+52.5512345678");
  assert.equal(normalizePhone("+1 415 555 0100", "US"), "+1.4155550100");
  assert.equal(normalizePhone("+44 20 7946 0958", "MX"), null);
  assert.equal(normalizePhone("123", "MX"), null);
});

test("threadRefsFor guarda el Message-ID que SES pone en su lugar", () => {
  assert.deepEqual(threadRefsFor({ messageId: "<a@denik.me>", sesMessageId: "0100abc-000000" }), [
    "<a@denik.me>",
    "<0100abc-000000@email.amazonses.com>",
  ]);
  assert.deepEqual(threadRefsFor({ messageId: "<a@denik.me>", sesMessageId: "" }), ["<a@denik.me>"]);
});

test("dropCnameConflicts: el CNAME gana y se van los ecos de su destino", async () => {
  const { dropCnameConflicts } = await import("./dns-records.js");
  const r = dropCnameConflicts([
    { name: "mail.k.mx", type: "A", ttl: 60, values: ["1.2.3.4"] },
    { name: "mail.k.mx", type: "CNAME", ttl: 300, values: ["k.mx"] },
    { name: "mail.k.mx", type: "TXT", ttl: 300, values: ['"v=spf1 ~all"'] },
    { name: "k.mx", type: "A", ttl: 60, values: ["1.2.3.4"] },
  ] as never);
  assert.deepEqual(r.map((x: { name: string; type: string }) => `${x.name} ${x.type}`), ["mail.k.mx CNAME", "k.mx A"]);
});

// Con X-Forwarded-For el cliente elegía su cubeta del rate limit (24-sep-2026).
test("el rate limit no se burla mandando X-Forwarded-For", async () => {
  const { app } = await import("./main.js");
  const request = (xff: string) => app.fetch(new Request("http://localhost/api/coupons/NOEXISTE", {
    headers: { "x-forwarded-for": xff, "fly-client-ip": "203.0.113.77" },
  }));
  const statuses: number[] = [];
  for (let i = 0; i < 12; i++) statuses.push((await request(`198.51.100.${i}`)).status);
  assert.ok(statuses.includes(429), `cambiar el XFF no debe dar cubeta nueva: ${statuses}`);
});

// AWS rechaza un .mx con el estado escrito como lo escribe la gente (kandey.com.mx pidió "CDMX").
test("normalizeMxState traduce a la clave que exige el registro", async () => {
  const { normalizeMxState } = await import("./main.js");
  assert.equal(normalizeMxState("CDMX"), "DF");
  assert.equal(normalizeMxState("Ciudad de México"), "DF");
  assert.equal(normalizeMxState("Jalisco"), "JA");
  assert.equal(normalizeMxState("Edo. Méx."), "ME");
  assert.equal(normalizeMxState("Nuevo León"), "NL");
  assert.equal(normalizeMxState("qro"), "QE");
  assert.equal(normalizeMxState("NL"), "NL");
  assert.equal(normalizeMxState("Narnia"), null);
});
