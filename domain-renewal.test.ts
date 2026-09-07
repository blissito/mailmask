// Renovación anual de un dominio.
//
// Existe porque `registerDomain` manda `AutoRenew: true` a AWS y el registro se cobraba una
// sola vez: AWS renovaba cada año y nos lo cobraba a nosotros, en silencio. Lo que se fija
// aquí es que la fecha venga de AWS y no de un `+365 días`, que un rechazo NO deje caer el
// dominio, y que un evento repetido de MercadoPago no cobre dos veces.

import { describe, it, before, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";

const suffix = Date.now();
// Lo que "dice AWS". Los tests lo mueven para comprobar que la base lo sigue.
const aws = { expirationDate: "2027-06-01T00:00:00.000Z", autoRenew: true };
const alertas: { tipo: string; mensaje: string }[] = [];
const correos: { to: string; subject: string }[] = [];

describe("renovación anual de dominios", () => {
  // deno-lint-ignore no-explicit-any
  let dbmod: any, sync: any, main: any;
  const email = `renov-${suffix}@example.com`;

  before(async () => {
    mock.module("./route53.ts", {
      namedExports: {
        getDomainDetail: async () => ({ ...aws, nameservers: [], statusList: [], transferLock: false }),
      },
    });
    const realSes = await import("./ses.ts");
    mock.module("./ses.ts", {
      namedExports: {
        ...realSes,
        sendAlert: async (tipo: string, mensaje: string) => { alertas.push({ tipo, mensaje }); return true; },
        // deno-lint-ignore no-explicit-any
        sendFromDomain: async (_f: string, to: string, subject: string) => {
          correos.push({ to, subject });
          return { messageId: "<x@test>", sesMessageId: "ses-x" };
        },
      },
    });

    main = await import("./main.ts");
    dbmod = await import("./db.ts");
    sync = await import("./domain-sync.ts");

    const { hashPassword } = await import("./auth.ts");
    dbmod.createUser(email, await hashPassword("password123"));
  });

  beforeEach(() => { alertas.length = 0; correos.length = 0; });

  const registrar = (extra: Record<string, unknown> = {}) => {
    const reg = dbmod.createDomainRegistration({
      domainName: `r${Math.random().toString(36).slice(2, 8)}-${suffix}.com`,
      ownerEmail: email, tld: ".com", priceCents: 59900, awsCostCents: 1300,
    });
    dbmod.updateDomainRegistration(reg.id, { status: "registered", expiresAt: aws.expirationDate, ...extra });
    return dbmod.getDomainRegistration(reg.id);
  };

  it("la fecha de expiración la manda AWS, no un +365 nuestro", async () => {
    const reg = registrar({ expiresAt: "2020-01-01T00:00:00.000Z" });
    aws.expirationDate = "2028-03-15T00:00:00.000Z";

    await sync.syncDomainExpirations();

    const fresco = dbmod.getDomainRegistration(reg.id);
    assert.equal(fresco.expiresAt, "2028-03-15T00:00:00.000Z");
    assert.equal(fresco.awsAutoRenew, true);
    // El cobro se agenda 60 días antes: AWS renueva sola ~45 días antes en varios TLDs.
    const margen = Date.parse(fresco.expiresAt) - Date.parse(fresco.nextChargeAt);
    assert.equal(margen / 864e5, 60);
    aws.expirationDate = "2027-06-01T00:00:00.000Z";
  });

  it("si AWS reporta AutoRenew apagado, se alerta: ese estado pierde dominios", async () => {
    registrar({ renewalStatus: "active" });
    aws.autoRenew = false;
    await sync.syncDomainExpirations();
    aws.autoRenew = true;

    assert.ok(alertas.some((a) => a.tipo === "dominio-sin-autorenew"), "no se avisó del AutoRenew apagado");
  });

  it("avisa de los que vencen pronto sin renovación cobrada", async () => {
    aws.expirationDate = new Date(Date.now() + 40 * 864e5).toISOString();
    registrar({ renewalStatus: "none" });
    await sync.syncDomainExpirations();
    aws.expirationDate = "2027-06-01T00:00:00.000Z";

    const digest = alertas.find((a) => a.tipo === "dominios-sin-renovacion");
    assert.ok(digest, "falta el digest que evita que paguemos dominios ajenos");
    assert.match(digest!.mensaje, /nos los va a cobrar/);
  });

  it("los avisos van a 75, 30 y 7 días, y cada hito una sola vez", async () => {
    const reg = registrar({ expiresAt: new Date(Date.now() + 25 * 864e5).toISOString() });
    // Otros casos dejan sus propias filas: se cuentan sólo los de este dominio.
    const mios = () => correos.filter((c) => c.subject.includes(reg.domainName));

    await sync.avisarRenovaciones();
    assert.equal(mios().length, 1);
    assert.match(mios()[0].subject, /vence el/);
    assert.equal(dbmod.getDomainRegistration(reg.id).warnedAt, "30");

    // Segunda pasada el mismo día: no debe repetir.
    correos.length = 0;
    await sync.avisarRenovaciones();
    assert.equal(mios().length, 0);

    // Al cruzar el hito de 7 sí vuelve a avisar.
    dbmod.updateDomainRegistration(reg.id, { expiresAt: new Date(Date.now() + 5 * 864e5).toISOString() });
    correos.length = 0;
    await sync.avisarRenovaciones();
    assert.equal(mios().length, 1);
    assert.equal(dbmod.getDomainRegistration(reg.id).warnedAt, "7");
  });

  it("a quien ya tiene la renovación activa se le avisa sin asustarlo", async () => {
    const reg = registrar({ expiresAt: new Date(Date.now() + 5 * 864e5).toISOString(), renewalStatus: "active" });
    await sync.avisarRenovaciones();
    const mio = correos.find((c) => c.subject.includes(reg.domainName));
    assert.ok(mio);
    assert.match(mio!.subject, /se renueva el/);
  });

  it("un cobro rechazado abre cobranza y NO deja caer el dominio", async () => {
    const reg = registrar({ renewalStatus: "active", mpPreapprovalId: `pre-${suffix}` });

    await main.procesarRenovacionDominio(dbmod.getDomainRegistration(reg.id), {
      id: `${suffix}-1`, preapproval_id: `pre-${suffix}`, transaction_amount: 599, currency_id: "MXN",
      status: "recycling", payment: { status: "rejected" },
    }, false);

    const fresco = dbmod.getDomainRegistration(reg.id);
    assert.equal(fresco.renewalStatus, "past_due");
    assert.ok(fresco.dunningStartedAt);
    // El dominio sigue registrado: dejarlo vencer es irreversible.
    assert.equal(fresco.status, "registered");
    const aviso = correos.find((c) => /No pudimos cobrar/.test(c.subject));
    assert.ok(aviso, "no se avisó del cobro fallido");
  });

  it("el correo del cobro fallido no dice que el correo deja de funcionar", async () => {
    // `chargeFailed` dice "tus máscaras dejan de reenviar", que en un dominio es falso: ya
    // lo renovamos y lo que falta es el pago.
    const { domainChargeFailed } = await import("./emails.ts");
    const e = domainChargeFailed({ domain: "x.com", attemptedCents: 59900, expiresAt: null });
    assert.match(e.text, /no está en riesgo inmediato/);
    assert.doesNotMatch(e.text, /dejan de reenviar/);
  });

  it("un cobro aprobado renueva, cobra una vez y manda recibo", async () => {
    const reg = registrar({ renewalStatus: "past_due", mpPreapprovalId: `pre2-${suffix}`, dunningStartedAt: new Date().toISOString() });
    aws.expirationDate = "2029-01-01T00:00:00.000Z";
    const ap = {
      id: `${suffix}-2`, preapproval_id: `pre2-${suffix}`, transaction_amount: 599, currency_id: "MXN",
      status: "processed", payment: { id: `${suffix}-p`, status: "approved" }, date_created: new Date().toISOString(),
    };

    await main.procesarRenovacionDominio(dbmod.getDomainRegistration(reg.id), ap, true);

    const fresco = dbmod.getDomainRegistration(reg.id);
    assert.equal(fresco.renewalStatus, "active");
    assert.equal(fresco.expiresAt, "2029-01-01T00:00:00.000Z", "no releyó la fecha de AWS");
    assert.equal(fresco.dunningStartedAt, null, "no cerró la cobranza");
    assert.ok(correos.some((c) => /Renovación/.test(c.subject)), "no mandó el recibo");

    // MercadoPago reenvía el mismo evento: el segundo no debe cobrar otra vez.
    correos.length = 0;
    await main.procesarRenovacionDominio(dbmod.getDomainRegistration(reg.id), ap, true);
    const ordenes = dbmod.listOrders(email).filter((o: { subjectId: string }) => o.subjectId === reg.id);
    assert.equal(ordenes.length, 1, "el evento repetido generó una segunda orden");
    assert.equal(correos.length, 0, "el evento repetido mandó otro recibo");

    aws.expirationDate = "2027-06-01T00:00:00.000Z";
  });
});
