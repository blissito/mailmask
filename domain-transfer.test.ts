// Transferencia de dominios, entrante y saliente.
//
// El riesgo que se fija aquí no es hablar con AWS: es que el dominio **ya está en producción
// para alguien**. Si se cambian sus nameservers con la zona vacía, su web y su correo mueren
// en el acto. De ahí el guard del inventario y el orden de los pasos.

import { describe, it, before, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";

const suffix = Date.now();

const llamadas: { op: string; args: unknown }[] = [];
const correos: { to: string; subject: string }[] = [];
const alertas: string[] = [];
let zona: { name: string; type: string; ttl: number; values: string[] }[] = [];
let estadoOperacion = "IN_PROGRESS";
let transferible: { transferable: boolean; motivo: string | null } = { transferable: true, motivo: null };

describe("transferencia de dominios", () => {
  // deno-lint-ignore no-explicit-any
  let dbmod: any, prov: any, transfer: any, sqlite: any;
  const email = `transf-${suffix}@example.com`;

  before(async () => {
    mock.module("./route53.ts", {
      namedExports: {
        checkTransferability: async () => transferible,
        transferDomain: async (domain: string, authCode: string, ns: string[], contacto: unknown) => {
          llamadas.push({ op: "transferDomain", args: { domain, authCode, ns, contacto } });
          return `op-${suffix}`;
        },
        getOperationStatus: async () => estadoOperacion,
        getDomainDetail: async () => ({ expirationDate: "2028-01-01T00:00:00.000Z", autoRenew: true, nameservers: [], statusList: [], transferLock: false }),
        ensureHostedZone: async () => ({ hostedZoneId: "ZT", nameservers: ["ns-1.awsdns-01.com"], created: true }),
        // deno-lint-ignore no-explicit-any
        applyRecordChanges: async (_z: string, cambios: any[]) => {
          llamadas.push({ op: "applyRecordChanges", args: cambios.length });
          for (const c of cambios) zona.push(c.rrset);
          return { changeId: "C1" };
        },
        listRecordSets: async () => zona,
        configureDnsRecords: async () => { llamadas.push({ op: "configureDnsRecords", args: null }); return { mxOurs: true }; },
        updateNameservers: async (domain: string, ns: string[]) => { llamadas.push({ op: "updateNameservers", args: { domain, ns } }); },
        disableDomainTransferLock: async (d: string) => { llamadas.push({ op: "disableLock", args: d }); },
        retrieveDomainAuthCode: async () => "EPP-SECRETO",
        resendTransferEmail: async () => undefined,
        // Precio vivo de AWS: `.design` cuesta 64 USD transferir, `.app` 20.
        listTldPrice: async (tld: string) => {
          const tabla: Record<string, number> = { design: 6400, app: 2000, quesoazul: 0 };
          const c = tabla[tld];
          return c === undefined ? null : { transferUsdCents: c, renewUsdCents: c };
        },
      },
    });
    mock.module("./dns-import.ts", {
      namedExports: {
        snapshotDns: async (d: string) => ({
          found: [
            { name: `www.${d}`, type: "CNAME", ttl: 300, values: ["sitio.vercel.app"] },
            { name: d, type: "TXT", ttl: 300, values: ['"google-site-verification=abc"'] },
          ],
          nameservers: ["ns1.viejo.com"],
          warning: "aviso",
        }),
        nameserversActuales: async () => ["ns1.viejo.com", "ns2.viejo.com"],
        delegacionActiva: async () => ({ delegated: false, observed: [], expected: [] }),
      },
    });
    const realSes = await import("./ses.ts");
    mock.module("./ses.ts", {
      namedExports: {
        ...realSes,
        sendAlert: async (_t: string, m: string) => { alertas.push(m); return true; },
        sendFromDomain: async (_f: string, to: string, subject: string) => {
          correos.push({ to, subject });
          return { messageId: "<x@test>", sesMessageId: "s" };
        },
        verifyDomain: async () => ({ verificationToken: "tok", dkimTokens: ["d1"] }),
        createReceiptRule: async () => undefined,
      },
    });

    dbmod = await import("./db.ts");
    ({ sqlite } = await import("./pg.ts"));
    prov = await import("./domain-provision.ts");
    transfer = await import("./domain-transfer.ts");

    const { hashPassword } = await import("./auth.ts");
    dbmod.createUser(email, await hashPassword("password123"));
  });

  beforeEach(() => {
    llamadas.length = 0; correos.length = 0; alertas.length = 0; zona = [];
    estadoOperacion = "IN_PROGRESS";
    transferible = { transferable: true, motivo: null };
    sqlite.prepare("DELETE FROM rate_limits").run();
  });

  const WHOIS = {
    firstName: "Ana", lastName: "López", email: "ana@example.com", phone: "+52.5512345678",
    address: "Calle 1", city: "CDMX", state: "CDMX", country: "mx", zip: "06600",
  };

  const crear = (extra: Record<string, unknown> = {}) => {
    const reg = dbmod.createDomainRegistration({
      domainName: `t${Math.random().toString(36).slice(2, 8)}-${suffix}.com`,
      ownerEmail: email, tld: ".com", priceCents: 59900, awsCostCents: 1300,
      kind: "transfer",
      dnsSnapshot: [{ name: "www.x.com", type: "CNAME", ttl: 300, values: ["sitio.vercel.app"] }],
    });
    dbmod.updateDomainRegistration(reg.id, extra);
    return dbmod.getDomainRegistration(reg.id);
  };

  it("el auth code no se guarda: sólo viven en la fila sus últimos 4 caracteres", () => {
    const reg = crear();
    const pista = transfer.saveAuthCode(reg.id, "SUPER-SECRETO-1234");
    assert.equal(pista, "1234");

    dbmod.updateDomainRegistration(reg.id, { transferAuthCodeHint: pista });
    const fila = JSON.stringify(dbmod.getDomainRegistration(reg.id));
    assert.doesNotMatch(fila, /SUPER-SECRETO/, "el código completo acabó en la base");
    assert.equal(transfer.takeAuthCode(reg.id), "SUPER-SECRETO-1234");

    transfer.forgetAuthCode(reg.id);
    assert.equal(transfer.takeAuthCode(reg.id), null);
  });

  it("el código EPP se guarda cifrado y sobrevive al proceso; caducado no se usa", async () => {
    const { sqlite } = await import("./pg.ts");
    const reg = crear();
    transfer.saveAuthCode(reg.id, "EPP-CIFRADO-9876");
    const row = sqlite.prepare("SELECT ciphertext FROM transfer_auth_codes WHERE registration_id = ?").get(reg.id) as { ciphertext: string };
    assert.doesNotMatch(row.ciphertext, /EPP-CIFRADO/, "el código quedó en claro en la base");
    assert.equal(transfer.takeAuthCode(reg.id), "EPP-CIFRADO-9876");

    sqlite.prepare("UPDATE transfer_auth_codes SET expires_at = 1 WHERE registration_id = ?").run(reg.id);
    assert.equal(transfer.takeAuthCode(reg.id), null);
  });

  it("la solicitud lleva los nameservers ACTUALES del cliente", async () => {
    // Si no se mandan, AWS pone los suyos al completarse y el dominio se queda sin DNS de
    // golpe. Mandándolos, el transfer no cambia nada y la migración la hacemos nosotros.
    const reg = crear();
    transfer.saveAuthCode(reg.id, "EPP123");
    await prov.iniciarTransferencia(dbmod.getDomainRegistration(reg.id));

    const llamada = llamadas.find((l) => l.op === "transferDomain");
    assert.ok(llamada);
    assert.deepEqual((llamada!.args as { ns: string[] }).ns, ["ns1.viejo.com", "ns2.viejo.com"]);
    assert.equal(dbmod.getDomainRegistration(reg.id).status, "transfer_submitted");
    assert.ok(correos.some((c) => /transferencia/i.test(c.subject)));
    // Usado el código, se olvida.
    assert.equal(transfer.takeAuthCode(reg.id), null);
  });

  it("sin auth code vigente no se manda nada a AWS", async () => {
    const reg = crear();
    await prov.iniciarTransferencia(reg);
    assert.equal(llamadas.filter((l) => l.op === "transferDomain").length, 0);
    assert.equal(dbmod.getDomainRegistration(reg.id).status, "transfer_pending_payment");
  });

  it("sin inventario aprobado, el aprovisionamiento NO toca los nameservers", async () => {
    // Es el guard que impide tumbarle la web al cliente.
    const reg = crear({ status: "registering", dnsImportStatus: "discovered" });
    await prov.finalizeDomainRegistration(dbmod.getDomainRegistration(reg.id));

    assert.equal(llamadas.length, 0, "no debe haber ni una llamada a AWS");
    assert.equal(dbmod.getDomainRegistration(reg.id).lastError, "dns_snapshot_no_aprobado");
  });

  it("con inventario aprobado, primero se puebla la zona y DESPUÉS se delega", async () => {
    const reg = crear({ status: "registering", dnsImportStatus: "approved" });
    await prov.finalizeDomainRegistration(dbmod.getDomainRegistration(reg.id));

    const orden = llamadas.map((l) => l.op);
    const iCopia = orden.indexOf("applyRecordChanges");
    const iDelega = orden.indexOf("updateNameservers");
    assert.ok(iCopia >= 0, "no se copió el inventario");
    assert.ok(iDelega >= 0, "no se delegó");
    assert.ok(iCopia < iDelega, `el orden es normativo: se delegó antes de poblar (${orden.join(" → ")})`);
    assert.ok(zona.some((r) => r.type === "CNAME"), "el registro del cliente no llegó a la zona");

    const fresco = dbmod.getDomainRegistration(reg.id);
    assert.equal(fresco.status, "registered");
    // La fecha la dice AWS.
    assert.equal(fresco.expiresAt, "2028-01-01T00:00:00.000Z");
    assert.ok(correos.some((c) => /ya está en MailMask/.test(c.subject)));
  });

  it("al completarse pide revisar el DNS si el inventario no está aprobado", async () => {
    const reg = crear({ status: "transfer_submitted", route53OperationId: `op-${suffix}`, transferRequestedAt: new Date().toISOString() });
    estadoOperacion = "SUCCESSFUL";
    await prov.sondearTransferencias();

    assert.equal(dbmod.getDomainRegistration(reg.id).status, "registering");
    const aviso = correos.find((c) => /Revisa el DNS/.test(c.subject));
    assert.ok(aviso, "no se pidió revisar el inventario");
  });

  it("recuerda la aprobación y cancela a los 10 días", async () => {
    const hace6 = new Date(Date.now() - 6 * 864e5).toISOString();
    const reg = crear({ status: "transfer_submitted", route53OperationId: `op-${suffix}`, transferRequestedAt: hace6 });

    await prov.sondearTransferencias();
    assert.equal(dbmod.getDomainRegistration(reg.id).status, "transfer_awaiting_approval");

    dbmod.updateDomainRegistration(reg.id, { transferRequestedAt: new Date(Date.now() - 11 * 864e5).toISOString() });
    correos.length = 0;
    await prov.sondearTransferencias();

    const fresco = dbmod.getDomainRegistration(reg.id);
    assert.equal(fresco.status, "transfer_cancelled");
    assert.ok(correos.some((c) => /No se pudo transferir/.test(c.subject)));
    // Ya se le cobró: alguien tiene que reembolsarle.
    assert.ok(alertas.some((a) => /reembolsar/.test(a)));
  });

  it("si AWS rechaza la operación, se avisa y se marca para reembolso", async () => {
    const reg = crear({ status: "transfer_submitted", route53OperationId: `op-${suffix}`, transferRequestedAt: new Date().toISOString() });
    estadoOperacion = "FAILED";
    await prov.sondearTransferencias();

    assert.equal(dbmod.getDomainRegistration(reg.id).status, "transfer_failed");
    assert.ok(alertas.some((a) => /reembolsar/.test(a)));
  });

  it("los requisitos del transfer-in se comprueban antes de cobrar", async () => {
    const r = await transfer.checkDomainReadiness("ejemplo.com");
    const claves = r.requisitos.map((x: { clave: string }) => x.clave);
    for (const c of ["aws", "edad", "lock", "whois", "correo", "authcode"]) {
      assert.ok(claves.includes(c), `falta el requisito ${c}`);
    }
    // Los que no se pueden verificar desde fuera se marcan como "confírmalo tú", no como ok.
    assert.equal(r.requisitos.find((x: { clave: string }) => x.clave === "whois").ok, null);
  });
  // --- Lo que se comprueba ANTES de cobrar ---
  //
  // Vivía sólo en `/transfer/check`, o sea en el front: un POST directo aquí cobraba una
  // transferencia imposible, y el reembolso es manual.

  const iniciar = async (cuerpo: Record<string, unknown>, existing?: string) => {
    const { app } = await import("./main.ts");
    const { hashPassword } = await import("./auth.ts");
    const correo = existing ?? `start-${Math.random().toString(36).slice(2, 8)}-${suffix}@example.com`;
    if (!existing) dbmod.createUser(correo, await hashPassword("password123"));
    const login = await app.fetch(new Request("http://localhost/api/auth/login", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: correo, password: "password123" }),
    }));
    // deno-lint-ignore no-explicit-any
    const galletas = (login.headers as any).getSetCookie?.() ?? [login.headers.get("set-cookie") ?? ""];
    const cookie = galletas.map((c: string) => c.split(";")[0]).join("; ");
    const csrf = /csrf_token=([^;]+)/.exec(cookie)?.[1] ?? "";
    const res = await app.fetch(new Request("http://localhost/api/domains/transfer/start", {
      method: "POST",
      headers: { "content-type": "application/json", cookie, "x-csrf-token": csrf },
      body: JSON.stringify(cuerpo),
    }));
    return { res, correo };
  };

  it("sin datos de WHOIS no se cobra: el dominio ya es del cliente", async () => {
    const { res } = await iniciar({ domain: `sinwhois-${suffix}.com`, authCode: "EPP" });
    assert.equal(res.status, 400);
    assert.match((await res.json()).error, /WHOIS/i);
    assert.equal(dbmod.getDomainRegistrationByDomainName(`sinwhois-${suffix}.com`), null);
  });

  it("reintentar sin haber pagado reusa la transferencia en vez de dar 409", async () => {
    const dominio = `reintento-${suffix}.com`;
    const { correo } = await iniciar({ domain: dominio, authCode: "EPP-1111", whois: WHOIS });
    const primera = dbmod.getDomainRegistrationByDomainName(dominio)!;
    assert.equal(primera.status, "transfer_pending_payment");

    const { res } = await iniciar({ domain: dominio, authCode: "EPP-2222", whois: WHOIS }, correo);
    assert.notEqual(res.status, 409);
    const segunda = dbmod.getDomainRegistrationByDomainName(dominio)!;
    assert.equal(segunda.id, primera.id, "debe ser la misma fila: el pago de cualquier link cae ahí");
    assert.equal(segunda.transferAuthCodeHint, "2222");
    assert.equal(transfer.takeAuthCode(primera.id), "EPP-2222");
  });

  it("otra cuenta sigue topándose con el 409", async () => {
    const dominio = `ajeno-${suffix}.com`;
    await iniciar({ domain: dominio, authCode: "EPP", whois: WHOIS });
    const { res } = await iniciar({ domain: dominio, authCode: "EPP", whois: WHOIS });
    assert.equal(res.status, 409);
  });

  it("un teléfono que Route 53 no acepta se rechaza aquí, no en AWS", async () => {
    const { res } = await iniciar({
      domain: `tel-${suffix}.com`, authCode: "EPP", whois: { ...WHOIS, phone: "+44 20 7946 0958" },
    });
    assert.equal(res.status, 400);
    assert.match((await res.json()).error, /tel/i);
  });

  it("un dominio que AWS no puede mover no llega al cobro", async () => {
    transferible = { transferable: false, motivo: "El registro lo tiene bloqueado." };
    const dominio = `nomueve-${suffix}.com`;
    const { res } = await iniciar({ domain: dominio, authCode: "EPP", whois: WHOIS });
    assert.equal(res.status, 400);
    // Y no queda fila cobrable: si la hubiera, el dominio quedaría bloqueado para siempre.
    assert.equal(dbmod.getDomainRegistrationByDomainName(dominio), null);
  });

  it("un dominio que ya está en otra cuenta de MailMask no se cobra", async () => {
    const dominio = `ajeno-${suffix}.com`;
    dbmod.createDomain(email, dominio, ["dk"], "vf");
    const { res } = await iniciar({ domain: dominio, authCode: "EPP", whois: WHOIS });
    assert.equal(res.status, 409);
  });

  it("no se puede borrar un dominio que sigue registrado a través de MailMask", async () => {
    // Borrar la fila no borra nada en AWS: el registro se queda renovándose a nuestra costa
    // y el preapproval le sigue cobrando al cliente algo que ya no tiene.
    const { app } = await import("./main.ts");
    const { hashPassword } = await import("./auth.ts");
    const dueño = `borra-${suffix}@example.com`;
    dbmod.createUser(dueño, await hashPassword("password123"));
    const login = await app.fetch(new Request("http://localhost/api/auth/login", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: dueño, password: "password123" }),
    }));
    // deno-lint-ignore no-explicit-any
    const galletas = (login.headers as any).getSetCookie?.() ?? [login.headers.get("set-cookie") ?? ""];
    const cookie = galletas.map((c: string) => c.split(";")[0]).join("; ");
    const csrf = /csrf_token=([^;]+)/.exec(cookie)?.[1] ?? "";

    const nombre = `borrable-${suffix}.com`;
    const d = dbmod.createDomain(dueño, nombre, ["dk"], "vf");
    const reg = dbmod.createDomainRegistration({
      domainName: nombre, ownerEmail: dueño, tld: ".com", priceCents: 59900, awsCostCents: 1300,
    });
    dbmod.updateDomainRegistration(reg.id, { status: "registered" });

    const r = await app.fetch(new Request(`http://localhost/api/domains/${d.id}`, {
      method: "DELETE", headers: { cookie, "x-csrf-token": csrf },
    }));
    assert.equal(r.status, 409);
    assert.match((await r.json()).error, /traslado a otro registrador/);
    assert.ok(dbmod.getDomainByName(nombre), "borró el dominio de todos modos");
  });

  it("el contacto WHOIS del cliente viaja a AWS: el dominio queda a su nombre", async () => {
    const reg = crear({ whoisContact: WHOIS });
    transfer.saveAuthCode(reg.id, "EPP-OK");
    await prov.iniciarTransferencia(dbmod.getDomainRegistration(reg.id));
    // deno-lint-ignore no-explicit-any
    const llamada = llamadas.find((l) => l.op === "transferDomain")!.args as any;
    assert.equal(llamada.contacto.firstName, "Ana");
  });

  it("una transferencia pagada que nunca se mandó a AWS acaba alertando", async () => {
    const reg = crear({ status: "transfer_paid" });
    dbmod.updateDomainRegistration(reg.id, { status: "transfer_paid" });
    // Se le añaden dos días de antigüedad: el auth code vive una hora y no sobrevive a un
    // deploy, así que esto es "cobrado y sin transferencia".
    sqlite.prepare("UPDATE domain_registrations SET created_at = ? WHERE id = ?")
      .run(new Date(Date.now() - 2 * 864e5).toISOString(), reg.id);

    await prov.sondearTransferencias();
    assert.ok(alertas.some((a) => /nunca se mandó a AWS/.test(a)), "no alertó del cobro sin transferencia");
    assert.equal(dbmod.getDomainRegistration(reg.id).warnedAt, "sin-auth-code");
  });

  it("no se activa el dominio en la cuenta de quien se adelantó a agregarlo", async () => {
    const otro = `otro-${suffix}@example.com`;
    const { hashPassword } = await import("./auth.ts");
    dbmod.createUser(otro, await hashPassword("password123"));
    const reg = crear({ dnsImportStatus: "approved", status: "registering" });
    dbmod.createDomain(otro, reg.domainName, ["dk"], "vf");

    await prov.finalizeDomainRegistration(dbmod.getDomainRegistration(reg.id));

    assert.equal(dbmod.getDomainRegistration(reg.id).lastError, "dominio_en_otra_cuenta");
    assert.ok(!llamadas.some((l) => l.op === "updateNameservers"), "tocó los nameservers de un dominio ajeno");
    assert.ok(alertas.some((a) => /otra cuenta|hay que resolver a mano/.test(a)));
  });

  it("el pago del dominio entra por el webhook PRINCIPAL de MercadoPago", async () => {
    // El panel de MP acepta una sola URL por aplicación. Hubo un momento en que estos pagos
    // tenían ruta propia, y sólo funcionaba mientras MP respetara el notification_url que
    // mandamos en cada Preference — que a veces pierde. Un pago perdido aquí es cobrarle al
    // cliente y no registrarle nada.
    const { app } = await import("./main.ts");
    const reg = crear({ status: "transfer_pending_payment" });
    transfer.saveAuthCode(reg.id, "EPP-OK");

    const pagoId = `${suffix}-pago`;
    globalThis.fetch = (async (url: string) =>
      String(url).includes("/v1/payments/")
        ? new Response(JSON.stringify({
            status: "approved",
            external_reference: `domain-transfer:${reg.id}`,
            currency_id: "MXN",
            date_approved: new Date().toISOString(),
          }), { headers: { "content-type": "application/json" } })
        : new Response("{}", { headers: { "content-type": "application/json" } })) as typeof fetch;

    const requestId = `req-${suffix}`;
    const ts = Math.floor(Date.now() / 1000).toString();
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(process.env.MP_WEBHOOK_SECRET!), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const firma = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`id:${pagoId};request-id:${requestId};ts:${ts};`));
    const v1 = Array.from(new Uint8Array(firma)).map((b) => b.toString(16).padStart(2, "0")).join("");

    const res = await app.fetch(new Request(`http://localhost/api/webhooks/mercadopago?data.id=${pagoId}`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-signature": `ts=${ts},v1=${v1}`, "x-request-id": requestId },
      body: JSON.stringify({ type: "payment", data: { id: pagoId } }),
    }));

    assert.equal(res.status, 200);
    assert.equal(dbmod.getDomainRegistration(reg.id).status, "transfer_submitted");
    assert.ok(llamadas.some((l) => l.op === "transferDomain"), "el pago no disparó la transferencia");
  });
  it("acepta cualquier TLD que AWS pueda mover, no sólo los 12 que vendemos", async () => {
    // AWS soporta 413 extensiones. La parrilla de 12 es para el buscador de dominios nuevos;
    // usarla como filtro de transferencias rechazaba a clientes que ya tenemos —
    // brendago.design y fancyfiles.app son de verdad.
    const { precioDeTransferencia } = await import("./tld-pricing.ts");

    const design = await precioDeTransferencia(".design");
    assert.ok(design, ".design se rechazó y es de una clienta real");
    assert.equal(design!.curado, false);
    assert.equal(design!.transferUsdCents, 6400);
    // Nunca por debajo del costo: 64 USD son ~1344 MXN al tipo de cambio por defecto.
    assert.ok(design!.transferMxnCents > 6400 * 21, `se vendería bajo costo: ${design!.transferMxnCents}`);

    const app = await precioDeTransferencia(".app");
    assert.ok(app!.transferMxnCents < design!.transferMxnCents, "un TLD más barato debe costar menos");
  });

  it("un TLD sin precio real en AWS se rechaza en vez de regalarse", async () => {
    const { precioDeTransferencia } = await import("./tld-pricing.ts");
    // Precio cero es "AWS no lo ofrece de verdad", no una ganga.
    assert.equal(await precioDeTransferencia(".quesoazul"), null);
    assert.equal(await precioDeTransferencia(".noexiste"), null);
  });

  it("los 12 curados conservan su precio hecho a mano", async () => {
    const { precioDeTransferencia } = await import("./tld-pricing.ts");
    const dbm = await import("./db.ts");
    const com = await precioDeTransferencia(".com");
    assert.equal(com!.curado, true);
    assert.equal(com!.transferMxnCents, dbm.TLD_PRICES[".com"].transferMxnCents);
  });
});
