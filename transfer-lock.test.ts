// Candado de transferencia: ponerlo es un clic, quitarlo pasa por correo y sólo con la
// sesión del panel, y vuelve solo a los 7 días.
//
// Lo que se fija aquí es la asimetría: un agente (o alguien con una API key robada) puede
// proteger el dominio pero nunca desprotegerlo, y un candado quitado sin fecha de regreso
// no existe salvo que alguien lo quite por fuera de la app — y entonces salta la alerta.

import { describe, it, before, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";

const suffix = Date.now();

// Estado del candado en "AWS", por dominio.
const candados = new Map<string, boolean>();
const llamadas: string[] = [];
const correos: { to: string; subject: string; text: string }[] = [];
const alertas: string[] = [];
let pendingTransfer = false;

describe("candado de transferencia", () => {
  // deno-lint-ignore no-explicit-any
  let app: any, dbmod: any, sqlite: any, sync: any;
  let cookie = "";
  let csrf = "";
  let apiKey = "";
  const email = `candado-${suffix}@example.com`;

  before(async () => {
    mock.module("./route53.ts", {
      namedExports: {
        enableDomainTransferLock: async (d: string) => { llamadas.push(`lock:${d}`); candados.set(d, true); },
        disableDomainTransferLock: async (d: string) => { llamadas.push(`unlock:${d}`); candados.set(d, false); },
        getDomainDetail: async (d: string) => {
          const lock = candados.get(d) ?? true;
          const statusList = [...(lock ? ["clientTransferProhibited"] : []), ...(pendingTransfer ? ["pendingTransfer"] : [])];
          return { expirationDate: "2028-01-01T00:00:00.000Z", autoRenew: true, nameservers: [], statusList, transferLock: lock };
        },
        listRegisteredDomains: async () => [...candados.keys()].map((d) => ({ domainName: d, expirationDate: null, autoRenew: true })),
        retrieveDomainAuthCode: async () => "EPP-SECRETO",
      },
    });
    const realSes = await import("./ses.ts");
    mock.module("./ses.ts", {
      namedExports: {
        ...realSes,
        sendAlert: async (_t: string, m: string) => { alertas.push(m); return true; },
        sendFromDomain: async (_f: string, to: string, subject: string, text: string) => {
          correos.push({ to, subject, text });
          return { messageId: "<x@test>", sesMessageId: "s" };
        },
      },
    });

    ({ app } = await import("./main.ts"));
    dbmod = await import("./db.ts");
    ({ sqlite } = await import("./pg.ts"));
    sync = await import("./domain-sync.ts");

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
    apiKey = (await dbmod.createApiKey(email, "pruebas")).plaintextKey;
  });

  beforeEach(() => {
    llamadas.length = 0; correos.length = 0; alertas.length = 0;
    pendingTransfer = false;
    sqlite.prepare("DELETE FROM rate_limits").run();
  });

  /** Registro ya `registered`; por defecto con más de 60 días (fuera de la regla de ICANN). */
  const crear = (extra: Record<string, unknown> = {}) => {
    const domainName = `c${Math.random().toString(36).slice(2, 8)}-${suffix}.com`;
    const reg = dbmod.createDomainRegistration({
      domainName, ownerEmail: email, tld: ".com", priceCents: 30000, awsCostCents: 1500,
      whoisContact: { firstName: "Ana", lastName: "López", email: "whois@example.com", phone: "+52.5512345678", address: "C 1", city: "X", state: "DF", country: "MX", zip: "06600" },
    });
    dbmod.updateDomainRegistration(reg.id, {
      status: "registered",
      registeredAt: new Date(Date.now() - 90 * 864e5).toISOString(),
      expiresAt: "2028-01-01T00:00:00.000Z",
      transferLock: true,
      ...extra,
    });
    candados.set(domainName, (extra.transferLock as boolean | undefined) ?? true);
    return dbmod.getDomainRegistration(reg.id);
  };

  const conSesion = (ruta: string, body: unknown) =>
    app.fetch(new Request(`http://localhost${ruta}`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie, "x-csrf-token": csrf },
      body: JSON.stringify(body),
    }));
  const conLlave = (ruta: string, body: unknown) =>
    app.fetch(new Request(`http://localhost${ruta}`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify(body),
    }));
  const tokenDelCorreo = (patron: RegExp) => {
    const c = correos.find((x) => patron.test(x.text));
    return c ? patron.exec(c.text)![1] : null;
  };

  it("poner el candado es directo, también con una API key", async () => {
    const reg = crear({ transferLock: false });
    const res = await conLlave(`/api/domains/registrations/${reg.id}/transfer-lock`, { locked: true });
    assert.equal(res.status, 200);
    assert.equal((await res.json()).transferLock, true);
    assert.deepEqual(llamadas, [`lock:${reg.domainName}`]);
    assert.equal(dbmod.getDomainRegistration(reg.id).transferLock, true);
  });

  it("quitarlo con un Bearer da 403 y no toca AWS ni manda correo", async () => {
    const reg = crear();
    const res = await conLlave(`/api/domains/registrations/${reg.id}/transfer-lock`, { locked: false });
    assert.equal(res.status, 403);
    assert.equal(llamadas.length, 0);
    assert.equal(correos.length, 0);
  });

  it("con sesión, quitarlo sólo manda un correo; el candado sigue puesto", async () => {
    const reg = crear();
    const res = await conSesion(`/api/domains/registrations/${reg.id}/transfer-lock`, { locked: false });
    assert.equal(res.status, 200);
    assert.equal(llamadas.length, 0, "no debe quitarse sin confirmar");
    assert.equal(dbmod.getDomainRegistration(reg.id).transferLock, true);
    assert.ok(tokenDelCorreo(/transfer-lock=([0-9a-f-]+)/), "el correo lleva el enlace de confirmación");
  });

  it("la confirmación quita el candado 7 días y avisa al dueño y al WHOIS con enlace para revertir", async () => {
    const reg = crear();
    await conSesion(`/api/domains/registrations/${reg.id}/transfer-lock`, { locked: false });
    const token = tokenDelCorreo(/transfer-lock=([0-9a-f-]+)/)!;
    correos.length = 0;

    // Con Bearer no se confirma, aunque se tenga el token.
    assert.equal((await conLlave("/api/domains/transfer-lock/confirm", { token })).status, 403);

    const res = await conSesion("/api/domains/transfer-lock/confirm", { token });
    assert.equal(res.status, 200);
    const j = await res.json();
    assert.equal(j.transferLock, false);
    const dias = (Date.parse(j.transferUnlockedUntil) - Date.now()) / 864e5;
    assert.ok(dias > 6.9 && dias <= 7, `vuelve en 7 días, no en ${dias}`);
    assert.deepEqual(llamadas, [`unlock:${reg.domainName}`]);
    assert.deepEqual(correos.map((c) => c.to).sort(), [email, "whois@example.com"].sort());

    // Un solo uso.
    assert.equal((await conSesion("/api/domains/transfer-lock/confirm", { token })).status, 400);

    // "No fui yo": el GET sólo pinta el botón (los escáneres de correo abren enlaces solos).
    const relock = tokenDelCorreo(/relock\?token=([0-9a-f-]+)/)!;
    llamadas.length = 0;
    const get = await app.fetch(new Request(`http://localhost/api/domains/transfer-lock/relock?token=${relock}`));
    assert.equal(get.status, 200);
    assert.equal(llamadas.length, 0, "el GET no debe mutar");
    // El POST lo hace sin sesión ni CSRF.
    const post = await app.fetch(new Request("http://localhost/api/domains/transfer-lock/relock", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `token=${relock}`,
    }));
    assert.equal(post.status, 200);
    assert.deepEqual(llamadas, [`lock:${reg.domainName}`]);
    const fila = dbmod.getDomainRegistration(reg.id);
    assert.equal(fila.transferLock, true);
    assert.equal(fila.transferUnlockedUntil, null);
  });

  it("antes de los 60 días de ICANN da 409 con la fecha", async () => {
    const reg = crear({ registeredAt: new Date(Date.now() - 10 * 864e5).toISOString() });
    const res = await conSesion(`/api/domains/registrations/${reg.id}/transfer-lock`, { locked: false });
    assert.equal(res.status, 409);
    const j = await res.json();
    assert.ok(j.transferEligibleAt > new Date().toISOString());
    assert.equal(correos.length, 0);
  });

  it("el cron vuelve a poner el candado vencido y avisa al dueño", async () => {
    const reg = crear({ transferLock: false, transferUnlockedUntil: new Date(Date.now() - 864e5).toISOString() });
    await sync.syncDomainExpirations();
    assert.ok(llamadas.includes(`lock:${reg.domainName}`));
    const fila = dbmod.getDomainRegistration(reg.id);
    assert.equal(fila.transferLock, true);
    assert.equal(fila.transferUnlockedUntil, null);
    assert.ok(correos.some((c) => c.to === email && /protegido/i.test(c.subject)));
  });

  it("el cron no toca un candado quitado y vigente, ni uno con transferencia de salida en curso", async () => {
    const vigente = crear({ transferLock: false, transferUnlockedUntil: new Date(Date.now() + 3 * 864e5).toISOString() });
    await sync.syncDomainExpirations();
    assert.ok(!llamadas.includes(`lock:${vigente.domainName}`));

    pendingTransfer = true;
    const saliendo = crear({ transferLock: false, transferUnlockedUntil: new Date(Date.now() - 864e5).toISOString() });
    await sync.syncDomainExpirations();
    assert.ok(!llamadas.includes(`lock:${saliendo.domainName}`), "poner el candado tumbaría la transferencia");
    candados.delete(vigente.domainName);
    candados.delete(saliendo.domainName);
  });

  it("sin candado y sin fecha de regreso, el cron alerta: alguien lo quitó por fuera", async () => {
    const reg = crear({ transferLock: true });
    candados.set(reg.domainName, false);
    await sync.syncDomainExpirations();
    assert.ok(alertas.some((a) => a.includes(reg.domainName) && /SIN candado/.test(a)));
    assert.equal(dbmod.getDomainRegistration(reg.id).transferLock, false);
    candados.delete(reg.domainName);
  });

  it("la lista expone el candado y la fecha de ICANN; otra cuenta no puede tocarlo", async () => {
    const reg = crear();
    const res = await app.fetch(new Request("http://localhost/api/domains/registrations", { headers: { cookie } }));
    const fila = (await res.json()).find((r: { id: string }) => r.id === reg.id);
    assert.equal(fila.transferLock, true);
    assert.ok(fila.transferEligibleAt);
    assert.equal(fila.awsCostCents, undefined);

    const { hashPassword } = await import("./auth.ts");
    const otro = `candado-otro-${suffix}@example.com`;
    dbmod.createUser(otro, await hashPassword("password123"));
    const suLlave = (await dbmod.createApiKey(otro, "x")).plaintextKey;
    const ajeno = await app.fetch(new Request(`http://localhost/api/domains/registrations/${reg.id}/transfer-lock`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${suLlave}` },
      body: JSON.stringify({ locked: true }),
    }));
    assert.equal(ajeno.status, 404);
  });
});
