import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { app } from "./main.ts";
import { createUser, createDomain, getUser, setVerifyToken, verifyUserEmail } from "./db.ts";
import { signJwt, generateCsrfToken } from "./auth.ts";
import { sqlite } from "./pg.ts";

// IP única por petición: los rate limits viven en la DB compartida de la suite.
let ipCounter = 0;
const testIpBase = `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
function nextIp(): string { return `${testIpBase}.${ipCounter++ % 255}`; }

const VERIFY_ERROR = "Verifica tu email para continuar";
const DAY_MS = 24 * 3600_000;

function uniqueEmail(tag: string): string {
  return `verify-${tag}-${crypto.randomUUID()}@example.com`;
}

async function verifyLink(token: string): Promise<Response> {
  return await app.fetch(new Request(`http://localhost/api/auth/verify-email?token=${token}`, {
    headers: { "fly-client-ip": nextIp() },
  }));
}

function postAuthed(path: string, body: unknown, email: string): Promise<Response> {
  const csrf = generateCsrfToken();
  return jsonPost(path, body, email, csrf);
}

async function jsonPost(path: string, body: unknown, email: string, csrf: string): Promise<Response> {
  const cookie = `token=${await signJwt({ email })}; csrf_token=${csrf}`;
  return app.fetch(new Request(`http://localhost${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "fly-client-ip": nextIp(),
      cookie,
      "x-csrf-token": csrf,
    },
    body: JSON.stringify(body),
  }));
}

function setCreatedAt(email: string, msAgo: number): void {
  sqlite.prepare("UPDATE users SET created_at = ? WHERE email = ?")
    .run(new Date(Date.now() - msAgo).toISOString(), email);
}

function newVerifyToken(email: string): string | undefined {
  const row = sqlite.prepare(
    "SELECT token FROM tokens WHERE kind = 'verify' AND json_extract(value, '$.email') = ? ORDER BY expires_at DESC LIMIT 1",
  ).get(email) as { token: string } | undefined;
  return row?.token;
}

describe("Verificación de correo: el enlace desbloquea la cuenta", () => {
  it("el enlace recién emitido verifica la cuenta y redirige a /app?verified=true", async () => {
    const email = uniqueEmail("feliz");
    createUser(email, "no-usado:0000");
    const token = crypto.randomUUID();
    setVerifyToken(email, token);

    const res = await verifyLink(token);
    assert.equal(res.status, 302);
    assert.equal(res.headers.get("location"), "/app?verified=true");
    assert.equal(getUser(email)!.emailVerified, true);
  });

  it("el mismo enlace por segunda vez ya no sirve", async () => {
    const email = uniqueEmail("dos-veces");
    createUser(email, "no-usado:0000");
    const token = crypto.randomUUID();
    setVerifyToken(email, token);
    await (await verifyLink(token)).body?.cancel();

    const again = await verifyLink(token);
    assert.equal(again.status, 400);
    assert.equal(await again.text(), "Token inválido o expirado");
  });

  it("un enlace vencido no verifica a nadie", async () => {
    const email = uniqueEmail("vencido");
    createUser(email, "no-usado:0000");
    const token = crypto.randomUUID();
    setVerifyToken(email, token);
    sqlite.prepare("UPDATE tokens SET expires_at = ? WHERE token = ?")
      .run(new Date(Date.now() - 1000).toISOString(), token);

    const res = await verifyLink(token);
    assert.equal(res.status, 400);
    assert.equal(getUser(email)!.emailVerified, false);
  });

  it("un token inventado no verifica a nadie", async () => {
    const email = uniqueEmail("inventado");
    createUser(email, "no-usado:0000");

    const res = await verifyLink(`inventado-${crypto.randomUUID()}`);
    assert.equal(res.status, 400);
    assert.equal(getUser(email)!.emailVerified, false);
  });

  it("sin token no verifica a nadie", async () => {
    const email = uniqueEmail("sin-token");
    createUser(email, "no-usado:0000");

    const res = await app.fetch(new Request("http://localhost/api/auth/verify-email", {
      headers: { "fly-client-ip": nextIp() },
    }));
    assert.notEqual(res.status, 302);
    assert.equal(getUser(email)!.emailVerified, false);
  });

  it("un token de otro tipo con el mismo valor no verifica", async () => {
    const email = uniqueEmail("otro-tipo");
    createUser(email, "no-usado:0000");
    const token = crypto.randomUUID();
    sqlite.prepare("INSERT INTO tokens (token, kind, value, expires_at) VALUES (?, 'reset', ?, ?)")
      .run(token, JSON.stringify({ email }), new Date(Date.now() + DAY_MS).toISOString());

    const res = await verifyLink(token);
    assert.equal(res.status, 400);
    assert.equal(getUser(email)!.emailVerified, false);
  });

  it("reenviar el correo emite un enlace nuevo que verifica la cuenta", async () => {
    const email = uniqueEmail("reenvio");
    createUser(email, "no-usado:0000");

    await (await postAuthed("/api/auth/resend-verification", {}, email)).body?.cancel();
    const token = newVerifyToken(email);
    assert.ok(token, "el reenvío debe dejar un token de verificación guardado");

    const res = await verifyLink(token);
    assert.equal(res.status, 302);
    assert.equal(getUser(email)!.emailVerified, true);
  });

  // Documenta el comportamiento actual, no el deseado: reenviar NO invalida el enlace anterior
  // (setVerifyToken sólo inserta otra fila). Si se arregla, este caso debe cambiar de verde.
  it("BUG CONOCIDO: el enlace anterior sigue sirviendo después de reenviar", async () => {
    const email = uniqueEmail("viejo-vigente");
    createUser(email, "no-usado:0000");
    const viejo = crypto.randomUUID();
    setVerifyToken(email, viejo);

    await (await postAuthed("/api/auth/resend-verification", {}, email)).body?.cancel();

    const res = await verifyLink(viejo);
    assert.equal(res.status, 302);
  });

  it("cuenta sin verificar de 14 días puede agregar una dirección", async () => {
    const email = uniqueEmail("14-dias");
    createUser(email, "no-usado:0000");
    const domain = createDomain(email, `${crypto.randomUUID()}.example.test`, ["dkim1"], "vt-14");
    setCreatedAt(email, 14 * DAY_MS);

    const res = await postAuthed(`/api/domains/${domain.id}/alias`, { alias: "hola", destinations: ["d@example.com"] }, email);
    const body = await res.text();
    assert.ok(!body.includes(VERIFY_ERROR), `no debe bloquear antes de los 15 días: ${res.status} ${body}`);
    assert.notEqual(res.status, 403);
  });

  it("cuenta sin verificar de 16 días recibe 403 al agregar un dominio", async () => {
    const email = uniqueEmail("16-dominio");
    createUser(email, "no-usado:0000");
    setCreatedAt(email, 16 * DAY_MS);

    const res = await postAuthed("/api/domains", { domain: `${crypto.randomUUID().slice(0, 8)}.example.com` }, email);
    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { error: VERIFY_ERROR });
  });

  it("cuenta sin verificar de 16 días recibe 403 al crear una dirección", async () => {
    const email = uniqueEmail("16-alias");
    createUser(email, "no-usado:0000");
    const domain = createDomain(email, `${crypto.randomUUID()}.example.test`, ["dkim1"], "vt-16");
    setCreatedAt(email, 16 * DAY_MS);

    const res = await postAuthed(`/api/domains/${domain.id}/alias`, { alias: "hola", destinations: ["d@example.com"] }, email);
    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { error: VERIFY_ERROR });
  });

  it("cuenta verificada de 16 días sí puede crear una dirección", async () => {
    const email = uniqueEmail("16-verificada");
    createUser(email, "no-usado:0000");
    const domain = createDomain(email, `${crypto.randomUUID()}.example.test`, ["dkim1"], "vt-ok");
    setCreatedAt(email, 16 * DAY_MS);
    verifyUserEmail(email);

    const res = await postAuthed(`/api/domains/${domain.id}/alias`, { alias: "hola", destinations: ["d@example.com"] }, email);
    const body = await res.text();
    assert.ok(!body.includes(VERIFY_ERROR), `verificada no debe bloquearse: ${res.status} ${body}`);
  });
});
