import { describe, it, mock, afterEach } from "node:test";
import assert from "node:assert/strict";

import { verificarTurnstile, turnstileActivo } from "./turnstile.ts";
import { app } from "./main.ts";

const fetchReal = globalThis.fetch;
const secretoPrevio = process.env.TURNSTILE_SECRET;
const entornoPrevio = process.env.NODE_ENV;

afterEach(() => {
  globalThis.fetch = fetchReal;
  if (secretoPrevio === undefined) delete process.env.TURNSTILE_SECRET;
  else process.env.TURNSTILE_SECRET = secretoPrevio;
  if (entornoPrevio === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = entornoPrevio;
});

/** Finge la respuesta de siteverify y anota si llegó a llamarse. */
function fingirSiteverify(respuesta: unknown) {
  const llamadas: { url: string; params: URLSearchParams }[] = [];
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    llamadas.push({ url: String(url), params: new URLSearchParams(String(init.body)) });
    return new Response(JSON.stringify(respuesta), { status: 200 });
  }) as typeof fetch;
  return llamadas;
}

describe("Turnstile", () => {
  it("🔴 con secreto configurado SIEMPRE llama a siteverify", async () => {
    process.env.TURNSTILE_SECRET = "secreto-de-prueba";
    const llamadas = fingirSiteverify({ success: true });
    const r = await verificarTurnstile("token-del-widget", "1.2.3.4");
    assert.equal(r.ok, true);
    // Es el punto entero del captcha: un widget cuyo token no se canjea no
    // protege nada, y Cloudflare lo reporta como "siteverify isn't being called".
    assert.equal(llamadas.length, 1);
    assert.match(llamadas[0].url, /challenges\.cloudflare\.com\/turnstile\/v0\/siteverify/);
    assert.equal(llamadas[0].params.get("secret"), "secreto-de-prueba");
    assert.equal(llamadas[0].params.get("response"), "token-del-widget");
    assert.equal(llamadas[0].params.get("remoteip"), "1.2.3.4");
  });

  it("rechaza cuando Cloudflare dice que no", async () => {
    process.env.TURNSTILE_SECRET = "secreto-de-prueba";
    fingirSiteverify({ success: false, "error-codes": ["invalid-input-response"] });
    const r = await verificarTurnstile("token-falso");
    assert.equal(r.ok, false);
    assert.deepEqual(r.errores, ["invalid-input-response"]);
  });

  it("rechaza un token vacío, ausente o absurdamente largo sin salir a la red", async () => {
    process.env.TURNSTILE_SECRET = "secreto-de-prueba";
    const llamadas = fingirSiteverify({ success: true });
    for (const malo of ["", undefined, null, 42, "x".repeat(3000)]) {
      const r = await verificarTurnstile(malo);
      assert.equal(r.ok, false, `debió rechazar: ${String(malo).slice(0, 20)}`);
    }
    assert.equal(llamadas.length, 0);
  });

  it("si siteverify no responde, rechaza: no comprobado no es comprobado", async () => {
    process.env.TURNSTILE_SECRET = "secreto-de-prueba";
    globalThis.fetch = (async () => { throw new Error("red caída"); }) as typeof fetch;
    const r = await verificarTurnstile("token");
    assert.equal(r.ok, false);
    assert.deepEqual(r.errores, ["internal-error"]);
  });

  it("🔴 en producción sin secreto CIERRA el registro, no lo deja abierto", async () => {
    delete process.env.TURNSTILE_SECRET;
    process.env.NODE_ENV = "production";
    assert.equal(turnstileActivo(), false);
    const r = await verificarTurnstile("lo-que-sea");
    // El caso peligroso: widget pintado, secreto ausente, formulario abierto.
    assert.equal(r.ok, false);
    assert.deepEqual(r.errores, ["missing-secret"]);
  });

  it("fuera de producción sin secreto deja pasar, para dev y pruebas", async () => {
    delete process.env.TURNSTILE_SECRET;
    process.env.NODE_ENV = "test";
    const r = await verificarTurnstile(undefined);
    assert.equal(r.ok, true);
  });
});

describe("El registro sí canjea el token", () => {
  it("🔴 POST /api/auth/register llama a siteverify y rechaza si Cloudflare dice que no", async () => {
    process.env.TURNSTILE_SECRET = "secreto-de-prueba";
    let canjeado = false;
    const real = fetchReal;
    globalThis.fetch = (async (url: any, init: any) => {
      if (String(url).includes("siteverify")) {
        canjeado = true;
        return new Response(JSON.stringify({ success: false, "error-codes": ["invalid-input-response"] }), { status: 200 });
      }
      return real(url, init);
    }) as typeof fetch;

    const correo = `bot-${Math.random().toString(36).slice(2, 10)}@ejemplo.com`;
    const res = await app.fetch(new Request("http://localhost/api/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json", "x-forwarded-for": `10.9.9.${Math.floor(Math.random() * 250)}` },
      body: JSON.stringify({ email: correo, password: "contrasena-larga", turnstileToken: "token-de-bot" }),
    }));

    // Si esta prueba falla porque `canjeado` es false, el widget está de adorno:
    // es exactamente el aviso "siteverify isn't being called" de Cloudflare.
    assert.equal(canjeado, true, "el registro debe canjear el token contra Cloudflare");
    assert.equal(res.status, 400);
  });

  it("🔴 POST /api/auth/forgot-password también lo canjea: manda correo por nuestro SES", async () => {
    process.env.TURNSTILE_SECRET = "secreto-de-prueba";
    let canjeado = false;
    const real = fetchReal;
    globalThis.fetch = (async (url: any, init: any) => {
      if (String(url).includes("siteverify")) {
        canjeado = true;
        return new Response(JSON.stringify({ success: false, "error-codes": ["invalid-input-response"] }), { status: 200 });
      }
      return real(url, init);
    }) as typeof fetch;

    const res = await app.fetch(new Request("http://localhost/api/auth/forgot-password", {
      method: "POST",
      headers: { "content-type": "application/json", "x-forwarded-for": `10.9.8.${Math.floor(Math.random() * 250)}` },
      body: JSON.stringify({ email: "quien-sea@ejemplo.com", turnstileToken: "token-de-bot" }),
    }));

    assert.equal(canjeado, true, "la recuperación debe canjear el token contra Cloudflare");
    assert.equal(res.status, 400);
  });
});
