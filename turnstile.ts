// Verificación de Cloudflare Turnstile.
//
// El widget del navegador no prueba nada por sí solo: el token que produce hay
// que canjearlo contra Cloudflare desde el servidor, con la clave secreta. Sin
// ese canje, cualquiera manda un token inventado.

import { log } from "./logger.js";

const ENDPOINT = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/** Sin secreto configurado no hay verificación: es el caso de las pruebas y de dev. */
export function turnstileActivo(): boolean {
  return !!process.env.TURNSTILE_SECRET;
}

const enProduccion = () => process.env.NODE_ENV === "production";

export interface TurnstileResult {
  ok: boolean;
  /** Códigos que devuelve Cloudflare; sólo para el log, nunca para el usuario. */
  errores?: string[];
}

export async function verificarTurnstile(token: unknown, ip?: string): Promise<TurnstileResult> {
  // Sin secreto se falla ABIERTO en local y en la suite —para que el registro
  // siga siendo probable sin credenciales— y CERRADO en producción.
  //
  // Ese segundo caso es el que importa: el widget pintado en la página no
  // protege nada por sí solo, y si el secreto falta en producción tendríamos un
  // captcha decorativo con el formulario abierto de par en par. Cloudflare lo
  // reporta como "siteverify isn't being called". Prefiero un registro caído y
  // ruidoso a uno abierto y silencioso.
  if (!turnstileActivo()) {
    if (enProduccion()) {
      log("error", "auth", "TURNSTILE_SECRET no está configurado en producción: el registro queda cerrado");
      return { ok: false, errores: ["missing-secret"] };
    }
    return { ok: true };
  }

  if (typeof token !== "string" || token.length === 0 || token.length > 2048) {
    return { ok: false, errores: ["missing-input-response"] };
  }

  const cuerpo = new URLSearchParams({
    secret: process.env.TURNSTILE_SECRET!,
    response: token,
  });
  if (ip) cuerpo.set("remoteip", ip);

  try {
    const res = await fetch(ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: cuerpo,
      signal: AbortSignal.timeout(10_000),
    });
    const data = (await res.json()) as { success?: boolean; "error-codes"?: string[] };
    if (data.success === true) return { ok: true };
    return { ok: false, errores: data["error-codes"] ?? [] };
  } catch (err) {
    // Cloudflare caído o red lenta. Se rechaza en vez de dejar pasar: si el
    // captcha no se puede comprobar, no está comprobado. El usuario reintenta.
    log("error", "auth", "Turnstile siteverify falló", { error: String(err) });
    return { ok: false, errores: ["internal-error"] };
  }
}
