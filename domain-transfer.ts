// Transferencia de dominios: traer uno que ya es del cliente (transfer-in) y dejarlo salir
// (transfer-out).
//
// La parte delicada no es hablar con AWS: es que el dominio **ya está en producción para
// alguien**. Si cambiamos sus nameservers con la zona vacía, su web y su correo mueren en el
// acto. Por eso nada se mueve sin un inventario de DNS aprobado por el cliente.
import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from "node:crypto";
import { log } from "./logger.js";
import { sqlite } from "./pg.js";

/**
 * El auth code EPP: entregarlo es entregar el dominio. Se guarda cifrado con AES-256-GCM y
 * la llave vive en el entorno, no en la base: un respaldo o un volcado de SQLite no lo
 * expone. En la fila del registro sólo quedan sus últimos 4 caracteres.
 *
 * Antes vivía en un Map en memoria con una hora de vida, y un deploy o un pago lento
 * (24-sep-2026, kandey.com.mx) dejaba la transferencia pagada y sin poderse mandar. Ahora
 * dura lo que puede durar un pago y se borra en cuanto AWS acepta la solicitud.
 */
const AUTH_TTL_MS = 7 * 864e5;

function encryptionKey(): Buffer {
  const explicit = process.env.EPP_ENCRYPTION_KEY;
  if (explicit) return createHash("sha256").update(explicit).digest();
  const jwt = process.env.JWT_SECRET;
  if (!jwt) throw new Error("Falta EPP_ENCRYPTION_KEY (o JWT_SECRET) para cifrar el código EPP");
  return Buffer.from(hkdfSync("sha256", jwt, "mailmask", "epp-auth-code", 32));
}

export function saveAuthCode(regId: string, code: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const body = Buffer.concat([cipher.update(code, "utf8"), cipher.final()]);
  const ciphertext = [iv, cipher.getAuthTag(), body].map((b) => b.toString("base64")).join(".");
  sqlite.prepare(`
    INSERT INTO transfer_auth_codes (registration_id, ciphertext, expires_at) VALUES (?, ?, ?)
    ON CONFLICT (registration_id) DO UPDATE SET ciphertext = excluded.ciphertext, expires_at = excluded.expires_at
  `).run(regId, ciphertext, Date.now() + AUTH_TTL_MS);
  return code.slice(-4);
}

export function takeAuthCode(regId: string): string | null {
  const row = sqlite.prepare(`SELECT ciphertext, expires_at FROM transfer_auth_codes WHERE registration_id = ?`)
    .get(regId) as { ciphertext: string; expires_at: number } | undefined;
  if (!row) return null;
  if (row.expires_at < Date.now()) { forgetAuthCode(regId); return null; }
  try {
    const [iv, tag, body] = row.ciphertext.split(".").map((p) => Buffer.from(p, "base64"));
    const decipher = createDecipheriv("aes-256-gcm", encryptionKey(), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8");
  } catch {
    // Llave rotada o dato corrupto: es lo mismo que no tenerlo, y se pide otra vez.
    log("warn", "route53", "No se pudo descifrar el código EPP guardado", { regId });
    return null;
  }
}

export function forgetAuthCode(regId: string): void {
  sqlite.prepare(`DELETE FROM transfer_auth_codes WHERE registration_id = ?`).run(regId);
}

export interface Requisito {
  clave: string;
  ok: boolean | null;
  texto: string;
  ayuda?: string;
}

/**
 * Requisitos del transfer-in, comprobados **antes de cobrar**. `ok: null` = no lo pudimos
 * verificar y lo tiene que confirmar el cliente.
 */
export async function checkDomainReadiness(domain: string): Promise<{ listo: boolean; requisitos: Requisito[] }> {
  const requisitos: Requisito[] = [];

  // 1. Lo que dice AWS.
  try {
    const { checkTransferability } = await import("./route53.js");
    const t = await checkTransferability(domain);
    requisitos.push({
      clave: "aws",
      // Un UNTRANSFERABLE de AWS es un NO, no un "quién sabe": dejarlo pasar significa
      // cobrarle al cliente una transferencia que no puede ocurrir.
      ok: t.transferable ? true : false,
      texto: "El registrador actual permite la transferencia",
      ayuda: t.motivo ?? undefined,
    });
  } catch (err) {
    log("warn", "route53", "checkTransferability falló", { domain, error: String(err) });
    requisitos.push({ clave: "aws", ok: null, texto: "El registrador actual permite la transferencia", ayuda: "No pudimos consultarlo ahora." });
  }

  // 2. RDAP: edad y candado. Es HTTP puro, no hace falta una librería de WHOIS.
  let edadOk: boolean | null = null;
  let lockOk: boolean | null = null;
  let lockServidor = false;
  let registrador: string | null = null;
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: {
        accept: "application/rdap+json",
        // Sin User-Agent, Cloudflare contesta 403 con una página HTML y el JSON.parse
        // revienta. La consulta fallaba SIEMPRE y todos los requisitos salían como "?".
        "user-agent": "MailMask/1.0 (+https://www.mailmask.studio)",
      },
      signal: AbortSignal.timeout(12_000),
      redirect: "follow",
    });
    if (res.ok && (res.headers.get("content-type") ?? "").includes("json")) {
      const j: any = await res.json();
      const alta = (j.events ?? []).find((e: any) => e.eventAction === "registration")?.eventDate;
      if (alta) edadOk = Date.now() - Date.parse(alta) > 60 * 864e5;
      const estados: string[] = j.status ?? [];
      // `server transfer prohibited` no lo puede quitar el cliente desde su panel: lo pone
      // el registro. Se distingue del `client…`, que sí depende de él.
      lockServidor = estados.some((e) => /server transfer prohibited/i.test(e));
      lockOk = !estados.some((e) => /transfer prohibited/i.test(e));
      registrador = (j.entities ?? []).find((e: any) => (e.roles ?? []).includes("registrar"))?.vcardArray?.[1]
        ?.find((v: any[]) => v[0] === "fn")?.[3] ?? null;
    }
  } catch (err) {
    log("warn", "route53", "RDAP falló", { domain, error: String(err) });
  }

  requisitos.push({
    clave: "edad",
    ok: edadOk,
    texto: "El dominio tiene más de 60 días",
    ayuda: edadOk === false
      ? "Los registros y transferencias recientes quedan bloqueados 60 días por regla del ICANN. No hay forma de saltarlo."
      : undefined,
  });
  requisitos.push({
    clave: "lock",
    ok: lockOk,
    texto: "El candado de transferencia está desactivado",
    ayuda: lockOk === false
      ? (lockServidor
        ? "El bloqueo lo puso el registro del dominio, no tu registrador: suele pasar los primeros 60 días o tras un cambio de titular. Hay que esperar a que caiga."
        : "Entra a tu registrador actual y desactiva el 'transfer lock' o 'bloqueo de transferencia'.")
      : undefined,
  });
  // Estos dos no se pueden comprobar desde fuera: los confirma el cliente.
  requisitos.push({
    clave: "whois",
    ok: null,
    texto: "La privacidad WHOIS está apagada",
    ayuda: "Con la privacidad encendida, el correo de aprobación no te llega. Apágala en tu registrador y vuelve a encenderla cuando termine.",
  });
  requisitos.push({
    clave: "correo",
    ok: null,
    texto: "Puedes leer el correo del contacto administrativo",
    ayuda: "Tu registrador te mandará ahí un correo de aprobación. Si no lo contestas, la transferencia se cancela sola en unos días.",
  });
  requisitos.push({
    clave: "authcode",
    ok: null,
    texto: "Tienes el código de autorización (EPP)",
    ayuda: "Se pide en el panel de tu registrador actual. A veces se llama 'código EPP', 'auth code' o 'código de transferencia'.",
  });

  return { listo: !requisitos.some((r) => r.ok === false), requisitos, ...(registrador ? { registrador } : {}) } as never;
}
