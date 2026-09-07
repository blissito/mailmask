// Transferencia de dominios: traer uno que ya es del cliente (transfer-in) y dejarlo salir
// (transfer-out).
//
// La parte delicada no es hablar con AWS: es que el dominio **ya está en producción para
// alguien**. Si cambiamos sus nameservers con la zona vacía, su web y su correo mueren en el
// acto. Por eso nada se mueve sin un inventario de DNS aprobado por el cliente.
import { log } from "./logger.js";

/**
 * El auth code EPP vive en memoria y con caducidad: entregarlo es entregar el dominio, así
 * que no toca disco ni logs. En la fila sólo quedan sus últimos 4 caracteres.
 */
const AUTH_TTL_MS = 60 * 60_000;
const authCodes = new Map<string, { code: string; expira: number }>();

export function guardarAuthCode(regId: string, code: string): string {
  authCodes.set(regId, { code, expira: Date.now() + AUTH_TTL_MS });
  return code.slice(-4);
}

export function tomarAuthCode(regId: string): string | null {
  const g = authCodes.get(regId);
  if (!g) return null;
  if (g.expira < Date.now()) { authCodes.delete(regId); return null; }
  return g.code;
}

export function olvidarAuthCode(regId: string): void {
  authCodes.delete(regId);
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
