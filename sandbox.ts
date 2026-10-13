// Cuentas de revisión (directorios de Claude y ChatGPT, 13-oct-2026): entran con correo y
// contraseña, tienen un dominio de muestra activado y pueden usar todo, pero NINGÚN correo
// suyo sale a un tercero real. Se reconocen por el correo (`*-review@mailmask.studio`): es
// sólo una restricción, así que registrarse con un correo así no da nada de más.
//
// Un correo de la cuenta sólo puede ir a: su propio correo, sus propios dominios, o dominios
// reservados por el RFC 2606/6761 (example.com, *.test, …), que no entregan a nadie.
import { getDomainByName, listUserDomains } from "./db.js";

const SANDBOX_ACCOUNT_RE = /-review@mailmask\.studio$/i;
const RESERVED_DOMAINS = ["example.com", "example.net", "example.org"];
const RESERVED_TLDS = [".example", ".test", ".invalid", ".localhost"];

export function isSandboxAccount(email: string | null | undefined): boolean {
  return !!email && SANDBOX_ACCOUNT_RE.test(email.trim());
}

function bare(addr: string): string {
  const m = addr.match(/<([^>]+)>/);
  return (m ? m[1] : addr).trim().toLowerCase();
}

function isReserved(domain: string): boolean {
  return RESERVED_DOMAINS.some((d) => domain === d || domain.endsWith(`.${d}`)) || RESERVED_TLDS.some((t) => domain.endsWith(t));
}

/** Destinatarios que una cuenta de revisión NO puede alcanzar. Vacío = se puede enviar. */
export function sandboxBlockedRecipients(ownerEmail: string, recipients: string[]): string[] {
  if (!isSandboxAccount(ownerEmail)) return [];
  const own = listUserDomains(ownerEmail).map((d) => d.domain.toLowerCase());
  const owner = ownerEmail.trim().toLowerCase();
  return recipients.map(bare).filter((r) => {
    if (r === owner) return false;
    const dom = r.split("@")[1] ?? "";
    return !(own.some((d) => dom === d || dom.endsWith(`.${d}`)) || isReserved(dom));
  });
}

/** Igual, pero a partir del dominio remitente (lo que conoce `ses.ts`). */
export function sandboxBlockedFromDomain(fromDomain: string, recipients: string[]): string[] {
  const d = getDomainByName(fromDomain.toLowerCase());
  return d ? sandboxBlockedRecipients(d.ownerEmail, recipients) : [];
}

export const SANDBOX_SEND_ERROR = "Cuenta de revisión: sólo envía correo a sus propios dominios o a dominios de ejemplo (example.com).";

export class SandboxSendError extends Error {
  constructor(public blocked: string[]) { super(`${SANDBOX_SEND_ERROR} Bloqueado: ${blocked.join(", ")}`); }
}

/** 403 listo para una ruta, o null si se puede enviar. */
export function sandboxSendResponse(ownerEmail: string, recipients: string[]): Response | null {
  const blocked = sandboxBlockedRecipients(ownerEmail, recipients);
  if (!blocked.length) return null;
  return new Response(JSON.stringify({ error: `${SANDBOX_SEND_ERROR} Bloqueado: ${blocked.join(", ")}` }), { status: 403, headers: { "content-type": "application/json" } });
}
