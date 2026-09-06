// Depósito del correo entrante en el servidor IMAP (Stalwart).
//
// Va por **JMAP sobre HTTPS** y no por LMTP a propósito: la plataforma donde vive
// el buzón sólo expone capa 7 hoy —ningún template declara puertos crudos— así que
// LMTP no es alcanzable desde aquí. JMAP además es el contrato público del
// servidor; leer su S3 por debajo sería acoplarse a su formato interno.
//
// Esto es un DESTINO ADICIONAL, no la fuente de verdad: el original sigue en S3
// vía SES. Por eso ningún fallo aquí puede romper el reenvío.

import { log } from "./logger.js";

const BASE = process.env.IMAP_JMAP_URL ?? "";
const USER = process.env.IMAP_JMAP_USER ?? "";
const PASS = process.env.IMAP_JMAP_PASSWORD ?? "";

/** Dominios con buzón IMAP, separados por coma. Vacío = nadie. */
function dominiosActivos(): Set<string> {
  return new Set(
    (process.env.IMAP_ENABLED_DOMAINS ?? "")
      .split(",")
      .map((d) => d.trim().toLowerCase())
      .filter(Boolean)
  );
}

export function imapHabilitado(domainName: string): boolean {
  if (!BASE || !USER || !PASS) return false;
  return dominiosActivos().has(domainName.toLowerCase());
}

function auth(): string {
  return `Basic ${Buffer.from(`${USER}:${PASS}`).toString("base64")}`;
}

interface Sesion { accountId: string; }
let sesionCache: { valor: Sesion; expira: number } | null = null;

/**
 * La sesión trae el accountId que piden todas las llamadas.
 *
 * Se cachea 10 minutos porque es una petición extra por correo, y el
 * `apiUrl` que devuelve el servidor se **descarta**: viene con su hostname
 * interno (detrás del proxy) y no resuelve desde fuera. La URL se arma sobre
 * IMAP_JMAP_URL, que es la pública.
 */
async function obtenerSesion(): Promise<Sesion> {
  if (sesionCache && sesionCache.expira > Date.now()) return sesionCache.valor;

  const res = await fetch(`${BASE}/.well-known/jmap`, {
    headers: { authorization: auth() },
    redirect: "follow",
    signal: AbortSignal.timeout(5_000),
  });
  if (!res.ok) throw new Error(`sesión JMAP ${res.status}`);
  const data = (await res.json()) as { accounts?: Record<string, unknown> };
  const accountId = Object.keys(data.accounts ?? {})[0];
  if (!accountId) throw new Error("la sesión JMAP no trae ninguna cuenta");

  sesionCache = { valor: { accountId }, expira: Date.now() + 600_000 };
  return sesionCache.valor;
}

async function jmap(cuerpo: unknown): Promise<any> {
  // Sin barra final: con ella el servidor redirige y el cuerpo del POST se pierde,
  // devolviendo "notRequest" con la petición entera en el detalle.
  const res = await fetch(`${BASE}/jmap`, {
    method: "POST",
    headers: { authorization: auth(), "content-type": "application/json" },
    body: JSON.stringify(cuerpo),
    redirect: "follow",
    signal: AbortSignal.timeout(6_000),
  });
  if (!res.ok) throw new Error(`JMAP ${res.status}`);
  return await res.json();
}

/** Id del buzón por rol (`inbox`), que es estable entre servidores e idiomas. */
async function buzonInbox(accountId: string): Promise<string> {
  const r = await jmap({
    using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    methodCalls: [["Mailbox/query", { accountId, filter: { role: "inbox" } }, "c0"]],
  });
  const ids = r?.methodResponses?.[0]?.[1]?.ids ?? [];
  if (!ids.length) throw new Error("la cuenta no tiene INBOX");
  return ids[0];
}

/**
 * Deposita el mensaje crudo en el buzón. Devuelve true si quedó guardado.
 *
 * Nunca lanza: el llamador está en el camino del reenvío y un buzón caído no
 * puede impedir que el correo llegue a su destino.
 */
export async function depositarEnImap(rawContent: string, domainName: string): Promise<boolean> {
  if (!imapHabilitado(domainName)) return false;

  // Presupuesto total. Esto corre DENTRO del camino del reenvío: sin un tope
  // global, un buzón que acepta la conexión pero no contesta sumaría los tres
  // timeouts internos —hasta un minuto— a la entrega de un correo que no tiene
  // nada que ver con IMAP.
  // El temporizador se limpia SIEMPRE al terminar la carrera. Un `unref()` no
  // sirve aquí: dejaría de sostener el bucle y entonces no dispararía cuando no
  // haya nada más pendiente. Y sin limpiarlo, cada correo dejaría un temporizador
  // vivo ocho segundos — que es la misma trampa que documentó `scheduler.ts`.
  let cronometro: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      depositar(rawContent, domainName),
      new Promise<boolean>((resolve) => {
        cronometro = setTimeout(() => {
          log("error", "forwarding", "El buzón IMAP no respondió a tiempo; el correo se reenvía igual", {
            domain: domainName,
            limiteMs: PRESUPUESTO_MS,
          });
          resolve(false);
        }, PRESUPUESTO_MS);
      }),
    ]);
  } finally {
    clearTimeout(cronometro);
  }
}

/** Segundos, no minutos: el reenvío es lo que no puede esperar. */
const PRESUPUESTO_MS = 8_000;

async function depositar(rawContent: string, domainName: string): Promise<boolean> {
  try {
    const { accountId } = await obtenerSesion();

    // El mensaje se sube como blob y luego se importa: es el camino de JMAP para
    // meter un correo ya formado, sin reconstruirlo campo por campo.
    const up = await fetch(`${BASE}/jmap/upload/${accountId}/`, {
      method: "POST",
      headers: { authorization: auth(), "content-type": "message/rfc822" },
      body: rawContent,
      redirect: "follow",
      signal: AbortSignal.timeout(7_000),
    });
    if (!up.ok) throw new Error(`upload ${up.status}`);
    const { blobId } = (await up.json()) as { blobId: string };

    const mailboxId = await buzonInbox(accountId);
    const r = await jmap({
      using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
      methodCalls: [[
        "Email/import",
        {
          accountId,
          emails: {
            e1: { blobId, mailboxIds: { [mailboxId]: true }, keywords: {} },
          },
        },
        "c0",
      ]],
    });

    const resp = r?.methodResponses?.[0]?.[1];
    if (resp?.created?.e1) return true;
    throw new Error(`Email/import: ${JSON.stringify(resp?.notCreated ?? resp)}`);
  } catch (err) {
    log("error", "forwarding", "No se pudo depositar en el buzón IMAP", {
      domain: domainName,
      error: String(err),
    });
    return false;
  }
}
