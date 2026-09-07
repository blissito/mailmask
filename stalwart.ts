// Provisión de buzones en el servidor IMAP (Stalwart 0.16.x).
//
// La administración NO va por REST: `/api/principal` devuelve 404 en 0.16 y todo
// vive en JMAP, en las extensiones `x:*` bajo "urn:stalwart:jmap". La lista completa
// de métodos y campos está en `GET /api/schema` de la propia caja.
//
// Auth HTTP Basic con la credencial de administrador. Es la MISMA que entrega el
// correo en `imap-store.ts`: Stalwart autoriza al admin por petición, así que un
// `accountId` ajeno en `Email/import` simplemente funciona. Por eso nunca guardamos
// la contraseña de un buzón — se genera, se muestra una vez y se olvida.

import { log } from "./logger.js";

// El entorno se lee en cada llamada, no al importar el módulo: así las pruebas
// pueden cambiarlo entre casos, y un secreto que llegue tarde no deja el proceso
// creyendo para siempre que no hay servidor.
const base = () => (process.env.STALWART_ADMIN_URL ?? "").replace(/\/+$/, "");
const usuario = () => process.env.STALWART_ADMIN_USER ?? "admin";
const clave = () => process.env.STALWART_ADMIN_PASSWORD ?? "";

export function stalwartConfigurado(): boolean {
  return Boolean(base() && usuario() && clave());
}

export type Resultado<T> =
  | { ok: true; valor: T }
  | { ok: false; error: string };

function fallo(error: string): Resultado<never> {
  return { ok: false, error };
}

function auth(): string {
  return `Basic ${Buffer.from(`${usuario()}:${clave()}`).toString("base64")}`;
}

const CORE = "urn:ietf:params:jmap:core";
const STALWART = "urn:stalwart:jmap";
const PRINCIPALS = "urn:ietf:params:jmap:principals";

/**
 * POST a `${BASE}/jmap` — **sin barra final**. Con ella el servidor redirige, el
 * cuerpo del POST se pierde y contesta `notRequest` con la petición entera en el
 * detalle, que es un error que no se parece en nada a su causa.
 */
async function jmap(using: string[], methodCalls: unknown[][], msTimeout = 8_000): Promise<any> {
  const res = await fetch(`${base()}/jmap`, {
    method: "POST",
    headers: { authorization: auth(), "content-type": "application/json" },
    body: JSON.stringify({ using, methodCalls }),
    redirect: "follow",
    signal: AbortSignal.timeout(msTimeout),
  });
  if (!res.ok) throw new Error(`JMAP ${res.status}`);
  return await res.json();
}

/** Primera respuesta de una llamada JMAP, o `null` si vino un `error`. */
function respuesta(r: any): any {
  const par = r?.methodResponses?.[0];
  if (!par || par[0] === "error") return null;
  return par[1];
}

// --- Dominios ---

// El id del dominio casi nunca cambia y hace falta en cada alta, así que se cachea.
const dominios = new Map<string, string>();

export async function domainId(domain: string): Promise<string | null> {
  const clave = domain.toLowerCase();
  const visto = dominios.get(clave);
  if (visto) return visto;

  const r = await jmap([CORE, STALWART], [["x:Domain/query", { filter: { name: clave } }, "c0"]]);
  const ids: string[] = respuesta(r)?.ids ?? [];
  if (!ids.length) return null;
  dominios.set(clave, ids[0]);
  return ids[0];
}

// --- Traducción dirección -> cuenta ---

// El `accountId` es lo que piden todas las llamadas de correo. `Principal/query`
// resuelve **también los alias**, y devuelve lista vacía —no un error— cuando la
// dirección no existe. Ese vacío es el fail-closed del depósito: sin buzón conocido,
// no se deposita, y así el correo de un dominio no puede caer en el buzón de otro.
const cuentas = new Map<string, { valor: string | null; expira: number }>();
const TTL_CUENTA_MS = 600_000;

export function olvidarCuenta(email: string): void {
  cuentas.delete(email.toLowerCase());
}

export async function accountIdDe(email: string): Promise<string | null> {
  const clave = email.toLowerCase();
  const visto = cuentas.get(clave);
  if (visto && visto.expira > Date.now()) return visto.valor;

  let valor: string | null = null;
  try {
    // `Principal/query` filtra global pero exige el accountId de QUIEN llama.
    const yo = await cuentaPropia();
    const r = await jmap([CORE, PRINCIPALS], [["Principal/query", { accountId: yo, filter: { email: clave } }, "c0"]]);
    valor = respuesta(r)?.ids?.[0] ?? null;
  } catch (err) {
    // Un fallo de red no es "no existe": no se cachea, para no dejar un buzón
    // legítimo marcado como inexistente durante diez minutos.
    log("error", "mesa", "No se pudo resolver el buzón en Stalwart", { email: clave, error: String(err) });
    return null;
  }

  cuentas.set(clave, { valor, expira: Date.now() + TTL_CUENTA_MS });
  return valor;
}

let cuentaPropiaCache: { valor: string; expira: number } | null = null;

/** El accountId del propio administrador, que `Principal/query` exige en los argumentos. */
async function cuentaPropia(): Promise<string> {
  if (cuentaPropiaCache && cuentaPropiaCache.expira > Date.now()) return cuentaPropiaCache.valor;

  const res = await fetch(`${base()}/jmap/session`, {
    headers: { authorization: auth() },
    redirect: "follow",
    signal: AbortSignal.timeout(5_000),
  });
  if (!res.ok) throw new Error(`sesión JMAP ${res.status}`);
  const data = (await res.json()) as { primaryAccounts?: Record<string, string>; accounts?: Record<string, unknown> };
  const id = Object.values(data.primaryAccounts ?? {})[0] ?? Object.keys(data.accounts ?? {})[0];
  if (!id) throw new Error("la sesión JMAP no trae ninguna cuenta");

  cuentaPropiaCache = { valor: id, expira: Date.now() + TTL_CUENTA_MS };
  return id;
}

// --- Contraseñas ---

/**
 * Stalwart rechaza contraseñas débiles con un medidor tipo zxcvbn ("This is similar
 * to a commonly used password"), no con una regla de caracteres. Así que no se trata
 * de "cumplir una política" sino de tener entropía de verdad: 24 caracteres base58
 * salidos de `crypto`, que además evita los pares que se confunden al dictarlas.
 */
const ALFABETO = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export function generarPassword(largo = 24): string {
  const bytes = crypto.getRandomValues(new Uint8Array(largo));
  let out = "";
  for (const b of bytes) out += ALFABETO[b % ALFABETO.length];
  return out;
}

// --- Alta, baja y modificación de buzones ---

/**
 * Crea la cuenta y devuelve su `accountId` y la contraseña generada.
 *
 * La contraseña se devuelve UNA vez y no se guarda en ningún lado: el depósito de
 * correo va con la credencial de administrador, así que nunca hace falta de nuevo.
 * Si el usuario la pierde, se genera otra con `cambiarPassword`.
 */
export async function crearBuzon(o: {
  localPart: string;
  domain: string;
  quotaBytes: number;
  descripcion?: string;
}): Promise<Resultado<{ accountId: string; email: string; password: string }>> {
  if (!stalwartConfigurado()) return fallo("El servidor IMAP no está configurado");

  try {
    const dom = await domainId(o.domain);
    if (!dom) return fallo(`El dominio ${o.domain} no existe en el servidor IMAP`);

    const password = generarPassword();
    // `emailAddress` NO se manda: lo deriva el servidor de `name` + `domainId`, y
    // mandarlo explícito revienta con `invalidPatch / Cannot modify server set property`.
    const crear: Record<string, unknown> = {
      "@type": "User",
      name: o.localPart,
      domainId: dom,
      credentials: { "0": { "@type": "Password", secret: password } },
      quotas: { maxDiskQuota: o.quotaBytes },
    };
    // Nunca mandar `null` en un campo opcional: tumba la petición ENTERA con
    // `400 notRequest`, un error que no menciona el campo culpable.
    if (o.descripcion) crear.description = o.descripcion;

    const r = await jmap([CORE, STALWART], [["x:Account/set", { create: { t1: crear } }, "c0"]]);
    const resp = respuesta(r);
    const id = resp?.created?.t1?.id;
    if (!id) {
      const no = resp?.notCreated?.t1;
      return fallo(no?.description ?? `No se pudo crear el buzón: ${JSON.stringify(no ?? resp)}`);
    }

    const email = `${o.localPart}@${o.domain}`.toLowerCase();
    olvidarCuenta(email);
    return { ok: true, valor: { accountId: id, email, password } };
  } catch (err) {
    return fallo(String(err));
  }
}

export async function cambiarPassword(accountId: string): Promise<Resultado<{ password: string }>> {
  if (!stalwartConfigurado()) return fallo("El servidor IMAP no está configurado");
  const password = generarPassword();
  const r = await actualizar(accountId, { credentials: { "0": { "@type": "Password", secret: password } } });
  return r.ok ? { ok: true, valor: { password } } : r;
}

export async function fijarCuota(accountId: string, bytes: number): Promise<Resultado<void>> {
  // Sintaxis de parche: en `update` la cuota se toca por ruta, no reemplazando el mapa.
  return await actualizar(accountId, { "quotas/maxDiskQuota": bytes });
}

async function actualizar(accountId: string, patch: Record<string, unknown>): Promise<Resultado<void>> {
  if (!stalwartConfigurado()) return fallo("El servidor IMAP no está configurado");
  try {
    const r = await jmap([CORE, STALWART], [["x:Account/set", { update: { [accountId]: patch } }, "c0"]]);
    const resp = respuesta(r);
    if (resp && accountId in (resp.updated ?? {})) return { ok: true, valor: undefined };
    const no = resp?.notUpdated?.[accountId];
    return fallo(no?.description ?? `No se pudo actualizar el buzón: ${JSON.stringify(no ?? resp)}`);
  } catch (err) {
    return fallo(String(err));
  }
}

/** Bytes usados y límite. El uso lo lleva el servidor; nuestra columna es sólo caché. */
export async function leerUso(accountId: string): Promise<Resultado<{ usados: number; limite: number | null; email: string }>> {
  if (!stalwartConfigurado()) return fallo("El servidor IMAP no está configurado");
  try {
    const r = await jmap([CORE, STALWART], [[
      "x:Account/get",
      { ids: [accountId], properties: ["quotas", "usedDiskQuota", "emailAddress"] },
      "c0",
    ]]);
    const cuenta = respuesta(r)?.list?.[0];
    if (!cuenta) return fallo("El buzón no existe en el servidor IMAP");
    return {
      ok: true,
      valor: {
        usados: cuenta.usedDiskQuota ?? 0,
        limite: cuenta.quotas?.maxDiskQuota ?? null,
        email: cuenta.emailAddress ?? "",
      },
    };
  } catch (err) {
    return fallo(String(err));
  }
}

export async function borrarBuzon(accountId: string, email?: string): Promise<Resultado<void>> {
  if (!stalwartConfigurado()) return fallo("El servidor IMAP no está configurado");
  try {
    const r = await jmap([CORE, STALWART], [["x:Account/set", { destroy: [accountId] }, "c0"]]);
    const resp = respuesta(r);
    if (email) olvidarCuenta(email);
    if (resp?.destroyed?.includes(accountId)) return { ok: true, valor: undefined };
    // Que ya no exista es exactamente lo que queríamos: borrar es idempotente.
    const no = resp?.notDestroyed?.[accountId];
    if (no?.type === "notFound") return { ok: true, valor: undefined };
    return fallo(no?.description ?? `No se pudo borrar el buzón: ${JSON.stringify(no ?? resp)}`);
  } catch (err) {
    return fallo(String(err));
  }
}

/** Todas las direcciones con cuenta en el servidor, para cazar huérfanas. */
export async function listarBuzones(): Promise<Resultado<{ accountId: string; email: string }[]>> {
  if (!stalwartConfigurado()) return fallo("El servidor IMAP no está configurado");
  try {
    const q = await jmap([CORE, STALWART], [["x:Account/query", {}, "c0"]]);
    const ids: string[] = respuesta(q)?.ids ?? [];
    if (!ids.length) return { ok: true, valor: [] };

    const g = await jmap([CORE, STALWART], [["x:Account/get", { ids, properties: ["emailAddress"] }, "c0"]]);
    const lista: any[] = respuesta(g)?.list ?? [];
    return {
      ok: true,
      valor: lista.map((c) => ({ accountId: c.id, email: (c.emailAddress ?? "").toLowerCase() })).filter((c) => c.email),
    };
  } catch (err) {
    return fallo(String(err));
  }
}

// --- Salud ---

/**
 * Vivo o no. `/jmap/session` contesta 200 **sin credenciales**, así que ejercita el
 * listener HTTP y la carga de configuración sin depender de que el secreto sea válido.
 * Es el chequeo que habría cazado en minutos el 502 del 6-sep, cuando el hostname
 * apuntaba al puerto de submission y el depósito llevaba horas fallando en silencio.
 */
export async function estaVivo(): Promise<boolean> {
  if (!base()) return false;
  try {
    const res = await fetch(`${base()}/jmap/session`, {
      redirect: "follow",
      signal: AbortSignal.timeout(6_000),
    });
    return res.ok || res.status === 401;
  } catch {
    return false;
  }
}

/** Días que le quedan al certificado del servidor IMAP (el suyo, no el del proxy). */
export async function diasDeCertificado(): Promise<number | null> {
  if (!stalwartConfigurado()) return null;
  try {
    const q = await jmap([CORE, STALWART], [["x:Certificate/query", {}, "c0"]]);
    const ids: string[] = respuesta(q)?.ids ?? [];
    if (!ids.length) return null;

    const g = await jmap([CORE, STALWART], [["x:Certificate/get", { ids, properties: ["notValidAfter"] }, "c0"]]);
    const lista: any[] = respuesta(g)?.list ?? [];
    const fechas = lista
      .map((c) => Date.parse(c.notValidAfter ?? ""))
      .filter((t) => Number.isFinite(t));
    if (!fechas.length) return null;

    // El que caduca primero: es el que rompe el servicio.
    return Math.floor((Math.min(...fechas) - Date.now()) / 86_400_000);
  } catch {
    return null;
  }
}

// --- Entrega ---

/**
 * Deposita un mensaje crudo en el INBOX de una cuenta cualquiera.
 *
 * Va con la credencial de ADMINISTRADOR, no con la del buzón: Stalwart autoriza al
 * admin por petición, así que un `accountId` ajeno en `Email/import` funciona. Es lo
 * que nos permite no guardar nunca la contraseña de un buzón.
 *
 * Lanza si falla; el llamador decide qué hacer (en el camino del reenvío, nada).
 */
export async function importarMensaje(accountId: string, rawContent: string): Promise<void> {
  // El mensaje se sube como blob y luego se importa: es el camino de JMAP para meter
  // un correo ya formado, sin reconstruirlo campo por campo.
  const up = await fetch(`${base()}/jmap/upload/${accountId}/`, {
    method: "POST",
    headers: { authorization: auth(), "content-type": "message/rfc822" },
    body: rawContent,
    redirect: "follow",
    signal: AbortSignal.timeout(7_000),
  });
  if (!up.ok) throw new Error(`upload ${up.status}`);
  const { blobId } = (await up.json()) as { blobId: string };

  // El buzón se busca por rol (`inbox`), que es estable entre servidores e idiomas.
  const q = await jmap([CORE, "urn:ietf:params:jmap:mail"], [[
    "Mailbox/query", { accountId, filter: { role: "inbox" } }, "c0",
  ]]);
  const mailboxId = respuesta(q)?.ids?.[0];
  if (!mailboxId) throw new Error("la cuenta no tiene INBOX");

  const r = await jmap([CORE, "urn:ietf:params:jmap:mail"], [[
    "Email/import",
    { accountId, emails: { e1: { blobId, mailboxIds: { [mailboxId]: true }, keywords: {} } } },
    "c0",
  ]]);
  const resp = respuesta(r);
  if (!resp?.created?.e1) throw new Error(`Email/import: ${JSON.stringify(resp?.notCreated ?? resp)}`);
}

/** Sólo para pruebas: los cachés viven en el módulo y sobreviven a un cambio de entorno. */
export function limpiarCaches(): void {
  dominios.clear();
  cuentas.clear();
  cuentaPropiaCache = null;
}

// --- Exportación ---

/**
 * Recorre TODO el correo de una cuenta y lo entrega crudo, uno por uno.
 *
 * Existe para que nadie pierda su correo al darse de baja: con un buzón sin reenvío,
 * lo que hay aquí es el único ejemplar. Va como generador y no como arreglo a
 * propósito — un buzón de 10 GB no cabe en memoria.
 */
export async function* exportarBuzon(accountId: string, lote = 100): AsyncGenerator<string> {
  if (!stalwartConfigurado()) return;

  let posicion = 0;
  while (true) {
    const q = await jmap([CORE, "urn:ietf:params:jmap:mail"], [[
      "Email/query", { accountId, position: posicion, limit: lote, calculateTotal: false }, "c0",
    ]], 20_000);
    const ids: string[] = respuesta(q)?.ids ?? [];
    if (!ids.length) return;

    const g = await jmap([CORE, "urn:ietf:params:jmap:mail"], [[
      "Email/get", { accountId, ids, properties: ["blobId"] }, "c0",
    ]], 20_000);

    for (const correo of respuesta(g)?.list ?? []) {
      if (!correo.blobId) continue;
      const res = await fetch(
        `${base()}/jmap/download/${accountId}/${correo.blobId}/mensaje.eml?accept=message/rfc822`,
        { headers: { authorization: auth() }, redirect: "follow", signal: AbortSignal.timeout(30_000) },
      );
      if (!res.ok) continue; // Un mensaje ilegible no puede abortar la exportación entera.
      yield await res.text();
    }

    posicion += ids.length;
    if (ids.length < lote) return;
  }
}

/**
 * Solo lectura: se le fija la cuota a lo que ya ocupa, así que no entra nada nuevo
 * pero se sigue pudiendo leer y descargar. Es lo que hace la gracia de 30 días.
 */
export async function congelarBuzon(accountId: string): Promise<Resultado<void>> {
  const uso = await leerUso(accountId);
  if (!uso.ok) return uso;
  return await fijarCuota(accountId, Math.max(uso.valor.usados, 1));
}
