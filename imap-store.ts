// Depósito del correo entrante en el buzón IMAP del destinatario (Stalwart).
//
// Va por **JMAP sobre HTTPS** y no por LMTP a propósito: la plataforma donde vive el
// buzón sólo expone capa 7 —ningún template declara puertos crudos— así que LMTP no
// es alcanzable desde aquí. JMAP además es el contrato público del servidor; leer su
// S3 por debajo sería acoplarse a su formato interno.
//
// Esto es un DESTINO ADICIONAL, no la fuente de verdad: el original sigue en S3 vía
// SES y la conversación sigue entrando a la Bandeja. Por eso ningún fallo de aquí
// puede romper el reenvío, y por eso este módulo nunca lanza.

import { log } from "./logger.js";
import { accountIdDe, importarMensaje, stalwartConfigurado } from "./stalwart.js";

/**
 * Hay servidor IMAP configurado. Ya no existe una lista de dominios habilitados: la
 * decisión es POR MÁSCARA (`alias.mailboxEnabled`, que la pone la app al crear el
 * buzón), y el depósito resuelve el buzón del destinatario y falla cerrado si no está.
 * La lista `IMAP_ENABLED_DOMAINS` dejó fuera al primer dominio de cliente sin que nadie
 * lo notara: la Bandeja recibía y el buzón no.
 */
export function imapHabilitado(_domainName?: string): boolean {
  return stalwartConfigurado();
}

/** Segundos, no minutos: el reenvío es lo que no puede esperar. */
const PRESUPUESTO_MS = 8_000;

/**
 * Deposita el mensaje en el buzón del destinatario. Devuelve true si quedó guardado.
 *
 * Nunca lanza: el llamador está en el camino del reenvío y un buzón caído no puede
 * impedir que el correo llegue a su destino.
 */
export async function depositarEnImap(
  rawContent: string,
  domainName: string,
  destinatario: string,
): Promise<boolean> {
  if (!imapHabilitado(domainName)) return false;

  // Presupuesto total. Esto corre DENTRO del camino del reenvío: sin un tope global,
  // un buzón que acepta la conexión pero no contesta sumaría los timeouts internos
  // —hasta un minuto— a la entrega de un correo que no tiene nada que ver con IMAP.
  // El temporizador se limpia SIEMPRE al terminar la carrera. Un `unref()` no sirve
  // aquí: dejaría de sostener el bucle y entonces no dispararía cuando no haya nada
  // más pendiente. Y sin limpiarlo, cada correo dejaría un temporizador vivo ocho
  // segundos — la misma trampa que documentó `scheduler.ts`.
  let cronometro: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      depositar(rawContent, domainName, destinatario),
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

async function depositar(rawContent: string, domainName: string, destinatario: string): Promise<boolean> {
  try {
    // 🔴 El buzón del DESTINATARIO, no uno global. Antes esto entregaba siempre en el
    // INBOX del único usuario de las credenciales, así que con dos dominios activados
    // el correo del cliente A habría caído en el buzón del cliente B.
    //
    // `accountIdDe` devuelve null tanto si la dirección no tiene buzón como si el
    // servidor no contesta, y en ambos casos NO se deposita. Ese fail-closed es la
    // defensa: sin buzón conocido el correo no se guarda en uno ajeno, y el reenvío
    // y la Bandeja siguen su camino igual.
    const accountId = await accountIdDe(destinatario);
    if (!accountId) {
      log("info", "forwarding", "El destinatario no tiene buzón IMAP; no se deposita", {
        domain: domainName,
        destinatario,
      });
      return false;
    }

    await importarMensaje(accountId, rawContent);
    return true;
  } catch (err) {
    log("error", "forwarding", "No se pudo depositar en el buzón IMAP", {
      domain: domainName,
      destinatario,
      error: String(err),
    });
    return false;
  }
}
