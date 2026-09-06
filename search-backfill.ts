// Backfill del índice de búsqueda de la Bandeja.
//
// Por qué un trabajador dentro del proceso y no un script suelto: el precedente
// de scripts/migrate-api-keys-hash.ts, documentado en pg.ts. Ese script se corrió
// a mano sobre producción y nunca entró a las migraciones, así que producción
// quedó en un estado y toda base nueva en otro, durante meses y sin que nadie lo
// notara. Aquí corre solo, en todas las bases, sin acordarse nadie.
//
// Por qué no perezoso (indexar al abrir el hilo): la búsqueda tiene que encontrar
// hilos que nadie ha abierto. Ese es exactamente el caso de uso.

import { listUnindexedMessages, indexMessage, markIndexState, contarSinIndexar } from "./db.js";
import { fetchEmailFromS3 } from "./ses.js";
import { extractPlainBody } from "./forwarding.js";
import { log } from "./logger.js";

const LOTE = 25;
const PAUSA_MS = 2000;

const dormir = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function backfillPendiente(): number {
  return contarSinIndexar();
}

let corriendo = false;

export interface ResultadoBackfill {
  indexados: number;
  errores: number;
  restantes: number;
}

/**
 * Indexa los mensajes que aún no están en la FTS, en lotes y con pausa.
 *
 * Reanudable: el progreso vive en la tabla `search_index_state`, no en memoria,
 * así que interrumpirlo a la mitad y relanzarlo no reindexa lo ya hecho. Un
 * mensaje que falla se marca como "error" para no reintentarlo en bucle infinito.
 */
export async function ejecutarBackfill(opts?: {
  lote?: number;
  pausaMs?: number;
  maxMensajes?: number;
}): Promise<ResultadoBackfill> {
  if (corriendo) return { indexados: 0, errores: 0, restantes: backfillPendiente() };
  corriendo = true;

  const lote = opts?.lote ?? LOTE;
  const pausaMs = opts?.pausaMs ?? PAUSA_MS;
  const maxMensajes = opts?.maxMensajes ?? Infinity;

  let indexados = 0;
  let errores = 0;

  try {
    while (indexados + errores < maxMensajes) {
      const pendientes = listUnindexedMessages(Math.min(lote, maxMensajes - indexados - errores));
      if (pendientes.length === 0) break;

      for (const m of pendientes) {
        try {
          // Los salientes ya traen el cuerpo en la base: sale gratis.
          // Los entrantes hay que bajarlos de S3, que es lo caro.
          let texto = m.body ?? "";
          if (!texto && m.s3Bucket && m.s3Key) {
            const raw = await fetchEmailFromS3(m.s3Bucket, m.s3Key);
            texto = raw ? extractPlainBody(raw) : "";
          }

          if (!texto) {
            // Sin cuerpo recuperable. Se marca para no volver a intentarlo cada
            // vuelta; si algún día se quiere reintentar, se borra la fila.
            markIndexState(m.id, "skipped", "sin cuerpo recuperable");
            indexados++;
            continue;
          }

          indexMessage({
            messageId: m.id,
            conversationId: m.conversationId,
            domainId: m.domainId,
            from: m.from,
            subject: m.subject,
            text: texto,
          });
          indexados++;
        } catch (err) {
          markIndexState(m.id, "error", String(err).slice(0, 500));
          errores++;
        }
      }

      // Pausa entre lotes para no saturar S3 ni acaparar el event loop: esto
      // corre en el mismo proceso que atiende el correo entrante.
      await dormir(pausaMs);
    }
  } finally {
    corriendo = false;
  }

  const restantes = backfillPendiente();
  if (indexados || errores) {
    log("info", "search", "Backfill del índice", { indexados, errores, restantes });
  }
  return { indexados, errores, restantes };
}
