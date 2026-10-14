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

import { listUnindexedMessages, indexMessage, markIndexState, countUnindexedMessages } from "./db.js";
import { fetchEmailFromS3 } from "./ses.js";
import { extractPlainBody } from "./forwarding.js";
import { log } from "./logger.js";

const BATCH_SIZE = 25;
const PAUSE_MS = 2000;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function pendingBackfillCount(): number {
  return countUnindexedMessages();
}

let running = false;

export interface BackfillResult {
  indexed: number;
  errors: number;
  remaining: number;
}

/**
 * Indexa los mensajes que aún no están en la FTS, en lotes y con pausa.
 *
 * Reanudable: el progreso vive en la tabla `search_index_state`, no en memoria,
 * así que interrumpirlo a la mitad y relanzarlo no reindexa lo ya hecho. Un
 * mensaje que falla se marca como "error" para no reintentarlo en bucle infinito.
 */
export async function runBackfill(opts?: {
  batchSize?: number;
  pauseMs?: number;
  maxMessages?: number;
}): Promise<BackfillResult> {
  if (running) return { indexed: 0, errors: 0, remaining: pendingBackfillCount() };
  running = true;

  const batchSize = opts?.batchSize ?? BATCH_SIZE;
  const pauseMs = opts?.pauseMs ?? PAUSE_MS;
  const maxMessages = opts?.maxMessages ?? Infinity;

  let indexed = 0;
  let errors = 0;

  try {
    while (indexed + errors < maxMessages) {
      const pending = listUnindexedMessages(Math.min(batchSize, maxMessages - indexed - errors));
      if (pending.length === 0) break;

      for (const m of pending) {
        try {
          // Los salientes ya traen el cuerpo en la base: sale gratis.
          // Los entrantes hay que bajarlos de S3, que es lo caro.
          let text = m.body ?? "";
          if (!text && m.s3Bucket && m.s3Key) {
            const raw = await fetchEmailFromS3(m.s3Bucket, m.s3Key);
            text = raw ? extractPlainBody(raw) : "";
          }

          if (!text) {
            // Sin cuerpo recuperable. Se marca para no volver a intentarlo cada
            // vuelta; si algún día se quiere reintentar, se borra la fila.
            markIndexState(m.id, "skipped", "sin cuerpo recuperable");
            indexed++;
            continue;
          }

          indexMessage({
            messageId: m.id,
            conversationId: m.conversationId,
            domainId: m.domainId,
            from: m.from,
            subject: m.subject,
            text,
          });
          indexed++;
        } catch (err) {
          markIndexState(m.id, "error", String(err).slice(0, 500));
          errors++;
        }
      }

      // Pausa entre lotes para no saturar S3 ni acaparar el event loop: esto
      // corre en el mismo proceso que atiende el correo entrante.
      await sleep(pauseMs);
    }
  } finally {
    running = false;
  }

  const remaining = pendingBackfillCount();
  if (indexed || errors) {
    log("info", "search", "Backfill del índice", { indexados: indexed, errores: errors, restantes: remaining });
  }
  return { indexed, errors, remaining };
}
