// SSE Hub for Bandeja real-time updates
// Avoids circular imports between main.ts and forwarding.ts

interface SseClient {
  controller: ReadableStreamDefaultController;
  domainId: string;
}

const clients = new Map<string, Set<SseClient>>();

export function addSseClient(userId: string, domainId: string, controller: ReadableStreamDefaultController): () => void {
  if (!clients.has(userId)) clients.set(userId, new Set());
  const client: SseClient = { controller, domainId };
  clients.get(userId)!.add(client);

  return () => {
    clients.get(userId)?.delete(client);
    if (clients.get(userId)?.size === 0) clients.delete(userId);
  };
}

export function notifyInbox(domainId: string, event: string, data: Record<string, unknown>): void {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  const encoder = new TextEncoder();
  const encoded = encoder.encode(payload);

  for (const [, clientSet] of clients) {
    for (const client of clientSet) {
      if (client.domainId === domainId) {
        try {
          client.controller.enqueue(encoded);
        } catch {
          // Client disconnected, will be cleaned up
        }
      }
    }
  }
}

export function getSseClientCount(): number {
  let count = 0;
  for (const [, clientSet] of clients) count += clientSet.size;
  return count;
}

// --- Presencia (detección de colisión) ---
//
// Vive en memoria del proceso a propósito. Es estado de ~30 segundos que cada
// agente reescribe cada 15: meterlo en SQLite sería un fsync en el volumen de Fly
// por dato desechable, y crearía una segunda verdad que al reiniciar deja
// una presencia fantasma. El TTL en memoria muere con el proceso, que es lo correcto.
//
// ⚠️ Presencia y SSE son locales al proceso. Con 2+ máquinas se rompen (el SSE ya
// se rompe hoy). No escalar `fly.toml` sin resolver antes el bus: Redis pub/sub o
// `fly-replay` pinneando el domainId.

export interface Presence {
  email: string;
  name: string;
  conversationId: string | null;
  state: "viewing" | "typing";
  expiresAt: number;
}

// El typing muere rápido a propósito: si dejaste de teclear, el aviso debe irse
// antes de que el compañero se quede esperando un mensaje que ya no llega.
const TTL_VIEWING = 35_000;
const TTL_TYPING = 12_000;

// Clave por email, no por conexión: tres pestañas del mismo agente colapsan solas.
const presences = new Map<string, Map<string, Presence>>();

export function setPresence(
  domainId: string,
  email: string,
  name: string,
  conversationId: string | null,
  state: "viewing" | "typing",
): void {
  if (!presences.has(domainId)) presences.set(domainId, new Map());
  presences.get(domainId)!.set(email, {
    email,
    name,
    conversationId,
    state,
    expiresAt: Date.now() + (state === "typing" ? TTL_TYPING : TTL_VIEWING),
  });
}

export function clearPresence(domainId: string, email: string): void {
  const m = presences.get(domainId);
  if (!m) return;
  m.delete(email);
  if (m.size === 0) presences.delete(domainId);
}

export function listPresence(domainId: string): Presence[] {
  const m = presences.get(domainId);
  if (!m) return [];
  const now = Date.now();
  const alive: Presence[] = [];
  for (const [email, p] of m) {
    if (p.expiresAt <= now) m.delete(email);
    else alive.push(p);
  }
  if (m.size === 0) presences.delete(domainId);
  return alive;
}

// Se manda el snapshot completo, no deltas: con cinco agentes son cinco objetos y
// no hay forma de que el cliente se desincronice.
export function notifyPresence(domainId: string): void {
  notifyInbox(domainId, "presence", { agents: listPresence(domainId) });
}
