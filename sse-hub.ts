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

export function notifyBandeja(domainId: string, event: string, data: Record<string, unknown>): void {
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
