// Verificación de la firma de un webhook, del lado del receptor.
// Usa WebCrypto para correr igual en Node 18+, Deno, Bun y Workers.

function hex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export interface WebhookSignatureHeaders {
  /** Header `X-MailMask-Signature`, con forma `sha256=<hex>`. */
  signature: string;
  /** Header `X-MailMask-Timestamp`, milisegundos Unix. */
  timestamp: string;
}

/**
 * Comprueba que `rawBody` (el cuerpo tal cual llegó, sin parsear) fue firmado
 * con `secret`. Rechaza timestamps con más de `toleranceMs` de diferencia para
 * frenar repeticiones.
 */
export async function verifyWebhookSignature(
  secret: string,
  headers: WebhookSignatureHeaders,
  rawBody: string,
  toleranceMs = 5 * 60_000,
): Promise<boolean> {
  const ts = Number(headers.timestamp);
  if (!Number.isFinite(ts) || Math.abs(Date.now() - ts) > toleranceMs) return false;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, enc.encode(`${headers.timestamp}.${rawBody}`));
  return constantTimeEqual(`sha256=${hex(mac)}`, headers.signature);
}
