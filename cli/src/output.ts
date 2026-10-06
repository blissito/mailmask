import { createInterface } from "node:readline/promises";
import { MailMaskError } from "@easybits.cloud/mailmask";

/** Taxonomía de exit codes (contrato fijo, ver docs/agents/mailmask-cli.md): 0 éxito, 1 genérico,
 * 2 sin API key activa o rechazada, 3 conflicto (409), 4 no encontrado (404), 5 transitorio (429/5xx/red). */
export const EXIT = { OK: 0, ERROR: 1, AUTH: 2, CONFLICT: 3, NOT_FOUND: 4, TRANSIENT: 5 } as const;

function exitCodeForStatus(status: number): number {
  if (status === 401 || status === 403) return EXIT.AUTH;
  if (status === 404) return EXIT.NOT_FOUND;
  if (status === 409) return EXIT.CONFLICT;
  if (status === 429 || status >= 500) return EXIT.TRANSIENT;
  return EXIT.ERROR;
}

export function printJson(data: unknown): void {
  process.stdout.write(`${JSON.stringify(data, null, 2)}\n`);
}

/** Primeros 7 y últimos 4 caracteres: alcanza para reconocer la llave sin volver a exponerla. */
export function maskSecret(secret: string): string {
  if (secret.length <= 12) return "*".repeat(secret.length);
  return `${secret.slice(0, 7)}...${secret.slice(-4)}`;
}

export function fail(message: string, code: number = EXIT.ERROR): never {
  process.stderr.write(`✖ ${message}\n`);
  process.exit(code);
}

/** Con `--json`, el error sale como `{error, status}` a stderr en vez del texto con "✖". */
function failJson(error: string, status: number | undefined, code: number): never {
  const payload: Record<string, unknown> = status === undefined ? { error } : { error, status };
  process.stderr.write(`${JSON.stringify(payload)}\n`);
  process.exit(code);
}

export function failFromError(err: unknown, opts: { json?: boolean } = {}): never {
  if (err instanceof MailMaskError) {
    const code = exitCodeForStatus(err.status);
    if (opts.json) failJson(err.message, err.status, code);
    if (code === EXIT.AUTH) {
      fail(`${err.message} — corre "mailmask login" con una API key válida.`, code);
    }
    fail(`MailMask respondió ${err.status}: ${err.message}`, code);
  }
  const message = err instanceof Error ? err.message : String(err);
  if (opts.json) failJson(message, undefined, EXIT.ERROR);
  fail(message, EXIT.ERROR);
}

export const NO_AUTH_MESSAGE =
  'No hay una API key activa. Corre "mailmask login" o fija la variable MAILMASK_API_KEY.';

/**
 * Lo destructivo o que sale a terceros (delete, revoke, send, reset de
 * contraseña) pasa por aquí antes de mutar. `--yes` se salta la pregunta — es
 * lo único que funciona fuera de una terminal, y ES obligatorio ahí: sin TTY
 * y sin `--yes` se aborta sin tocar el SDK, nunca se asume un "sí" silencioso.
 */
export async function confirmOrExit(message: string, opts: { yes?: boolean; json?: boolean } = {}): Promise<void> {
  if (opts.yes) return;
  if (!process.stdin.isTTY) {
    const reason = `${message} Fuera de una terminal hace falta --yes.`;
    if (opts.json) failJson(reason, undefined, EXIT.ERROR);
    fail(reason, EXIT.ERROR);
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  let answer: string;
  try {
    answer = await rl.question(`${message} [y/N] `);
  } finally {
    rl.close();
  }
  if (!/^(y|yes|s|si|sí)$/i.test(answer.trim())) {
    process.stdout.write("Cancelado.\n");
    process.exit(EXIT.OK);
  }
}
