import { MailMaskError } from "@easybits.cloud/mailmask";

/** 0 éxito, 1 error genérico, 2 falta o falla la autenticación — el resto de la taxonomía llega en el ticket de confirmaciones/--json. */
export const EXIT = { OK: 0, ERROR: 1, AUTH: 2 } as const;

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

export function failFromError(err: unknown): never {
  if (err instanceof MailMaskError) {
    if (err.status === 401 || err.status === 403) {
      fail(`${err.message} — corre "mailmask login" con una API key válida.`, EXIT.AUTH);
    }
    fail(`MailMask respondió ${err.status}: ${err.message}`, EXIT.ERROR);
  }
  fail(err instanceof Error ? err.message : String(err), EXIT.ERROR);
}

export const NO_AUTH_MESSAGE =
  'No hay una API key activa. Corre "mailmask login" o fija la variable MAILMASK_API_KEY.';
