import { MailMask } from "@easybits.cloud/mailmask";
import { fail, NO_AUTH_MESSAGE } from "./output.js";
import { resolveAuth, type ResolvedAuth } from "./config.js";

export function buildClient(auth: Pick<ResolvedAuth, "apiKey" | "baseUrl">): MailMask {
  return new MailMask({ apiKey: auth.apiKey, baseUrl: auth.baseUrl });
}

/** Resuelve la auth guardada/env y construye el cliente, o termina el proceso con el código de auth. */
export async function requireClient(): Promise<{ client: MailMask; auth: ResolvedAuth }> {
  const auth = await resolveAuth();
  if (!auth) fail(NO_AUTH_MESSAGE, 2);
  return { client: buildClient(auth), auth };
}
