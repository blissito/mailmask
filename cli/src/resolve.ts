import type { MailMask } from "@easybits.cloud/mailmask";
import { failFromError } from "./output.js";

/**
 * La mayoría de los comandos reciben "el dominio" como lo escribiría una
 * persona (acme.com), no el id interno que usa la API. Se resuelve contra
 * `domains.list()` por nombre O id; si no aparece en la lista, se deja pasar
 * tal cual para que la API responda su propio 404 en vez de inventar uno aquí.
 */
export async function resolveDomainId(client: MailMask, domainOrId: string): Promise<string> {
  let domains: Awaited<ReturnType<MailMask["domains"]["list"]>>;
  try {
    domains = await client.domains.list();
  } catch (err) {
    failFromError(err);
  }
  const match = domains.find((d) => d.domain === domainOrId || d.id === domainOrId);
  return match ? match.id : domainOrId;
}
