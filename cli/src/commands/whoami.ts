import { defineCommand } from "citty";
import { requireClient } from "../client.js";
import { failFromError, maskSecret, printJson } from "../output.js";

export default defineCommand({
  meta: {
    name: "whoami",
    description: "Muestra qué API key está activa y a qué cuenta pertenece",
  },
  args: {
    json: { type: "boolean", description: "Salida en JSON para scripts/agentes" },
  },
  async run({ args }) {
    const { client, auth } = await requireClient();

    // No hay endpoint de identidad: apiKeys.list() + domains.list() es la forma de
    // confirmar que la llave sirve y de qué cuenta es (por el prefijo de la llave activa).
    let keys: Awaited<ReturnType<typeof client.apiKeys.list>> = [];
    let domains: Awaited<ReturnType<typeof client.domains.list>> = [];
    try {
      [keys, domains] = await Promise.all([client.apiKeys.list(), client.domains.list()]);
    } catch (err) {
      failFromError(err, { json: args.json });
    }

    const activeKey = keys.find((k) => auth.apiKey.startsWith(k.keyPrefix));
    const sourceLabel =
      auth.source === "env" ? "MAILMASK_API_KEY" : auth.source === "keychain" ? "el keychain del sistema" : "archivo local";
    const result = {
      authSource: auth.source,
      baseUrl: auth.baseUrl ?? "https://www.mailmask.studio",
      apiKey: maskSecret(auth.apiKey),
      apiKeyName: activeKey?.name ?? null,
      domainCount: domains.length,
    };

    if (args.json) {
      printJson(result);
      return;
    }

    process.stdout.write(`Llave activa: ${result.apiKey}${activeKey ? ` ("${activeKey.name}")` : ""}\n`);
    process.stdout.write(`Guardada en: ${sourceLabel}\n`);
    process.stdout.write(`API: ${result.baseUrl}\n`);
    process.stdout.write(`Dominios visibles: ${result.domainCount}\n`);
  },
});
