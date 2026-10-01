import { defineCommand } from "citty";
import { MailMaskError } from "@easybits.cloud/mailmask";
import { buildClient } from "../client.js";
import { writeCredentials } from "../config.js";
import { EXIT, fail, maskSecret } from "../output.js";
import { promptLine } from "../prompt.js";

export default defineCommand({
  meta: {
    name: "login",
    description: "Guarda la API key de MailMask (mk_...) para los siguientes comandos",
  },
  args: {
    apiKey: {
      type: "string",
      description: "API key de MailMask. Si se omite, se pide de forma interactiva (requiere TTY).",
    },
    baseUrl: {
      type: "string",
      description: "URL base de la API, sólo para apuntar a un entorno distinto al de producción.",
    },
  },
  async run({ args }) {
    let apiKey = args.apiKey;
    if (!apiKey) {
      try {
        apiKey = await promptLine("Pega tu API key de MailMask (la consigues en mailmask.studio/dashboard): ");
      } catch (err) {
        fail(err instanceof Error ? err.message : String(err), EXIT.ERROR);
      }
    }
    if (!apiKey) fail("No llegó ninguna API key.", EXIT.ERROR);
    if (!apiKey.startsWith("mk_")) {
      process.stderr.write('⚠ Esa llave no empieza con "mk_" — sigo, pero revisa que sea la correcta.\n');
    }

    const client = buildClient({ apiKey, baseUrl: args.baseUrl });
    try {
      await client.apiKeys.list();
    } catch (err) {
      if (err instanceof MailMaskError && (err.status === 401 || err.status === 403)) {
        fail("MailMask rechazó esa API key. Revisa que la copiaste completa.", EXIT.AUTH);
      }
      fail(err instanceof Error ? err.message : String(err), EXIT.ERROR);
    }

    writeCredentials({ apiKey, baseUrl: args.baseUrl });
    process.stdout.write(`✓ Sesión guardada con la llave ${maskSecret(apiKey)}\n`);
  },
});
