import { defineCommand } from "citty";
import { MailMaskError } from "@easybits.cloud/mailmask";
import { buildClient } from "../client.js";
import { writeCredentials } from "../config.js";
import { startDeviceLogin, pollDeviceLogin } from "../device-auth.js";
import { openBrowser } from "../open-browser.js";
import { EXIT, fail, maskSecret } from "../output.js";

const DEFAULT_BASE_URL = "https://www.mailmask.studio";

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function announce(apiKey: string, source: "keychain" | "file"): void {
  process.stdout.write(`✓ Sesión guardada con la llave ${maskSecret(apiKey)}\n`);
  process.stdout.write(
    source === "keychain"
      ? "Guardada en el keychain del sistema.\n"
      : "Guardada en el archivo local (permisos 600) — no se encontró keychain del SO.\n",
  );
}

async function loginWithApiKey(apiKey: string, baseUrl: string | undefined): Promise<void> {
  if (!apiKey.startsWith("mk_")) {
    process.stderr.write('⚠ Esa llave no empieza con "mk_" — sigo, pero revisa que sea la correcta.\n');
  }
  const client = buildClient({ apiKey, baseUrl });
  try {
    await client.apiKeys.list();
  } catch (err) {
    if (err instanceof MailMaskError && (err.status === 401 || err.status === 403)) {
      fail("MailMask rechazó esa API key. Revisa que la copiaste completa.", EXIT.AUTH);
    }
    fail(err instanceof Error ? err.message : String(err), EXIT.ERROR);
  }
  const { source } = await writeCredentials({ apiKey, baseUrl });
  announce(apiKey, source);
}

async function loginWithDeviceCode(baseUrl: string, explicitBaseUrl: string | undefined): Promise<void> {
  const start = await startDeviceLogin(baseUrl);
  process.stdout.write(`Código: ${start.userCode}\n`);
  process.stdout.write(`Abriendo ${start.verificationUri} para autorizar este dispositivo…\n`);
  process.stdout.write("Si no se abre solo, entra tú con ese link y escribe el código.\n");
  openBrowser(start.verificationUriComplete);

  const deadline = Date.now() + start.expiresIn * 1000;
  const intervalMs = Math.max(start.interval, 1) * 1000;

  while (Date.now() < deadline) {
    await sleep(intervalMs);
    const poll = await pollDeviceLogin(baseUrl, start.deviceCode);
    if (poll.status === "expired") {
      fail('El código expiró. Vuelve a correr "mailmask login".', EXIT.ERROR);
    }
    if (poll.status === "approved") {
      const { source } = await writeCredentials({ apiKey: poll.apiKey, baseUrl: explicitBaseUrl });
      process.stdout.write(`✓ Sesión iniciada como ${poll.email}\n`);
      announce(poll.apiKey, source);
      return;
    }
  }
  fail('Tiempo de espera agotado. Vuelve a correr "mailmask login".', EXIT.ERROR);
}

export default defineCommand({
  meta: {
    name: "login",
    description: "Abre el navegador para autorizar este dispositivo (o usa --api-key para saltarlo)",
  },
  args: {
    apiKey: {
      type: "string",
      description: "Salta el navegador: guarda esta API key de MailMask (mk_...) directamente.",
    },
    baseUrl: {
      type: "string",
      description: "URL base de la API, sólo para apuntar a un entorno distinto al de producción.",
    },
  },
  async run({ args }) {
    const baseUrl = args.baseUrl || DEFAULT_BASE_URL;
    if (args.apiKey) {
      await loginWithApiKey(args.apiKey, args.baseUrl);
      return;
    }
    await loginWithDeviceCode(baseUrl, args.baseUrl);
  },
});
