// Keychain del SO sin dependencias nuevas: llama a los binarios que ya trae
// cada plataforma (`security` en macOS, `secret-tool`/libsecret en Linux).
// Windows y cualquier Linux sin Secret Service caen al archivo de `config.ts`:
// no hay CLI nativo equivalente ahí.
import { spawn } from "node:child_process";

const SERVICE = "mailmask-cli";
const ACCOUNT = "api-key";

type Backend = "macos" | "linux";

function backend(): Backend | null {
  if (process.platform === "darwin") return "macos";
  if (process.platform === "linux") return "linux";
  return null;
}

function run(cmd: string, args: string[], input?: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve(stdout);
      else reject(new Error(stderr.trim() || `${cmd} salió con código ${code}`));
    });
    // Si el binario sale antes de leer stdin (p. ej. secret-tool sin Secret
    // Service encendido), escribirle dispara EPIPE como evento 'error' en el
    // stream; sin este handler Node lo trata como no manejado y mata el
    // proceso entero. El 'close' de arriba ya captura el código de salida
    // real y rechaza — este handler sólo evita el crash.
    child.stdin.on("error", () => {});
    if (input !== undefined) child.stdin.write(input);
    child.stdin.end();
  });
}

async function commandExists(bin: string): Promise<boolean> {
  try {
    await run(process.platform === "win32" ? "where" : "which", [bin]);
    return true;
  } catch {
    return false;
  }
}

/**
 * `MAILMASK_NO_KEYCHAIN` fuerza el fallback de archivo aunque el binario del SO
 * esté instalado — es la forma determinista de probar ese camino (ver
 * `test/config.test.ts`) sin depender de si la máquina que corre la prueba tiene
 * o no Keychain/Secret Service.
 */
export async function isAvailable(): Promise<boolean> {
  if (process.env.MAILMASK_NO_KEYCHAIN) return false;
  const b = backend();
  if (!b) return false;
  return commandExists(b === "macos" ? "security" : "secret-tool");
}

export async function get(): Promise<string | null> {
  const b = backend();
  if (!b) return null;
  try {
    if (b === "macos") {
      const out = await run("security", ["find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"]);
      return out.trim() || null;
    }
    const out = await run("secret-tool", ["lookup", "service", SERVICE, "account", ACCOUNT]);
    return out.trim() || null;
  } catch {
    return null;
  }
}

export async function set(apiKey: string): Promise<void> {
  const b = backend();
  if (!b) throw new Error("Keychain no disponible en esta plataforma");
  if (b === "macos") {
    // -U: si ya existe una entrada previa, la actualiza en vez de fallar.
    // Riesgo conocido: a diferencia de `secret-tool store` (Linux), el
    // binario `security` no tiene forma de leer `-w` desde stdin — sin
    // valor abre un diálogo interactivo del Keychain, que no sirve para un
    // proceso no interactivo. La api key queda como argumento de ESTE
    // proceso y es visible un instante en `ps` para otros procesos del
    // mismo usuario. Es una limitación de `security`, no de este código;
    // documentado también en docs/agents/mailmask-cli.md.
    await run("security", ["add-generic-password", "-U", "-s", SERVICE, "-a", ACCOUNT, "-w", apiKey]);
    return;
  }
  await run("secret-tool", ["store", "--label=MailMask CLI", "service", SERVICE, "account", ACCOUNT], apiKey);
}

/** @returns true si el comando de borrado reportó éxito (no siempre implica que había algo). */
export async function remove(): Promise<boolean> {
  const b = backend();
  if (!b) return false;
  try {
    if (b === "macos") await run("security", ["delete-generic-password", "-s", SERVICE, "-a", ACCOUNT]);
    else await run("secret-tool", ["clear", "service", SERVICE, "account", ACCOUNT]);
    return true;
  } catch {
    return false;
  }
}
