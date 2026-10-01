import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import * as keychain from "./keychain.js";

export interface StoredCredentials {
  apiKey: string;
  baseUrl?: string;
}

export interface ResolvedAuth extends StoredCredentials {
  /** De dónde salió la credencial: útil para explicar qué borra `logout`. */
  source: "env" | "keychain" | "file";
}

/** `MAILMASK_CONFIG_DIR` sólo existe para aislar las pruebas; en uso normal nunca se fija. */
function configDir(): string {
  return process.env.MAILMASK_CONFIG_DIR || join(homedir(), ".config", "mailmask");
}

function credentialsPath(): string {
  return join(configDir(), "credentials.json");
}

// El archivo guarda `baseUrl` SIEMPRE que se fijó (no es secreto), y `apiKey`
// SÓLO cuando no hay keychain disponible — si la llave vive en el keychain, el
// archivo se queda sin ese campo (o no existe, si tampoco hay baseUrl que guardar).
interface CredentialsFile {
  apiKey?: string;
  baseUrl?: string;
}

function readFile(): CredentialsFile | null {
  const path = credentialsPath();
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
}

function writeFile(data: CredentialsFile): void {
  const path = credentialsPath();
  if (Object.keys(data).length === 0) {
    if (existsSync(path)) rmSync(path);
    return;
  }
  mkdirSync(configDir(), { recursive: true, mode: 0o700 });
  writeFileSync(path, JSON.stringify(data, null, 2) + "\n", { mode: 0o600 });
  // `mode` en writeFileSync no cambia los permisos de un archivo que ya existía.
  chmodSync(path, 0o600);
}

export function readCredentials(): StoredCredentials | null {
  const file = readFile();
  return file?.apiKey ? { apiKey: file.apiKey, baseUrl: file.baseUrl } : null;
}

/**
 * Guarda la sesión: keychain del SO primero, archivo 600 si no hay keychain o si
 * lo rechaza (p.ej. sin daemon de secretos desbloqueado). `baseUrl` siempre va al
 * archivo —no es secreto y el keychain sólo guarda un valor por cuenta—.
 */
export async function writeCredentials(creds: StoredCredentials): Promise<{ source: "keychain" | "file" }> {
  if (await keychain.isAvailable()) {
    try {
      await keychain.set(creds.apiKey);
      writeFile(creds.baseUrl ? { baseUrl: creds.baseUrl } : {});
      return { source: "keychain" };
    } catch {
      // El keychain está instalado pero rechazó la escritura: cae al archivo
      // en vez de perder la sesión.
    }
  }
  writeFile({ apiKey: creds.apiKey, baseUrl: creds.baseUrl });
  return { source: "file" };
}

/** @returns true si había algo que borrar (en el keychain, en el archivo, o ambos). */
export async function clearCredentials(): Promise<boolean> {
  let removed = false;
  if (await keychain.isAvailable()) {
    const hadKey = (await keychain.get()) !== null;
    if (hadKey) removed = (await keychain.remove()) || removed;
  }
  if (readFile()) {
    rmSync(credentialsPath());
    removed = true;
  }
  return removed;
}

export function credentialsFilePath(): string {
  return credentialsPath();
}

/** `MAILMASK_API_KEY` siempre gana sobre lo guardado — es lo esperado para CI/agentes. */
export async function resolveAuth(): Promise<ResolvedAuth | null> {
  if (process.env.MAILMASK_API_KEY) {
    return { apiKey: process.env.MAILMASK_API_KEY, baseUrl: process.env.MAILMASK_BASE_URL, source: "env" };
  }
  const file = readFile();
  if (await keychain.isAvailable()) {
    const apiKey = await keychain.get();
    if (apiKey) return { apiKey, baseUrl: file?.baseUrl, source: "keychain" };
  }
  if (file?.apiKey) return { apiKey: file.apiKey, baseUrl: file.baseUrl, source: "file" };
  return null;
}
