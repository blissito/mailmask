import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export interface StoredCredentials {
  apiKey: string;
  baseUrl?: string;
}

export interface ResolvedAuth extends StoredCredentials {
  /** De dónde salió la credencial: útil para explicar por qué `logout` no la borró. */
  source: "env" | "file";
}

/** `MAILMASK_CONFIG_DIR` sólo existe para aislar las pruebas; en uso normal nunca se fija. */
function configDir(): string {
  return process.env.MAILMASK_CONFIG_DIR || join(homedir(), ".config", "mailmask");
}

function credentialsPath(): string {
  return join(configDir(), "credentials.json");
}

export function readCredentials(): StoredCredentials | null {
  const path = credentialsPath();
  if (!existsSync(path)) return null;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    if (typeof parsed?.apiKey === "string") return parsed;
    return null;
  } catch {
    return null;
  }
}

/** Archivo 600: es el fallback mientras no hay integración con el keychain del SO. */
export function writeCredentials(creds: StoredCredentials): void {
  const dir = configDir();
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const path = credentialsPath();
  writeFileSync(path, JSON.stringify(creds, null, 2) + "\n", { mode: 0o600 });
  chmodSync(path, 0o600);
}

/** @returns true si había algo que borrar. */
export function clearCredentials(): boolean {
  const path = credentialsPath();
  if (!existsSync(path)) return false;
  rmSync(path);
  return true;
}

export function credentialsFilePath(): string {
  return credentialsPath();
}

/** `MAILMASK_API_KEY` siempre gana sobre lo guardado — es lo esperado para CI/agentes. */
export function resolveAuth(): ResolvedAuth | null {
  if (process.env.MAILMASK_API_KEY) {
    return { apiKey: process.env.MAILMASK_API_KEY, baseUrl: process.env.MAILMASK_BASE_URL, source: "env" };
  }
  const stored = readCredentials();
  if (stored) return { ...stored, source: "file" };
  return null;
}
