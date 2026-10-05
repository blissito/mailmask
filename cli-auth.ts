// Device-code login del CLI (`mailmask login`), al estilo `gh auth login`.
//
// En memoria y no en `schema.ts`: el código vive 5 minutos y no necesita
// sobrevivir un restart. Pasarlo por Drizzle habría sumado una migración y una
// tabla para un dato que ya no importa cuando el deploy (con downtime
// estructural, ver AGENTS.md) lo tumba.
import { randomBytes, randomUUID } from "node:crypto";

const TTL_MS = 5 * 60 * 1000;
const POLL_INTERVAL_S = 3;
// Tope de device-codes pendientes a la vez: sin esto, /api/cli/device/start
// (sin auth, sólo con rate limit por IP) podría inflar sin fin la memoria
// del único proceso del server rotando de IP.
const MAX_PENDING = 500;
// Sin 0/O/1/I: nadie debería dudar si lo que ve en pantalla es una letra o un número.
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

type DeviceStatus = "pending" | "approved";

interface DeviceRecord {
  userCode: string;
  status: DeviceStatus;
  createdAt: number;
  apiKey?: string;
  email?: string;
}

export interface DeviceStartResult {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  expiresIn: number;
  interval: number;
}

export type DevicePollResult =
  | { status: "pending" }
  | { status: "approved"; apiKey: string; email: string }
  | { status: "expired" };

export interface DeviceAuthStore {
  start(verificationBase: string): DeviceStartResult;
  confirm(userCode: string, email: string): Promise<boolean>;
  poll(deviceCode: string): DevicePollResult;
}

export function createDeviceAuthStore(opts: {
  createKey: (email: string) => Promise<{ plaintextKey: string }>;
  ttlMs?: number;
  maxPending?: number;
}): DeviceAuthStore {
  const ttlMs = opts.ttlMs ?? TTL_MS;
  const maxPending = opts.maxPending ?? MAX_PENDING;
  const byDeviceCode = new Map<string, DeviceRecord>();
  const byUserCode = new Map<string, string>();

  function sweep(): void {
    const now = Date.now();
    for (const [deviceCode, rec] of byDeviceCode) {
      if (now - rec.createdAt > ttlMs) {
        byDeviceCode.delete(deviceCode);
        byUserCode.delete(rec.userCode);
      }
    }
  }

  function generateUserCode(): string {
    const part = () =>
      Array.from({ length: 4 }, () => ALPHABET[randomBytes(1)[0] % ALPHABET.length]).join("");
    return `${part()}-${part()}`;
  }

  return {
    start(verificationBase: string): DeviceStartResult {
      sweep();
      if (byDeviceCode.size >= maxPending) {
        throw new Error("Demasiadas solicitudes de autorización pendientes");
      }
      const deviceCode = randomUUID();
      let userCode = generateUserCode();
      while (byUserCode.has(userCode)) userCode = generateUserCode();
      byDeviceCode.set(deviceCode, { userCode, status: "pending", createdAt: Date.now() });
      byUserCode.set(userCode, deviceCode);
      return {
        deviceCode,
        userCode,
        verificationUri: `${verificationBase}/cli/authorize`,
        expiresIn: Math.floor(ttlMs / 1000),
        interval: POLL_INTERVAL_S,
      };
    },

    async confirm(userCode: string, email: string): Promise<boolean> {
      sweep();
      const deviceCode = byUserCode.get(userCode.toUpperCase().trim());
      if (!deviceCode) return false;
      const rec = byDeviceCode.get(deviceCode);
      if (!rec || rec.status !== "pending") return false;
      const { plaintextKey } = await opts.createKey(email);
      rec.status = "approved";
      rec.apiKey = plaintextKey;
      rec.email = email;
      return true;
    },

    poll(deviceCode: string): DevicePollResult {
      sweep();
      const rec = byDeviceCode.get(deviceCode);
      if (!rec) return { status: "expired" };
      if (rec.status === "approved" && rec.apiKey && rec.email) {
        byDeviceCode.delete(deviceCode);
        byUserCode.delete(rec.userCode);
        return { status: "approved", apiKey: rec.apiKey, email: rec.email };
      }
      return { status: "pending" };
    },
  };
}
