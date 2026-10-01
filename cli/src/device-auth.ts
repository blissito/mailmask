export interface DeviceStart {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  verificationUriComplete: string;
  expiresIn: number;
  interval: number;
}

export type DevicePoll =
  | { status: "pending" }
  | { status: "approved"; apiKey: string; email: string }
  | { status: "expired" };

export async function startDeviceLogin(baseUrl: string): Promise<DeviceStart> {
  const res = await fetch(`${baseUrl}/api/cli/device/start`, { method: "POST" });
  if (!res.ok) throw new Error(`No se pudo iniciar el login (${res.status})`);
  return (await res.json()) as DeviceStart;
}

export async function pollDeviceLogin(baseUrl: string, deviceCode: string): Promise<DevicePoll> {
  const res = await fetch(`${baseUrl}/api/cli/device/poll?deviceCode=${encodeURIComponent(deviceCode)}`);
  if (!res.ok) throw new Error(`No se pudo confirmar el login (${res.status})`);
  return (await res.json()) as DevicePoll;
}
