import { spawn } from "node:child_process";

// Si no se puede abrir solo (sin entorno gráfico, sin `xdg-open` instalado,
// sandbox, etc.) no truena el login: el mensaje que lo llama ya imprimió el
// link a mano. El listener de "error" es obligatorio porque `spawn` falla de
// forma ASÍNCRONA cuando el binario no existe (ENOENT) — sin él, Node trata
// ese error como no manejado y mata el proceso completo.
export function openBrowser(url: string): void {
  try {
    const platform = process.platform;
    const child =
      platform === "darwin"
        ? spawn("open", [url], { stdio: "ignore", detached: true })
        : platform === "win32"
          ? spawn("cmd", ["/c", "start", "", url], { stdio: "ignore", detached: true })
          : spawn("xdg-open", [url], { stdio: "ignore", detached: true });
    child.on("error", () => {
      // ignorado a propósito: el mensaje con el link ya se imprimió antes de llamar aquí.
    });
    child.unref();
  } catch {
    // ignorado a propósito
  }
}
