import cron from "node-cron";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Programación de tareas que sólo corre cuando el proceso ES el servidor.
 *
 * Los crons viven en tres módulos (`main.ts`, `cron.ts`, `forwarding.ts`) y los tres se
 * importan desde los tests. `node-cron` se re-agenda cada segundo, así que un solo
 * `cron.schedule()` bastaba para que el proceso de pruebas no muriera nunca. Por eso
 * `npm test` llevaba `--test-force-exit`, y ese flag mata al hijo antes de que termine
 * de mandar su TAP al padre: el resumen perdía resultados al azar — 244 tests en una
 * corrida y 293 en la siguiente, con los mismos archivos y sin un solo fallo.
 *
 * El criterio es "¿este proceso arrancó main.ts?" y no "¿este archivo es el
 * entrypoint?", justamente porque quien programa no es quien arranca.
 */
const MAIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "main.ts");

export const esServidor = (() => {
  const arg = process.argv[1];
  if (!arg) return false;
  try {
    return path.resolve(arg) === MAIN;
  } catch {
    return false;
  }
})();

/** `cron.schedule`, pero inerte fuera del servidor. */
export function programar(expr: string, fn: () => void | Promise<void>): void {
  if (esServidor) cron.schedule(expr, fn);
}
