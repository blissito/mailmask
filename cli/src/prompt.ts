import { createInterface } from "node:readline";

/**
 * Pide una línea por stdin. Rechaza de inmediato si no hay TTY, en vez de quedarse
 * colgada esperando una tecla que nunca llega (mata cualquier uso desde un agente o pipeline).
 */
export function promptLine(question: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) {
      reject(new Error("stdin no es interactivo: pasa --api-key o fija MAILMASK_API_KEY."));
      return;
    }
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}
