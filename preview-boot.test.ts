// El criterio de aceptación del modo preview, medido de verdad: se arranca el servidor como
// lo arranca la caja (`tsx main.ts`) y se CUENTA lo que sale hacia AWS.
//
// El espía es un servidor HTTP local: `AWS_ENDPOINT_URL` redirige ahí a todos los clientes
// del SDK, así que cualquier llamada real (reparar receipt rules de SES, SNS, la
// reconciliación de dominios) aparece como una petición. `SNS_TOPIC_ARN` va puesto a
// propósito: sin él, la reparación de receipt rules se salta sola y el conteo saldría en
// cero por el motivo equivocado — la segunda prueba es justo eso, el control que demuestra
// que el espía SÍ ve las llamadas cuando las hay.
//
// Las llamadas a MercadoPago no pasan por el SDK de AWS: van por su propio guard y su
// propia prueba (`preview-mp.test.ts`).

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { AddressInfo } from "node:net";

const RAIZ = resolve(import.meta.dirname);
const ESPERA_MS = 60_000;

/** Un puerto libre de verdad: se lo pedimos al sistema y lo soltamos. */
async function puertoLibre(): Promise<number> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const { port } = s.address() as AddressInfo;
  await new Promise<void>((r) => s.close(() => r()));
  return port;
}

async function arrancar({ preview }: { preview: boolean }) {
  const peticionesAWS: string[] = [];
  const espia = createServer((req, res) => {
    peticionesAWS.push(`${req.method} ${req.url}`);
    res.writeHead(200, { "content-type": "application/json" });
    res.end("{}");
  });
  await new Promise<void>((r) => espia.listen(0, "127.0.0.1", r));
  const puertoAWS = (espia.address() as AddressInfo).port;

  const puerto = await puertoLibre();
  const datos = mkdtempSync(join(tmpdir(), "mailmask-preview-"));
  const hijo = spawn(process.execPath, ["--import", "tsx", join(RAIZ, "main.ts")], {
    cwd: RAIZ,
    env: {
      ...process.env,
      ...(preview ? { PREVIEW: "1" } : {}),
      PORT: String(puerto),
      DATABASE_PATH: join(datos, "preview.db"),
      AWS_ENDPOINT_URL: `http://127.0.0.1:${puertoAWS}`,
      SNS_TOPIC_ARN: "arn:aws:sns:us-east-1:000000000000:entrante",
      SNS_OUTBOUND_TOPIC_ARN: "arn:aws:sns:us-east-1:000000000000:saliente",
      JWT_SECRET: "test-secret-key",
      MP_ACCESS_TOKEN: "test",
      MP_WEBHOOK_SECRET: "test",
      AWS_ACCESS_KEY_ID: "test",
      AWS_SECRET_ACCESS_KEY: "test",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  let salida = "";
  hijo.stdout?.on("data", (d) => { salida += String(d); });
  hijo.stderr?.on("data", (d) => { salida += String(d); });

  /** Espera el 200 de `/` y deja pasar `margen` ms antes de contar. */
  const levantar = async (margen: number): Promise<number | null> => {
    const inicio = Date.now();
    let estado: number | null = null;
    while (Date.now() - inicio < ESPERA_MS) {
      if (hijo.exitCode !== null) break;
      try {
        estado = (await fetch(`http://127.0.0.1:${puerto}/`)).status;
        if (estado === 200) break;
      } catch {
        // Todavía no escucha: el arranque de tsx sobre un main.ts de 8 mil líneas tarda.
      }
      await new Promise((r) => setTimeout(r, 500));
    }
    if (estado === 200) await new Promise((r) => setTimeout(r, margen));
    return estado;
  };

  return {
    peticionesAWS,
    levantar,
    salida: () => salida,
    cerrar: async () => {
      hijo.kill("SIGKILL");
      await new Promise<void>((r) => espia.close(() => r()));
    },
  };
}

describe("arranque en preview", () => {
  it("responde 200 en / y no hace ni una petición a AWS", { timeout: 110_000 }, async () => {
    const p = await arrancar({ preview: true });
    try {
      const estado = await p.levantar(3000);
      assert.equal(
        estado,
        200,
        `GET / en una preview debe dar 200 en ${ESPERA_MS} ms. Salida del hijo:\n${p.salida().slice(-3000)}`,
      );
      assert.deepEqual(p.peticionesAWS, [], "una preview no debe hacer ninguna petición a AWS");
      assert.match(p.salida(), /Arranque con efectos omitido/, "el arranque con efectos se salta y lo dice");
      assert.match(p.salida(), /Backfill de búsqueda omitido/, "tampoco corre el backfill de búsqueda");
    } finally {
      await p.cerrar();
    }
  });

  // El control. Sin esta prueba, el `deepEqual(..., [])` de arriba podría estar pasando
  // porque el espía no ve nada, y no porque la preview se aguante las ganas.
  it("control: sin PREVIEW el mismo arranque sí toca AWS", { timeout: 110_000 }, async () => {
    const p = await arrancar({ preview: false });
    try {
      const estado = await p.levantar(10_000);
      assert.equal(estado, 200, `sin PREVIEW el servidor también tiene que levantar. Salida:\n${p.salida().slice(-3000)}`);
      assert.ok(
        p.peticionesAWS.length > 0,
        `sin PREVIEW el arranque repara receipt rules contra AWS; el espía no vio nada:\n${JSON.stringify(p.peticionesAWS)}`,
      );
    } finally {
      await p.cerrar();
    }
  });
});
