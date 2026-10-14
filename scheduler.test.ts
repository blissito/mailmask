// scheduler.ts existe para que los ~30 `schedule()` de `cron.ts` y `forwarding.ts` sean inertes
// fuera de `main.ts`. Nada lo vigilaba: `preview.test.ts` prueba la función pura `debeProgramar`,
// pero no que los módulos de verdad pasen por ella. Un `cron.schedule` directo —o un `isServer`
// roto— dejaba el proceso de pruebas vivo para siempre, y eso era lo que llevaba a
// `--test-force-exit`, el flag que truncaba el reporte al azar.
//
// Se mide de dos maneras porque son dos fallas distintas:
//   1. En proceso: un espía sobre `node-cron` cuenta los crons que dispara importar los dos
//      módulos. Es el síntoma directo, y señala al culpable.
//   2. En un proceso hijo de verdad: importarlos y ver si el proceso MUERE SOLO. Es lo que de
//      verdad dolía (la suite colgada), y cubre lo que el espía no ve: un `setInterval` suelto
//      en cualquier módulo de la cadena cuelga igual sin agendar un cron.
// El hijo de control, que sí agenda, demuestra que el método detecta el cuelgue.

import { describe, it, before, mock } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const RAIZ = resolve(import.meta.dirname);

/** Tope del hijo «sano»: importar medio repo con tsx tarda, pero no 45 s. */
const TOPE_IMPORT_MS = 45_000;
/** Lo que se le da al hijo de control para demostrar que sigue vivo. */
const MARGEN_CONTROL_MS = 10_000;

// --- 1. En proceso: el espía sobre `node-cron` -------------------------------------------

const realCron = (await import("node-cron")) as unknown as Record<string, unknown>;
const agendados: unknown[][] = [];

// Los named exports del real, MENOS `default`: una llave `default` ahí hace que el módulo
// sintético no compile («Unexpected token 'default'»), y `scheduler.ts` lo único que importa de
// node-cron es el default.
const nombrados: Record<string, unknown> = {};
for (const [clave, valor] of Object.entries(realCron)) {
  if (clave !== "default") nombrados[clave] = valor;
}

// El doble va ANTES de importar (ficha `docs/agents/pruebas-mocks.md`) y con el módulo real
// esparcido: el default de node-cron es el objeto que trae `schedule`. El espía NO llama al
// `schedule` real a propósito: si lo llamara, el mutante de esta prueba dejaría un cron vivo y
// este archivo se colgaría en vez de ponerse rojo.
mock.module("node-cron", {
  defaultExport: {
    ...((realCron.default ?? realCron) as Record<string, unknown>),
    schedule: (...args: unknown[]) => {
      agendados.push(args);
      return { start: () => {}, stop: () => {} };
    },
  },
  namedExports: nombrados,
});

describe("scheduler: importar los crons no agenda nada", () => {
  let isServer: boolean | undefined;

  before(async () => {
    isServer = (await import("./scheduler.ts")).isServer;
    await import("./cron.ts");
    await import("./forwarding.ts");
  });

  it("desde el proceso de pruebas, isServer es false", () => {
    assert.equal(
      isServer,
      false,
      "`tsx --test` no arranca main.ts: isServer tiene que ser false, o los crons de abajo se agendan",
    );
  });

  it("importar cron.ts y forwarding.ts no agenda ni un cron", () => {
    assert.deepEqual(
      agendados.map((args) => args[0]),
      [],
      "los schedule() de cron.ts y forwarding.ts deben ser inertes fuera de main.ts",
    );
  });
});

// --- 2. El proceso hijo: el cuelgue de verdad ----------------------------------------------

interface Hijo {
  proceso: ChildProcess;
  salida: () => string;
  terminado: Promise<{ code: number | null; signal: NodeJS.Signals | null } | null>;
}

/**
 * Un hijo con el MISMO entorno que una prueba real —hereda `NODE_OPTIONS`, así que también trae
 * `test-setup.mjs` y su `unref` de los timers de más de un minuto—, sólo que con `PREVIEW` fuera
 * (para que la prueba no pase por `esPreview()` en vez de por `isServer`) y su propia base.
 *
 * `-e` es a propósito: sin `argv[1]`, `isServer` es `false`, igual que dentro de la suite. Si se
 * lanzara `main.ts`, el hijo agendaría los crons y la prueba no probaría nada.
 */
function lanzarHijo(codigo: string, datos: string): Hijo {
  const env: NodeJS.ProcessEnv = { ...process.env, DATABASE_PATH: join(datos, "hijo.db") };
  delete env.PREVIEW;

  const proceso = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", codigo], {
    cwd: RAIZ,
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  let salida = "";
  proceso.stdout?.on("data", (d) => { salida += String(d); });
  proceso.stderr?.on("data", (d) => { salida += String(d); });

  let tope: NodeJS.Timeout | undefined;
  const terminado = new Promise<{ code: number | null; signal: NodeJS.Signals | null } | null>((res) => {
    tope = setTimeout(() => res(null), TOPE_IMPORT_MS);
    proceso.on("exit", (code, signal) => {
      clearTimeout(tope);
      res({ code, signal });
    });
  });

  return { proceso, salida: () => salida, terminado };
}

/** `SIGKILL` si sigue vivo: un hijo colgado no se queda a vivir con el runner. */
function matar(hijo: Hijo): void {
  if (hijo.proceso.exitCode === null) hijo.proceso.kill("SIGKILL");
}

/** Espera la marca en la salida del hijo; `false` si el tope vence sin verla. */
async function esperarMarca(hijo: Hijo, marca: RegExp, topeMs: number): Promise<boolean> {
  const inicio = Date.now();
  while (Date.now() - inicio < topeMs) {
    if (marca.test(hijo.salida())) return true;
    if (hijo.proceso.exitCode !== null) break;
    await new Promise((r) => setTimeout(r, 200));
  }
  return marca.test(hijo.salida());
}

describe("scheduler: importar los crons no cuelga el proceso", () => {
  it(
    "un proceso que sólo importa cron.ts y forwarding.ts termina solo, con código 0",
    { timeout: 60_000 },
    async () => {
      const datos = mkdtempSync(join(tmpdir(), "mailmask-scheduler-"));
      const hijo = lanzarHijo(
        "await import('./cron.ts'); await import('./forwarding.ts'); console.log('importado');",
        datos,
      );
      try {
        const fin = await hijo.terminado;
        assert.ok(
          fin,
          `el hijo sigue vivo ${TOPE_IMPORT_MS} ms después de importar los crons: hay un cron agendado o un timer suelto en la cadena de imports.\nSalida:\n${hijo.salida().slice(-3000)}`,
        );
        assert.equal(
          fin.signal,
          null,
          `el hijo terminó por señal ${fin.signal}, no solo.\nSalida:\n${hijo.salida().slice(-3000)}`,
        );
        assert.equal(
          fin.code,
          0,
          `el hijo salió con ${fin.code}.\nSalida:\n${hijo.salida().slice(-3000)}`,
        );
        assert.match(
          hijo.salida(),
          /importado/,
          "sin el `importado` la prueba pasaría aunque el import hubiera tronado",
        );
      } finally {
        matar(hijo);
      }
    },
  );

  // El control. Sin él, la prueba de arriba podría estar pasando por el motivo equivocado: que un
  // hijo lanzado con `-e` termine siempre, agende o no. Éste agenda un cron directo y por eso
  // NO debe terminar.
  it(
    "control: un hijo que sí agenda un cron directo no termina solo",
    { timeout: 30_000 },
    async () => {
      const datos = mkdtempSync(join(tmpdir(), "mailmask-scheduler-control-"));
      const hijo = lanzarHijo(
        "import cron from 'node-cron'; cron.schedule('* * * * *', () => {}); console.log('agendado');",
        datos,
      );
      try {
        assert.ok(
          await esperarMarca(hijo, /agendado/, MARGEN_CONTROL_MS),
          `el control ni siquiera llegó a agendar.\nSalida:\n${hijo.salida().slice(-3000)}`,
        );
        // Ya agendado, se le dan unos segundos de reloj real: si el cron no lo mantuviera vivo,
        // para aquí ya habría salido. Sin esta espera el control sólo probaría que node tardó
        // 0 ms en morirse.
        await new Promise((r) => setTimeout(r, MARGEN_CONTROL_MS / 2));
        assert.equal(
          hijo.proceso.exitCode,
          null,
          `un cron agendado directo debe mantener vivo al hijo, y ya había salido.\nSalida:\n${hijo.salida().slice(-3000)}`,
        );
      } finally {
        matar(hijo);
      }
    },
  );
});
