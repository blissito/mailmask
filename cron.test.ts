// Smoke test de cron.ts: los 25 jobs que agenda al importarse, cada uno una vez, sobre una base
// recién migrada y vacía. Nada lo ejercía: scheduler.test.ts sólo vigila que importarlo no agende
// nada. Un job que truene, o que llame a AWS o a MercadoPago de verdad, se descubría en producción,
// a la hora que le tocaba.
//
// Dobles (ficha docs/agents/pruebas-mocks.md):
//  - ./scheduler.ts con el real esparcido: schedule() guarda {expr, fn} en vez de agendar.
//  - Los clientes del SDK de AWS, no los módulos: registran el comando y contestan vacío.
//  - globalThis.fetch: registra la URL y contesta 503. Contesta en vez de lanzar, para no ejercer
//    sólo los catch.
//  - net.Socket.prototype.connect: registra y rechaza toda conexión real.
// La base se aísla con DATABASE_PATH en un mkdtemp ANTES de importar pg.ts, que migra al cargarse.

import { describe, it, before, after, mock } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const DIR_BASE = mkdtempSync(join(tmpdir(), "cron-smoke-"));
process.env.DATABASE_PATH = join(DIR_BASE, "cron-smoke.db");
// Sin estas tres, los 5 jobs de IMAP salen por stalwartConfigurado() y no ejercen nada.
process.env.STALWART_ADMIN_URL = "http://stalwart.invalid";
process.env.STALWART_ADMIN_USER = "admin";
process.env.STALWART_ADMIN_PASSWORD = "test";
delete process.env.PREVIEW;

/** Expresiones de los 25 jobs de cron.ts, en el orden en que los agenda. */
const EXPRESIONES = [
  "* * * * *",
  "*/5 * * * *",
  "0 14 * * *",
  "*/15 * * * *",
  "0 4 * * *",
  "0 5 * * *",
  "0 3 * * *",
  "* * * * *",
  "*/10 * * * *",
  "7 * * * *",
  "0 8 * * *",
  "30 8 * * *",
  "45 8 * * *",
  "10 5 * * *",
  "*/10 * * * *",
  "* * * * *",
  "0 9 * * *",
  "*/5 * * * *",
  "0 6 * * *",
  "30 6 * * *",
  "0 7 * * *",
  "15 7 * * *",
  "30 3 * * *",
  "0 15 * * *",
  "0 15 * * 1",
];

/** Hosts que la prueba DOBLA a propósito. Cualquier otro en fetch es una fuga a la red real. */
const HOSTS_DOBLADOS = new Set([
  "api.mercadopago.com",
  "open.er-api.com",
  "api.frankfurter.app",
  "stalwart.invalid",
]);

/** Clientes del SDK que cron.ts y sus dependencias pueden usar: nombre del módulo → clase. */
const CLIENTES_AWS = {
  "@aws-sdk/client-s3": "S3Client",
  "@aws-sdk/client-ses": "SESClient",
  "@aws-sdk/client-sns": "SNSClient",
  "@aws-sdk/client-route-53": "Route53Client",
  "@aws-sdk/client-route-53-domains": "Route53DomainsClient",
  "@aws-sdk/client-iam": "IAMClient",
} as const;

const capturados: { expr: string; fn: () => void | Promise<void> }[] = [];
const comandosAws: string[] = [];
const urlsFetch: string[] = [];
const conexiones: string[] = [];
const fetchReal = globalThis.fetch;

function clienteAwsFalso() {
  return class {
    async send(comando: { constructor: { name: string } }) {
      comandosAws.push(comando.constructor.name);
      return {};
    }
  };
}

describe("cron.ts: cada job corre una vez sin lanzar ni salir a la red", () => {
  before(async () => {
    // forwarding.ts llega a cron.ts por sus imports y agenda su propio `*/5` al cargarse. El plan
    // deja sus crons fuera de esta prueba: se carga ANTES del doble, con el schedule real (inerte
    // fuera de main.ts), para que su llamada no cuente como un job de cron.ts.
    await import("./forwarding.ts");

    // El doble va ANTES de importar cron.ts, con el módulo real esparcido.
    const realScheduler = await import("./scheduler.ts");
    mock.module("./scheduler.ts", {
      namedExports: {
        ...realScheduler,
        schedule: (expr: string, fn: () => void | Promise<void>) => {
          capturados.push({ expr, fn });
        },
      },
    });

    for (const [modulo, clase] of Object.entries(CLIENTES_AWS)) {
      const real = await import(modulo);
      mock.module(modulo, { namedExports: { ...real, [clase]: clienteAwsFalso() } });
    }

    globalThis.fetch = (async (entrada: string | URL | Request) => {
      urlsFetch.push(
        typeof entrada === "string" ? entrada : entrada instanceof URL ? entrada.href : entrada.url,
      );
      return new Response("", { status: 503 });
    }) as typeof fetch;

    mock.method(net.Socket.prototype, "connect", (...args: unknown[]) => {
      conexiones.push(JSON.stringify(args[0]).slice(0, 200));
      throw new Error("prueba: conexión de red real bloqueada");
    });

    await import("./cron.ts");
  });

  after(() => {
    globalThis.fetch = fetchReal;
    mock.restoreAll();
    rmSync(DIR_BASE, { recursive: true, force: true });
  });

  it("agenda exactamente los 25 jobs de hoy, con sus expresiones en orden", () => {
    assert.deepEqual(capturados.map((c) => c.expr), EXPRESIONES);
  });

  EXPRESIONES.forEach((expr, i) => {
    it(`job ${i + 1} (${expr}) termina sin lanzar`, async () => {
      const job = capturados[i];
      assert.ok(job, `falta el job ${i + 1}`);
      await assert.doesNotReject(async () => {
        await job.fn();
      });
    });
  });

  it("durante toda la corrida no se abrió ninguna conexión real", () => {
    assert.deepEqual(
      conexiones,
      [],
      `conexiones de red reales: ${conexiones.join(", ")} (comandos AWS: ${comandosAws.length})`,
    );
    const hostsNoDoblados = urlsFetch
      .map((u) => new URL(u).host)
      .filter((host) => !HOSTS_DOBLADOS.has(host));
    assert.deepEqual(hostsNoDoblados, [], "fetch llegó a un host que no está doblado");
  });
});
