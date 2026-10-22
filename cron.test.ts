// Smoke test de cron.ts: los 26 jobs que agenda al importarse, cada uno una vez, sobre una base
// recién migrada y vacía. Nada lo ejercía: scheduler.test.ts sólo vigila que importarlo no agende
// nada. Un job que truene, o que llame a AWS o a MercadoPago de verdad, se descubría en producción,
// a la hora que le tocaba.
//
// Dobles (ficha docs/agents/pruebas-mocks.md):
//  - ./logger.ts con el real esparcido: los niveles "error" se guardan por job; el resto pasa al real.
//    Casi todos los jobs envuelven su cuerpo en try/catch y sólo registran el error: sin esto, un
//    ReferenceError dentro del job se tragaría y la prueba seguiría verde.
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

/** Expresiones de los 26 jobs de cron.ts, en el orden en que los agenda. */
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
  "17 * * * *", // vigía de 48 h tras mudar los NS (dns-watch.ts)
];

/**
 * Jobs IMAP que sí llegan a Stalwart con base vacía (índice base 0): estaVivo, diasDeCertificado y
 * listarBuzones. Los de `30 6` (leerUso) y `15 7` iteran listas vacías y nunca llaman al servidor:
 * desde fuera son indistinguibles de un job que salió por stalwartConfigurado(), así que sólo
 * cuentan como «no truenan».
 */
const TOCAN_STALWART = new Set([17, 18, 20]);

/**
 * Errores que un job registra A PROPÓSITO por culpa de un doble. Hoy está vacía: con el 503 del
 * fetch doblado (MercadoPago, fx, Stalwart) ningún job registra error. Cualquier error registrado
 * por un job que no esté aquí es un fallo de la prueba.
 */
const ERRORES_ESPERADOS: Record<number, string[]> = {};

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
const erroresLog: { component: string; msg: string }[] = [];
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
    // El logger va PRIMERO: así todo módulo que cargue después registra en el doble.
    const realLogger = await import("./logger.ts");
    mock.module("./logger.ts", {
      namedExports: {
        ...realLogger,
        log: (level: string, component: string, msg: string, data?: Record<string, unknown>) => {
          if (level === "error") erroresLog.push({ component, msg });
          else realLogger.log(level as never, component as never, msg, data);
        },
      },
    });

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

  it("agenda exactamente los 26 jobs de hoy, con sus expresiones en orden", () => {
    assert.deepEqual(capturados.map((c) => c.expr), EXPRESIONES);
  });

  EXPRESIONES.forEach((expr, i) => {
    it(`job ${i + 1} (${expr}) termina sin lanzar ni registrar errores no esperados`, async () => {
      const job = capturados[i];
      assert.ok(job, `falta el job ${i + 1}`);
      const erroresAntes = erroresLog.length;
      const urlsAntes = urlsFetch.length;
      await assert.doesNotReject(async () => {
        await job.fn();
      });
      const erroresDelJob = erroresLog.slice(erroresAntes).map((e) => `${e.component}: ${e.msg}`);
      assert.deepEqual(erroresDelJob, ERRORES_ESPERADOS[i] ?? [], `errores registrados por el job ${i + 1}`);
      if (TOCAN_STALWART.has(i)) {
        const hosts = urlsFetch.slice(urlsAntes).map((u) => new URL(u).host);
        assert.ok(hosts.includes("stalwart.invalid"), `el job ${i + 1} no llegó al servidor de correo doblado`);
      }
    });
  });

  it("el doble de logger registra un error aunque el job lo trague", async () => {
    const { log } = await import("./logger.ts");
    const antes = erroresLog.length;
    log("error", "cron", "prueba de guardia");
    assert.equal(erroresLog.length, antes + 1);
    erroresLog.length = antes;
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
