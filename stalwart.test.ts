import { describe, it, afterEach, beforeEach } from "node:test";
import assert from "node:assert/strict";
import {
  generarPassword, stalwartConfigurado, limpiarCaches,
  crearBuzon, borrarBuzon, leerUso, accountIdDe, estaVivo, diasDeCertificado,
} from "./stalwart.ts";

const CLAVES = ["STALWART_ADMIN_URL", "STALWART_ADMIN_USER", "STALWART_ADMIN_PASSWORD"];
const previo = { ...process.env };
const fetchReal = globalThis.fetch;

beforeEach(() => {
  limpiarCaches();
  process.env.STALWART_ADMIN_URL = "https://buzon.ejemplo.test";
  process.env.STALWART_ADMIN_USER = "admin";
  process.env.STALWART_ADMIN_PASSWORD = "secreto";
});
afterEach(() => {
  globalThis.fetch = fetchReal;
  for (const k of CLAVES) {
    if (previo[k] === undefined) delete process.env[k]; else process.env[k] = previo[k];
  }
});

/** Servidor de mentira que responde a los métodos JMAP que usamos. */
function servidor(manejar: (metodo: string, args: any) => any, extra?: (url: string) => Response | null) {
  const vistas: { metodo: string; args: any }[] = [];
  globalThis.fetch = (async (url: any, init?: any) => {
    const u = String(url);
    const especial = extra?.(u);
    if (especial) return especial;
    if (u.endsWith("/jmap/session")) {
      return new Response(JSON.stringify({ primaryAccounts: { "urn:x": "admin1" } }));
    }
    const [metodo, args] = JSON.parse(String(init.body)).methodCalls[0];
    vistas.push({ metodo, args });
    return new Response(JSON.stringify({ methodResponses: [[metodo, manejar(metodo, args), "c0"]] }));
  }) as typeof fetch;
  return vistas;
}

describe("Contraseñas de buzón", () => {
  it("son largas y con alfabeto sin caracteres confundibles", () => {
    // Stalwart rechaza contraseñas débiles con un medidor tipo zxcvbn, no con una
    // regla de caracteres: lo que hace falta es entropía, no cumplir una política.
    const p = generarPassword();
    assert.equal(p.length, 24);
    assert.ok(!/[0O1lI]/.test(p), `"${p}" trae caracteres que se confunden al dictarla`);
  });

  it("no se repiten", () => {
    const muestras = new Set(Array.from({ length: 200 }, () => generarPassword()));
    assert.equal(muestras.size, 200);
  });
});

describe("Configuración", () => {
  it("sin URL ni clave, no está configurado", () => {
    delete process.env.STALWART_ADMIN_URL;
    assert.equal(stalwartConfigurado(), false);
  });

  it("las operaciones fallan limpio, sin lanzar, si no hay servidor", async () => {
    delete process.env.STALWART_ADMIN_PASSWORD;
    const r = await crearBuzon({ localPart: "ventas", domain: "uno.com", quotaBytes: 100 });
    assert.equal(r.ok, false);
  });
});

describe("Alta de buzón", () => {
  it("NO manda emailAddress: lo deriva el servidor", async () => {
    // Mandarlo explícito revienta con `invalidPatch / Cannot modify server set property`.
    const vistas = servidor((m) => {
      if (m === "x:Domain/query") return { ids: ["d1"] };
      if (m === "x:Account/set") return { created: { t1: { id: "a1" } } };
      return {};
    });
    const r = await crearBuzon({ localPart: "ventas", domain: "uno.com", quotaBytes: 1024 });
    assert.equal(r.ok, true);

    const alta = vistas.find((v) => v.metodo === "x:Account/set")!;
    const creado = alta.args.create.t1;
    assert.ok(!("emailAddress" in creado), "emailAddress no debe ir en la petición");
    assert.equal(creado.name, "ventas");
    assert.equal(creado.quotas.maxDiskQuota, 1024);
  });

  it("devuelve la contraseña UNA vez y no la guarda en ningún lado", async () => {
    servidor((m) => {
      if (m === "x:Domain/query") return { ids: ["d1"] };
      if (m === "x:Account/set") return { created: { t1: { id: "a1" } } };
      return {};
    });
    const r = await crearBuzon({ localPart: "ventas", domain: "uno.com", quotaBytes: 1024 });
    assert.ok(r.ok && r.valor.password.length === 24);
    assert.equal(r.ok && r.valor.email, "ventas@uno.com");
  });

  it("un dominio que no existe en el servidor se crea solo, ya en split delivery", async () => {
    // `allowRelaying: true` es lo que deja que un buzón le escriba a una máscara del
    // mismo dominio (que vive en SES) en vez de recibir "550 Mailbox does not exist".
    const vistas = servidor((m) => {
      if (m === "x:Domain/query") return { ids: [] };
      if (m === "x:Domain/set") return { created: { d1: { id: "dnuevo" } } };
      if (m === "x:Account/set") return { created: { t1: { id: "a1" } } };
      return {};
    });
    const r = await crearBuzon({ localPart: "ventas", domain: "nuevo.com", quotaBytes: 1024 });
    assert.equal(r.ok, true);
    const alta = vistas.find((v) => v.metodo === "x:Domain/set")!;
    assert.equal(alta.args.create.d1.name, "nuevo.com");
    assert.equal(alta.args.create.d1.allowRelaying, true);
    // Si Stalwart firmara, SES rechaza el correo por DKIM duplicado.
    assert.deepEqual(alta.args.create.d1.dkimManagement, { "@type": "Manual" });
    const cuenta = vistas.find((v) => v.metodo === "x:Account/set")!;
    assert.equal(cuenta.args.create.t1.domainId, "dnuevo");
  });

  it("si el servidor no deja crear el dominio, el error lo dice", async () => {
    servidor((m) => (m === "x:Domain/query" ? { ids: [] } : {}));
    const r = await crearBuzon({ localPart: "ventas", domain: "ajeno.com", quotaBytes: 1024 });
    assert.equal(r.ok, false);
    assert.match(r.ok ? "" : r.error, /preparar el dominio/);
  });

  it("una contraseña rechazada por débil se reporta con el motivo del servidor", async () => {
    servidor((m) => {
      if (m === "x:Domain/query") return { ids: ["d1"] };
      return { notCreated: { t1: { type: "invalidProperties", description: "Password is too weak." } } };
    });
    const r = await crearBuzon({ localPart: "ventas", domain: "uno.com", quotaBytes: 1024 });
    assert.equal(r.ok, false);
    assert.match(r.ok ? "" : r.error, /too weak/);
  });
});

describe("Baja de buzón", () => {
  it("borrar es idempotente: una cuenta que ya no está no es un error", async () => {
    // Si no lo fuera, un reintento del cron de gracia dejaría la fila marcada para
    // siempre y el barrido de huérfanas la reportaría cada día.
    servidor(() => ({ notDestroyed: { a1: { type: "notFound" } } }));
    const r = await borrarBuzon("a1", "ventas@uno.com");
    assert.equal(r.ok, true);
  });

  it("un fallo real sí se reporta", async () => {
    servidor(() => ({ notDestroyed: { a1: { type: "forbidden", description: "nel" } } }));
    const r = await borrarBuzon("a1");
    assert.equal(r.ok, false);
  });
});

describe("Cuota y uso", () => {
  it("uso y límite salen de UNA sola llamada", async () => {
    const vistas = servidor(() => ({
      list: [{ id: "a1", usedDiskQuota: 500, quotas: { maxDiskQuota: 1000 }, emailAddress: "v@uno.com" }],
    }));
    const r = await leerUso("a1");
    assert.deepEqual(r.ok && r.valor, { usados: 500, limite: 1000, email: "v@uno.com" });
    assert.equal(vistas.length, 1, "no debe hacer falta autenticarse como el usuario");
  });
});

describe("Resolver una dirección a su cuenta", () => {
  it("una dirección sin buzón devuelve null, no un error", async () => {
    // Ese null es el fail-closed del depósito: sin buzón conocido no se guarda nada.
    servidor((m) => (m === "Principal/query" ? { ids: [] } : {}));
    assert.equal(await accountIdDe("nadie@uno.com"), null);
  });

  it("se cachea, para no preguntar por cada correo", async () => {
    const vistas = servidor((m) => (m === "Principal/query" ? { ids: ["a1"] } : {}));
    assert.equal(await accountIdDe("v@uno.com"), "a1");
    assert.equal(await accountIdDe("v@uno.com"), "a1");
    assert.equal(vistas.filter((v) => v.metodo === "Principal/query").length, 1);
  });
});

describe("Salud", () => {
  it("está vivo si /jmap/session contesta, incluso sin credenciales", async () => {
    // Es un chequeo anónimo a propósito: prueba el listener, no el secreto.
    globalThis.fetch = (async () => new Response("{}", { status: 401 })) as typeof fetch;
    assert.equal(await estaVivo(), true);
  });

  it("no está vivo si la conexión falla", async () => {
    globalThis.fetch = (async () => { throw new Error("nel"); }) as typeof fetch;
    assert.equal(await estaVivo(), false);
  });

  it("del certificado se toma el que caduca PRIMERO", async () => {
    const dentroDe10 = new Date(Date.now() + 10 * 86400_000).toISOString();
    const dentroDe90 = new Date(Date.now() + 90 * 86400_000).toISOString();
    servidor((m) => {
      if (m === "x:Certificate/query") return { ids: ["c1", "c2"] };
      return { list: [{ notValidAfter: dentroDe90 }, { notValidAfter: dentroDe10 }] };
    });
    const dias = await diasDeCertificado();
    assert.ok(dias !== null && dias >= 9 && dias <= 10, `dio ${dias}`);
  });
});
