import { describe, it, afterEach, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { limpiarCaches } from "./stalwart.ts";

const CLAVES = [
  "STALWART_ADMIN_URL", "STALWART_ADMIN_USER", "STALWART_ADMIN_PASSWORD",
  "IMAP_ENABLED_DOMAINS",
];
const previo = { ...process.env };
afterEach(() => {
  for (const k of CLAVES) {
    if (previo[k] === undefined) delete process.env[k]; else process.env[k] = previo[k];
  }
});
beforeEach(() => limpiarCaches());

/** El módulo lee el entorno al llamarse, pero recargarlo mantiene los casos aislados. */
async function cargar(env: Record<string, string | undefined>) {
  for (const [k, v] of Object.entries(env)) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
  limpiarCaches();
  return await import(`./imap-store.ts?v=${Math.random()}`);
}

const CONFIG = {
  STALWART_ADMIN_URL: "https://buzon.ejemplo.test",
  STALWART_ADMIN_USER: "admin",
  STALWART_ADMIN_PASSWORD: "secreto",
};

const CRUDO = "From: a@ejemplo.com\r\nTo: ventas@mailmask.studio\r\n\r\nhola";

describe("Buzón IMAP: cuándo aplica", () => {
  it("con servidor configurado aplica a cualquier dominio: la decisión es por máscara", async () => {
    const m = await cargar({ ...CONFIG });
    assert.equal(m.imapHabilitado("mailmask.studio"), true);
    assert.equal(m.imapHabilitado("cualquiera.com"), true);
  });

  it("sin credenciales de administrador no aplica", async () => {
    const m = await cargar({ STALWART_ADMIN_URL: undefined, STALWART_ADMIN_PASSWORD: undefined });
    assert.equal(m.imapHabilitado("mailmask.studio"), false);
  });
});

/**
 * Lo que este bloque protege: hasta el 7-sep-2026 el depósito autenticaba con UN
 * usuario global y entregaba siempre en su INBOX, ignorando al destinatario. Con un
 * solo dominio activado no se notaba; con dos, el correo del cliente A habría caído
 * en el buzón del cliente B. No es una molestia, es una fuga de datos.
 */
describe("🔴 Cada correo va al buzón de SU destinatario", () => {
  const fetchReal = globalThis.fetch;
  afterEach(() => { globalThis.fetch = fetchReal; });

  /** Servidor de mentira: cada dirección tiene su propia cuenta. */
  function servidor(buzones: Record<string, string>) {
    const importados: { accountId: string; blob: string }[] = [];
    const blobs = new Map<string, string>();

    globalThis.fetch = (async (url: any, init?: any) => {
      const u = String(url);
      const cuerpo = init?.body ? String(init.body) : "";

      if (u.endsWith("/jmap/session")) {
        return new Response(JSON.stringify({ primaryAccounts: { "urn:x": "admin1" } }));
      }
      if (u.includes("/jmap/upload/")) {
        const accountId = u.split("/jmap/upload/")[1].replace(/\/$/, "");
        const blobId = `blob${blobs.size}`;
        blobs.set(blobId, accountId);
        return new Response(JSON.stringify({ blobId, accountId }));
      }
      const req = JSON.parse(cuerpo);
      const [metodo, args] = req.methodCalls[0];

      if (metodo === "Principal/query") {
        const id = buzones[String(args.filter.email).toLowerCase()];
        return new Response(JSON.stringify({
          methodResponses: [["Principal/query", { ids: id ? [id] : [] }, "c0"]],
        }));
      }
      if (metodo === "Mailbox/query") {
        return new Response(JSON.stringify({
          methodResponses: [["Mailbox/query", { ids: [`inbox-${args.accountId}`] }, "c0"]],
        }));
      }
      if (metodo === "Email/import") {
        const blobId = args.emails.e1.blobId;
        importados.push({ accountId: args.accountId, blob: blobId });
        return new Response(JSON.stringify({
          methodResponses: [["Email/import", { created: { e1: { id: "e1" } } }, "c0"]],
        }));
      }
      return new Response(JSON.stringify({ methodResponses: [[metodo, {}, "c0"]] }));
    }) as typeof fetch;

    return { importados, blobs };
  }

  it("dos dominios activados NO se mezclan", async () => {
    const s = servidor({
      "ventas@uno.com": "cuentaUno",
      "ventas@dos.com": "cuentaDos",
    });
    const m = await cargar({ ...CONFIG });

    assert.equal(await m.depositarEnImap(CRUDO, "uno.com", "ventas@uno.com"), true);
    assert.equal(await m.depositarEnImap(CRUDO, "dos.com", "ventas@dos.com"), true);

    assert.deepEqual(s.importados.map((i) => i.accountId), ["cuentaUno", "cuentaDos"]);
    // Y el blob se subió a la cuenta correcta, no sólo se importó ahí.
    for (const i of s.importados) assert.equal(s.blobs.get(i.blob), i.accountId);
  });

  it("un destinatario SIN buzón no se deposita en ningún lado", async () => {
    // Fail-closed: es lo que impide que el correo caiga en un buzón ajeno.
    const s = servidor({ "ventas@uno.com": "cuentaUno" });
    const m = await cargar({ ...CONFIG });

    assert.equal(await m.depositarEnImap(CRUDO, "uno.com", "nadie@uno.com"), false);
    assert.equal(s.importados.length, 0);
  });

  it("la dirección se resuelve sin importar mayúsculas", async () => {
    const s = servidor({ "ventas@uno.com": "cuentaUno" });
    const m = await cargar({ ...CONFIG });

    assert.equal(await m.depositarEnImap(CRUDO, "uno.com", "Ventas@UNO.com"), true);
    assert.equal(s.importados[0].accountId, "cuentaUno");
  });
});

describe("🔴 El buzón nunca puede romper el reenvío", () => {
  const fetchReal = globalThis.fetch;
  afterEach(() => { globalThis.fetch = fetchReal; });

  it("sin servidor configurado devuelve false sin salir a la red", async () => {
    let llamadas = 0;
    globalThis.fetch = (async () => { llamadas++; return new Response("{}"); }) as typeof fetch;
    const m = await cargar({ STALWART_ADMIN_URL: undefined, STALWART_ADMIN_PASSWORD: undefined });
    assert.equal(await m.depositarEnImap(CRUDO, "mailmask.studio", "ventas@mailmask.studio"), false);
    assert.equal(llamadas, 0);
  });

  it("si el buzón está caído devuelve false, NO lanza", async () => {
    globalThis.fetch = (async () => { throw new Error("conexión rechazada"); }) as typeof fetch;
    const m = await cargar({ ...CONFIG });
    // Si esto lanzara, el correo del cliente no se reenviaría por culpa de un
    // destino secundario. Es la razón de ser del try/catch de ese módulo.
    assert.equal(await m.depositarEnImap(CRUDO, "mailmask.studio", "ventas@mailmask.studio"), false);
  });

  it("si el buzón responde error HTTP tampoco lanza", async () => {
    globalThis.fetch = (async () => new Response("no", { status: 500 })) as typeof fetch;
    const m = await cargar({ ...CONFIG });
    assert.equal(await m.depositarEnImap(CRUDO, "mailmask.studio", "ventas@mailmask.studio"), false);
  });

  it("un fallo de red al resolver NO se cachea como 'no existe'", async () => {
    // Si se cacheara, un parpadeo de red dejaría un buzón legítimo sin correo
    // durante los diez minutos del TTL, en silencio.
    let intentos = 0;
    globalThis.fetch = (async () => { intentos++; throw new Error("red"); }) as typeof fetch;
    const m = await cargar({ ...CONFIG });

    await m.depositarEnImap(CRUDO, "uno.com", "ventas@uno.com");
    await m.depositarEnImap(CRUDO, "uno.com", "ventas@uno.com");
    assert.ok(intentos >= 2, "el segundo intento debe volver a preguntar");
  });

  it("un buzón que acepta pero nunca contesta se corta por presupuesto", async () => {
    // Sin el tope global, los timeouts internos se suman y un buzón colgado
    // retrasaría el reenvío de un correo que no tiene nada que ver con IMAP.
    globalThis.fetch = (() => new Promise(() => {})) as unknown as typeof fetch;
    const m = await cargar({ ...CONFIG });
    const t0 = Date.now();
    assert.equal(await m.depositarEnImap(CRUDO, "mailmask.studio", "ventas@mailmask.studio"), false);
    const ms = Date.now() - t0;
    assert.ok(ms < 12_000, `tardó ${ms} ms; el presupuesto son 8 s`);
  });
});
