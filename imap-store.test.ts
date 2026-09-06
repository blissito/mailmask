import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";

const previo = { ...process.env };
afterEach(() => {
  for (const k of ["IMAP_JMAP_URL", "IMAP_JMAP_USER", "IMAP_JMAP_PASSWORD", "IMAP_ENABLED_DOMAINS"]) {
    if (previo[k] === undefined) delete process.env[k]; else process.env[k] = previo[k];
  }
});

/** El módulo lee el entorno al importarse, así que cada caso lo recarga. */
async function cargar(env: Record<string, string | undefined>) {
  for (const [k, v] of Object.entries(env)) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
  return await import(`./imap-store.ts?v=${Math.random()}`);
}

const CONFIG = {
  IMAP_JMAP_URL: "https://buzon.ejemplo.test",
  IMAP_JMAP_USER: "buzon@ejemplo.test",
  IMAP_JMAP_PASSWORD: "secreto",
};

describe("Buzón IMAP: qué dominios entran", () => {
  it("sólo los listados, y sin importar mayúsculas", async () => {
    const m = await cargar({ ...CONFIG, IMAP_ENABLED_DOMAINS: "MailMask.Studio, otro.com" });
    assert.equal(m.imapHabilitado("mailmask.studio"), true);
    assert.equal(m.imapHabilitado("MAILMASK.STUDIO"), true);
    assert.equal(m.imapHabilitado("otro.com"), true);
    assert.equal(m.imapHabilitado("ajeno.com"), false);
  });

  it("lista vacía significa NADIE, no todos", async () => {
    // Es el default en producción: activar IMAP tiene que ser un acto explícito.
    const m = await cargar({ ...CONFIG, IMAP_ENABLED_DOMAINS: "" });
    assert.equal(m.imapHabilitado("mailmask.studio"), false);
  });

  it("sin credenciales no se activa aunque el dominio esté listado", async () => {
    const m = await cargar({
      IMAP_JMAP_URL: undefined, IMAP_JMAP_USER: undefined, IMAP_JMAP_PASSWORD: undefined,
      IMAP_ENABLED_DOMAINS: "mailmask.studio",
    });
    assert.equal(m.imapHabilitado("mailmask.studio"), false);
  });
});

describe("🔴 El buzón nunca puede romper el reenvío", () => {
  const fetchReal = globalThis.fetch;
  afterEach(() => { globalThis.fetch = fetchReal; });

  it("un dominio no habilitado devuelve false sin salir a la red", async () => {
    let llamadas = 0;
    globalThis.fetch = (async () => { llamadas++; return new Response("{}"); }) as typeof fetch;
    const m = await cargar({ ...CONFIG, IMAP_ENABLED_DOMAINS: "otro.com" });
    assert.equal(await m.depositarEnImap("From: a\r\n\r\nhola", "mailmask.studio"), false);
    assert.equal(llamadas, 0);
  });

  it("si el buzón está caído devuelve false, NO lanza", async () => {
    globalThis.fetch = (async () => { throw new Error("conexión rechazada"); }) as typeof fetch;
    const m = await cargar({ ...CONFIG, IMAP_ENABLED_DOMAINS: "mailmask.studio" });
    // Si esto lanzara, el correo del cliente no se reenviaría por culpa de un
    // destino secundario. Es la razón de ser del try/catch de ese módulo.
    assert.equal(await m.depositarEnImap("From: a\r\n\r\nhola", "mailmask.studio"), false);
  });

  it("si el buzón responde error HTTP tampoco lanza", async () => {
    globalThis.fetch = (async () => new Response("no", { status: 500 })) as typeof fetch;
    const m = await cargar({ ...CONFIG, IMAP_ENABLED_DOMAINS: "mailmask.studio" });
    assert.equal(await m.depositarEnImap("From: a\r\n\r\nhola", "mailmask.studio"), false);
  });

  it("si la sesión no trae cuenta, se rinde sin romper", async () => {
    globalThis.fetch = (async () => new Response(JSON.stringify({ accounts: {} }))) as typeof fetch;
    const m = await cargar({ ...CONFIG, IMAP_ENABLED_DOMAINS: "mailmask.studio" });
    assert.equal(await m.depositarEnImap("From: a\r\n\r\nhola", "mailmask.studio"), false);
  });

  it("un buzón que acepta pero nunca contesta se corta por presupuesto", async (t) => {
    // Sin el tope global, los timeouts internos se suman y un buzón colgado
    // retrasaría el reenvío de un correo que no tiene nada que ver con IMAP.
    globalThis.fetch = (() => new Promise(() => {})) as unknown as typeof fetch;
    const m = await cargar({ ...CONFIG, IMAP_ENABLED_DOMAINS: "mailmask.studio" });
    const t0 = Date.now();
    assert.equal(await m.depositarEnImap("From: a\r\n\r\nhola", "mailmask.studio"), false);
    const ms = Date.now() - t0;
    assert.ok(ms < 12_000, `tardó ${ms} ms; el presupuesto son 8 s`);
  });
});
