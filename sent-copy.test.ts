// Copia en Enviados: lo que sale por la Bandeja o la API desde una máscara con buzón
// se guarda también en la carpeta Enviados de ese buzón (Email/import con rol `sent`).
// SES y Stalwart son dobles; main.ts se importa después de instalar el mock de ses.ts.
import { describe, it, before, after, mock } from "node:test";
import assert from "node:assert/strict";

const suffix = Date.now();
const owner = `sentcopy-${suffix}@example.com`;
const domainName = `sentcopy-${suffix}.com`;
const ana = `ana@${domainName}`;

const STALWART = "https://buzon.ejemplo.test";
const fetchReal = globalThis.fetch;
const imports: { accountId: string; role: string; keywords: Record<string, boolean>; raw: string }[] = [];
let stalwartDown = false;

/** Stalwart de mentira: `ana@` tiene cuenta, nadie más. */
function fakeStalwart() {
  const blobs = new Map<string, string>();
  let lastRole = "";
  globalThis.fetch = (async (url: any, init?: any) => {
    const u = String(url);
    if (!u.startsWith(STALWART)) return fetchReal(url, init);
    if (stalwartDown) throw new Error("ECONNREFUSED");
    if (u.endsWith("/jmap/session")) return new Response(JSON.stringify({ primaryAccounts: { "urn:x": "admin1" } }));
    if (u.includes("/jmap/upload/")) {
      const id = `blob${blobs.size}`;
      blobs.set(id, String(init.body));
      return new Response(JSON.stringify({ blobId: id }));
    }
    const [method, args] = JSON.parse(String(init.body)).methodCalls[0];
    const reply = (r: unknown) => new Response(JSON.stringify({ methodResponses: [[method, r, "c0"]] }));
    if (method === "Principal/query") return reply({ ids: args.filter.email === ana ? ["acc-ana"] : [] });
    if (method === "Mailbox/query") { lastRole = args.filter.role; return reply({ ids: [`mbx-${args.filter.role}`] }); }
    if (method === "Email/import") {
      const e = args.emails.e1;
      imports.push({ accountId: args.accountId, role: lastRole, keywords: e.keywords, raw: blobs.get(e.blobId) ?? "" });
      return reply({ created: { e1: { id: "email1" } } });
    }
    return reply({});
  }) as typeof fetch;
}

async function waitFor(pred: () => boolean, ms = 3000) {
  const t0 = Date.now();
  while (!pred()) {
    if (Date.now() - t0 > ms) return false;
    await new Promise((r) => setTimeout(r, 20));
  }
  return true;
}

const RAW = "From: ana@x.com\r\nTo: c@gmail.com\r\nSubject: Hola\r\nMessage-ID: <ours@x.com>\r\nMIME-Version: 1.0\r\n\r\ncuerpo";

describe("Copia en Enviados", () => {
  // deno-lint-ignore no-explicit-any
  let app: any; let dbmod: any; let sqlite: any; let store: any;
  let cookie = ""; let csrf = ""; let domainId = "";
  const envPrev = { ...process.env };

  before(async () => {
    process.env.STALWART_ADMIN_URL = STALWART;
    process.env.STALWART_ADMIN_USER = "admin";
    process.env.STALWART_ADMIN_PASSWORD = "secreto";
    fakeStalwart();

    const realSes = await import("./ses.ts");
    mock.module("./ses.ts", {
      namedExports: {
        ...realSes,
        sendFromDomain: async (from: string, to: string, subject: string) => {
          const sesMessageId = `ses-${crypto.randomUUID()}`;
          const raw = `From: ${from}\r\nTo: ${to}\r\nSubject: ${subject}\r\nMessage-ID: <stub@test>\r\nMIME-Version: 1.0\r\n\r\nhola`;
          return { messageId: "<stub@test>", sesMessageId, raw };
        },
      },
    });

    ({ app } = await import("./main.ts"));
    dbmod = await import("./db.ts");
    store = await import("./imap-store.ts");
    ({ sqlite } = await import("./pg.ts"));
    const { hashPassword } = await import("./auth.ts");
    (await import("./stalwart.ts")).limpiarCaches();

    sqlite.prepare("DELETE FROM rate_limits").run();
    dbmod.createUser(owner, await hashPassword("password123"));
    const loginRes = await app.fetch(new Request("http://localhost/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json", "fly-client-ip": "10.8.8.8" },
      body: JSON.stringify({ email: owner, password: "password123" }),
    }));
    for (const sc of loginRes.headers.getSetCookie?.() ?? []) {
      const t = sc.match(/(?:^|[\s,])token=([^;,]+)/);
      if (t && !cookie) cookie = `token=${t[1]}`;
      const c = sc.match(/csrf_token=([^;,]+)/);
      if (c && !csrf) csrf = c[1];
    }
    await loginRes.body?.cancel();

    const dom = dbmod.createDomain(owner, domainName, ["dk"], "vf");
    domainId = dom.id;
    sqlite.prepare("UPDATE domains SET verified = 1 WHERE id = ?").run(domainId);
    const addon = dbmod.createAddon(owner, "domain", domainId);
    dbmod.updateAddon(addon.id, { status: "active", currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString() });
    dbmod.createAlias(domainId, "ana", []);
    sqlite.prepare("UPDATE alias SET mailbox_enabled = 1 WHERE domain_id = ? AND alias = 'ana'").run(domainId);
    dbmod.createAlias(domainId, "hola", ["destino@example.com"]);
  });

  after(() => {
    globalThis.fetch = fetchReal;
    for (const k of ["STALWART_ADMIN_URL", "STALWART_ADMIN_USER", "STALWART_ADMIN_PASSWORD"]) {
      if (envPrev[k] === undefined) delete process.env[k]; else process.env[k] = envPrev[k];
    }
  });

  it("la copia lleva el Message-ID que SES pone (el que cita la respuesta) y fecha", () => {
    const out = store.prepareSentCopy(RAW, "abc123");
    assert.match(out, /^Message-ID: <abc123@email\.amazonses\.com>$/m);
    assert.doesNotMatch(out, /<ours@x\.com>/);
    assert.match(out, /^Date: /m);
    assert.ok(out.endsWith("\r\n\r\ncuerpo"), "el cuerpo no se toca");
  });

  it("máscara con buzón: importa en Enviados, marcado como leído", async () => {
    const n = imports.length;
    assert.equal(await store.copyToSentFolder(domainId, ana, { raw: RAW, sesMessageId: "s1" }), true);
    const imp = imports[n];
    assert.equal(imp.accountId, "acc-ana");
    assert.equal(imp.role, "sent");
    assert.deepEqual(imp.keywords, { $seen: true });
  });

  it("máscara sin buzón: ni una llamada a Stalwart", async () => {
    const n = imports.length;
    assert.equal(await store.copyToSentFolder(domainId, `hola@${domainName}`, { raw: RAW }), false);
    assert.equal(imports.length, n);
  });

  it("Stalwart caído: devuelve false y no lanza", async () => {
    stalwartDown = true;
    (await import("./stalwart.ts")).limpiarCaches();
    try {
      assert.equal(await store.copyToSentFolder(domainId, ana, { raw: RAW, sesMessageId: "s2" }), false);
    } finally {
      stalwartDown = false;
    }
  });

  it("responder desde la Bandeja deja la respuesta en Enviados del buzón", async () => {
    const conv = dbmod.createConversation({
      domainId, from: "lead@empresa.mx", to: ana, subject: "Duda", status: "open", priority: "normal",
      lastMessageAt: new Date().toISOString(), messageCount: 1, tags: [], threadReferences: ["<in-1@empresa.mx>"],
    });
    const n = imports.length;
    const res = await app.fetch(new Request(`http://localhost/api/bandeja/conversations/${conv.id}/reply`, {
      method: "POST",
      headers: {
        "content-type": "application/json", "fly-client-ip": "10.8.8.9",
        cookie: `${cookie}; csrf_token=${csrf}`, "x-csrf-token": csrf,
      },
      body: JSON.stringify({ domainId, body: "Claro, va." }),
    }));
    assert.equal(res.status, 200, await res.clone().text());
    assert.ok(await waitFor(() => imports.length > n), "debe importarse en Enviados");
    const imp = imports[imports.length - 1];
    assert.equal(imp.role, "sent");
    assert.match(imp.raw, new RegExp(`^From: ${ana}`, "m"));
    assert.match(imp.raw, /@email\.amazonses\.com>/);
  });
});
