import assert from "node:assert/strict";
import { afterEach, describe, it, mock } from "node:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fakeClient, trapExit, ExitSignal } from "./test-helpers.js";

let currentClient: ReturnType<typeof fakeClient>["client"];

trapExit();
mock.module("../src/client.js", {
  namedExports: {
    requireClient: async () => ({ client: currentClient, auth: { apiKey: "mk_test", baseUrl: undefined, source: "env" as const } }),
    buildClient: () => currentClient,
  },
});

const { default: send } = await import("../src/commands/send.js");
const { email, bulk, status } = send.subCommands as Record<string, any>;

const OK = { ok: true, messageId: "m1", sesMessageId: "s1" };
const base = { domain: "acme.com", to: "x@y.com", subject: "Hola", text: "cuerpo", yes: true };
const dir = mkdtempSync(join(tmpdir(), "mm-send-"));
const archivo = (nombre: string, contenido: string | Buffer) => {
  const ruta = join(dir, nombre);
  writeFileSync(ruta, contenido);
  return ruta;
};

/** Ejecuta sin TTY y sin --yes: lo que haría un script o un agente. */
async function sinTty<T>(fn: () => Promise<T>): Promise<T> {
  const tty = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
  Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
  try {
    return await fn();
  } finally {
    if (tty) Object.defineProperty(process.stdin, "isTTY", tty); else delete (process.stdin as any).isTTY;
  }
}

function capturaStderr(): { texto: () => string } {
  let buf = "";
  espiar(process.stderr, (c) => (buf += c));
  return { texto: () => buf };
}

const exit1 = (e: unknown) => e instanceof ExitSignal && e.code === 1;
const enviado = (calls: { method: string; args: unknown[] }[]) => calls.find((c) => c.method === "send.send")!;

// Sólo se restauran los espías de stdout/stderr; el de process.exit y el de requireClient quedan para todo el archivo.
const restores: Array<() => void> = [];
function espiar(stream: NodeJS.WriteStream, onWrite: (chunk: string) => void): void {
  const spy = mock.method(stream, "write", ((chunk: unknown) => (onWrite(String(chunk)), true)) as never);
  restores.push(() => spy.mock.restore());
}
afterEach(() => {
  while (restores.length) restores.pop()!();
});

describe("send email", () => {
  it("--from hola envía con from=hola (nunca fromLocal) y --text va a body", async () => {
    const { client, calls } = fakeClient({ domains: { list: () => [{ id: "dom_9", domain: "acme.com" }] }, send: { send: () => OK } });
    currentClient = client;
    await email.run({ args: { ...base, from: "hola" } });
    const [id, input] = enviado(calls).args as [string, Record<string, unknown>];
    assert.equal(id, "dom_9");
    assert.equal(input.from, "hola");
    assert.equal(input.body, "cuerpo");
    assert.equal("fromLocal" in input, false);
    assert.equal("text" in input, false);
  });

  it("--from hola@acme.com se recorta a hola (sin importar mayúsculas)", async () => {
    const { client, calls } = fakeClient({ send: { send: () => OK } });
    currentClient = client;
    await email.run({ args: { ...base, from: "hola@ACME.com" } });
    assert.equal((enviado(calls).args[1] as any).from, "hola");
  });

  it("--from de otro dominio falla con error claro sin tocar la red", async () => {
    const { client, calls } = fakeClient({ send: { send: () => OK } });
    currentClient = client;
    const err = capturaStderr();
    await assert.rejects(() => email.run({ args: { ...base, from: "hola@otro.com" } }), exit1);
    assert.equal(calls.length, 0);
    assert.match(err.texto(), /otro\.com/);
  });

  it("--from completo con el dominio dado como id pide la parte local", async () => {
    const { client, calls } = fakeClient({ send: { send: () => OK } });
    currentClient = client;
    await assert.rejects(() => email.run({ args: { ...base, domain: "dom_1", from: "hola@acme.com" } }), exit1);
    assert.equal(calls.length, 0);
  });

  it("sin --from avisa en stderr que saldrá desde noreply@", async () => {
    const { client } = fakeClient({ send: { send: () => OK } });
    currentClient = client;
    const err = capturaStderr();
    await email.run({ args: base });
    assert.match(err.texto(), /noreply@acme\.com/);
  });

  it("--text, --html y --markdown van a body, html y markdown", async () => {
    const { client, calls } = fakeClient({ send: { send: () => OK } });
    currentClient = client;
    await email.run({ args: { ...base, text: undefined, html: "<p>hi</p>", markdown: "# hi" } });
    const input = enviado(calls).args[1] as Record<string, unknown>;
    assert.equal(input.html, "<p>hi</p>");
    assert.equal(input.markdown, "# hi");
    assert.equal("body" in input, false);
  });

  it("@ruta lee el cuerpo de un archivo", async () => {
    const { client, calls } = fakeClient({ send: { send: () => OK } });
    currentClient = client;
    await email.run({ args: { ...base, text: undefined, html: `@${archivo("c.html", "<b>archivo</b>")}` } });
    assert.equal((enviado(calls).args[1] as any).html, "<b>archivo</b>");
  });

  it("@ruta inexistente sale con 1 sin llamar al SDK", async () => {
    const { client, calls } = fakeClient({ send: { send: () => OK } });
    currentClient = client;
    await assert.rejects(() => email.run({ args: { ...base, text: `@${join(dir, "no-existe.txt")}` } }), exit1);
    assert.equal(calls.length, 0);
  });

  it("sin cuerpo sale con 1 sin llamar al SDK", async () => {
    const { client, calls } = fakeClient({ send: { send: () => OK } });
    currentClient = client;
    await assert.rejects(() => email.run({ args: { ...base, text: undefined } }), exit1);
    assert.equal(calls.length, 0);
  });

  it("html de más de 100 KB sale con 1 sin llamar al SDK", async () => {
    const { client, calls } = fakeClient({ send: { send: () => OK } });
    currentClient = client;
    await assert.rejects(() => email.run({ args: { ...base, text: undefined, html: "a".repeat(100 * 1024 + 1) } }), exit1);
    assert.equal(calls.length, 0);
  });

  it("sin --to o sin --subject sale con 1 sin llamar al SDK", async () => {
    const { client, calls } = fakeClient({ send: { send: () => OK } });
    currentClient = client;
    await assert.rejects(() => email.run({ args: { ...base, to: undefined } }), exit1);
    await assert.rejects(() => email.run({ args: { ...base, subject: "" } }), exit1);
    assert.equal(calls.length, 0);
  });

  it("--cc y --bcc aceptan uno o varios; más de 20 se rechaza", async () => {
    const { client, calls } = fakeClient({ send: { send: () => OK } });
    currentClient = client;
    await email.run({ args: { ...base, cc: "a@x.com", bcc: ["b@x.com", "c@x.com"] } });
    const input = enviado(calls).args[1] as any;
    assert.deepEqual(input.cc, ["a@x.com"]);
    assert.deepEqual(input.bcc, ["b@x.com", "c@x.com"]);
    const muchos = Array.from({ length: 21 }, (_, i) => `u${i}@x.com`);
    await assert.rejects(() => email.run({ args: { ...base, cc: muchos } }), exit1);
  });

  it("--from-name y --reply-to llegan como fromName y replyTo", async () => {
    const { client, calls } = fakeClient({ send: { send: () => OK } });
    currentClient = client;
    await email.run({ args: { ...base, "from-name": "Libretas", "reply-to": "r@x.com" } });
    const input = enviado(calls).args[1] as any;
    assert.equal(input.fromName, "Libretas");
    assert.equal(input.replyTo, "r@x.com");
  });

  it("--idempotency-key llega en opts, no en el input; más de 128 se rechaza", async () => {
    const { client, calls } = fakeClient({ send: { send: () => OK } });
    currentClient = client;
    await email.run({ args: { ...base, "idempotency-key": "k-1" } });
    const [, input, opts] = enviado(calls).args as [string, Record<string, unknown>, unknown];
    assert.deepEqual(opts, { idempotencyKey: "k-1" });
    assert.equal("idempotencyKey" in input, false);
    await assert.rejects(() => email.run({ args: { ...base, "idempotency-key": "k".repeat(129) } }), exit1);
  });

  it("--attach sube cada archivo ANTES de enviar y pasa las llaves en attachments", async () => {
    const { client, calls } = fakeClient({
      send: { send: () => OK },
      attachments: { upload: (_id: unknown, input: any) => ({ ok: true, key: `k/${input.filename}`, filename: input.filename, size: 3 }) },
    });
    currentClient = client;
    await email.run({ args: { ...base, attach: [archivo("a.pdf", "pdf"), archivo("b.png", "png")] } });
    assert.deepEqual(calls.map((c) => c.method), ["domains.list", "attachments.upload", "attachments.upload", "send.send"]);
    const sub = calls[1].args[1] as any;
    assert.equal(sub.filename, "a.pdf");
    assert.equal(sub.contentType, "application/pdf");
    assert.ok(sub.data instanceof Uint8Array);
    const refs = (enviado(calls).args[1] as any).attachments;
    assert.deepEqual(refs.map((r: any) => r.key), ["k/a.pdf", "k/b.png"]);
    assert.equal(refs[0].filename, "a.pdf");
  });

  it("un adjunto de más de 5 MB o inexistente sale con 1 sin llamar al SDK", async () => {
    const { client, calls } = fakeClient({ send: { send: () => OK }, attachments: { upload: () => ({}) } });
    currentClient = client;
    await assert.rejects(() => email.run({ args: { ...base, attach: archivo("grande.bin", Buffer.alloc(5 * 1024 * 1024 + 1)) } }), exit1);
    await assert.rejects(() => email.run({ args: { ...base, attach: join(dir, "nada.pdf") } }), exit1);
    assert.equal(calls.length, 0);
  });

  it("sin --yes y sin TTY sale con 1 sin llamar al SDK (ni domains.list)", async () => {
    const { client, calls } = fakeClient();
    currentClient = client;
    await sinTty(() => assert.rejects(() => email.run({ args: { ...base, yes: undefined } }), exit1));
    assert.equal(calls.length, 0);
  });

  it("con --attach, sin --yes y sin TTY tampoco sube adjuntos", async () => {
    const { client, calls } = fakeClient();
    currentClient = client;
    await sinTty(() => assert.rejects(() => email.run({ args: { ...base, yes: undefined, attach: archivo("a.pdf", "pdf") } }), exit1));
    assert.equal(calls.length, 0);
  });

  it("--json imprime la respuesta del SDK", async () => {
    const { client } = fakeClient({ send: { send: () => OK } });
    currentClient = client;
    let out = "";
    espiar(process.stdout, (c) => (out += c));
    await email.run({ args: { ...base, json: true } });
    assert.deepEqual(JSON.parse(out), OK);
  });
});

describe("send bulk", () => {
  const valido = { recipients: ["a@x.com", "b@x.com"], subject: "Novedades", html: "<p>hola</p>" };
  const conJson = (obj: unknown) => archivo(`bulk-${Math.random().toString(36).slice(2)}.json`, typeof obj === "string" ? obj : JSON.stringify(obj));

  it("llama bulkSend con el input exacto e imprime el jobId", async () => {
    const { client, calls } = fakeClient({ domains: { list: () => [{ id: "dom_9", domain: "acme.com" }] }, send: { bulkSend: () => ({ ok: true, jobId: "job_1" }) } });
    currentClient = client;
    let out = "";
    espiar(process.stdout, (c) => (out += c));
    await bulk.run({ args: { domain: "acme.com", file: conJson({ ...valido, from: "ventas@acme.com" }), yes: true } });
    const call = calls.find((c) => c.method === "send.bulkSend")!;
    assert.deepEqual(call.args, ["dom_9", { ...valido, from: "ventas" }]);
    assert.match(out, /job_1/);
    assert.match(out, /send status/);
  });

  it("JSON inválido, llave extra, lista vacía o html > 100 KB fallan antes de la red", async () => {
    const { client, calls } = fakeClient({ send: { bulkSend: () => ({ ok: true, jobId: "j" }) } });
    currentClient = client;
    const malos = [
      "{no es json",
      { ...valido, markdown: "# x" },
      { ...valido, attachments: [] },
      { ...valido, recipients: [] },
      { ...valido, recipients: ["no-es-correo"] },
      { ...valido, subject: "" },
      { ...valido, html: "" },
      { ...valido, html: "a".repeat(100 * 1024 + 1) },
      [],
    ];
    for (const m of malos) {
      await assert.rejects(() => bulk.run({ args: { domain: "acme.com", file: conJson(m), yes: true } }), exit1);
    }
    await assert.rejects(() => bulk.run({ args: { domain: "acme.com", file: join(dir, "nada.json"), yes: true } }), exit1);
    assert.equal(calls.length, 0);
  });

  it("from de otro dominio falla sin red", async () => {
    const { client, calls } = fakeClient({ send: { bulkSend: () => ({ ok: true, jobId: "j" }) } });
    currentClient = client;
    await assert.rejects(() => bulk.run({ args: { domain: "acme.com", file: conJson({ ...valido, from: "a@otro.com" }), yes: true } }), exit1);
    assert.equal(calls.length, 0);
  });

  it("sin --yes y sin TTY sale con 1 con calls vacío", async () => {
    const { client, calls } = fakeClient();
    currentClient = client;
    await sinTty(() => assert.rejects(() => bulk.run({ args: { domain: "acme.com", file: conJson(valido) } }), exit1));
    assert.equal(calls.length, 0);
  });
});

describe("send status", () => {
  it("llama bulkStatus(domainId, jobId) y muestra sent/failed/skippedSuppressed de total", async () => {
    const job = { id: "job_1", status: "completed", totalRecipients: 10, sent: 7, failed: 1, skippedSuppressed: 2 };
    const { client, calls } = fakeClient({ domains: { list: () => [{ id: "dom_9", domain: "acme.com" }] }, send: { bulkStatus: () => job } });
    currentClient = client;
    let out = "";
    espiar(process.stdout, (c) => (out += c));
    await status.run({ args: { domain: "acme.com", jobId: "job_1" } });
    assert.deepEqual(calls.find((c) => c.method === "send.bulkStatus")!.args, ["dom_9", "job_1"]);
    assert.match(out, /completed/);
    assert.match(out, /7/);
    assert.match(out, /10/);
  });
});
