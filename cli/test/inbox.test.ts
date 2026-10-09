import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, mock } from "node:test";
import { MailMaskError } from "@easybits.cloud/mailmask";
import { captureWrites, fakeClient, trapExit, ExitSignal } from "./test-helpers.js";

let currentClient: ReturnType<typeof fakeClient>["client"];

trapExit();
mock.module("../src/client.js", {
  namedExports: {
    requireClient: async () => ({ client: currentClient, auth: { apiKey: "mk_test", baseUrl: undefined, source: "env" as const } }),
    buildClient: () => currentClient,
  },
});

const { default: inbox, textoDeMensaje } = await import("../src/commands/inbox.js");
const cmd = inbox.subCommands as Record<string, any>;

const conv = { id: "c1", domainId: "dom_1", from: "ana@x.com", to: "ventas@acme.com", subject: "Hola", status: "open", priority: "normal", lastMessageAt: "2026-10-08T10:00:00Z", messageCount: 1, tags: [] };
const detail = (messages: unknown[]) => ({ ...conv, messages, notes: [], totalMessages: messages.length, hasMore: false });

function llamada(calls: { method: string; args: unknown[] }[], method: string) {
  const c = calls.find((x) => x.method === method);
  assert.ok(c, `no se llamó ${method}`);
  return c.args;
}

/** Corre `fn` con stdin sin TTY (como en CI o un agente). */
async function sinTty<T>(fn: () => Promise<T>): Promise<T> {
  const tty = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
  Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
  try {
    return await fn();
  } finally {
    if (tty) Object.defineProperty(process.stdin, "isTTY", tty); else delete (process.stdin as any).isTTY;
  }
}

const sale = (code: number) => (e: unknown) => e instanceof ExitSignal && e.code === code;

describe("inbox list", () => {
  it("llama inbox.list con el id resuelto y --alias como opts.to", async () => {
    const { client, calls } = fakeClient({ domains: { list: () => [{ id: "dom_9", domain: "acme.com" }] }, inbox: { list: () => ({ items: [conv], nextCursor: null, mode: "list" }) } });
    currentClient = client;
    await cmd.list.run({ args: { domain: "acme.com", status: "unread", alias: "ventas@acme.com", assigned: "bo@acme.com", q: "factura", limit: "20", cursor: "abc" } });
    assert.deepEqual(llamada(calls, "inbox.list"), ["dom_9", { status: "unread", to: "ventas@acme.com", assignedTo: "bo@acme.com", q: "factura", limit: 20, cursor: "abc" }]);
  });

  it("imprime una fila por conversación", async () => {
    const otra = { ...conv, id: "c2", unread: true };
    const { client } = fakeClient({ inbox: { list: () => ({ items: [conv, otra], nextCursor: null, mode: "list" }) } });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await cmd.list.run({ args: { domain: "dom_1" } });
    } finally {
      out.restore();
    }
    const filas = out.text().trim().split("\n");
    assert.equal(filas.length, 2);
    assert.match(filas[0], /c1.*open.*ventas@acme\.com.*ana@x\.com.*Hola/);
    assert.match(filas[1], /^\* c2/);
  });

  it("--status inválido sale con 1 antes de tocar la API", async () => {
    const { client, calls } = fakeClient();
    currentClient = client;
    await assert.rejects(() => cmd.list.run({ args: { domain: "dom_1", status: "archivado" } }), sale(1));
    assert.equal(calls.length, 0);
  });
});

describe("inbox get", () => {
  it("llama inbox.get con --before", async () => {
    const { client, calls } = fakeClient({ inbox: { get: () => detail([]) } });
    currentClient = client;
    await cmd.get.run({ args: { domain: "dom_1", conversation: "c1", before: "m9" } });
    assert.deepEqual(llamada(calls, "inbox.get"), ["dom_1", "c1", { before: "m9" }]);
  });

  it("un mensaje que sólo trae HTML se imprime como texto, sin una sola etiqueta", async () => {
    const html = '<html><head><style>p{color:red}</style></head><body><p>Hola <b>Ana</b>,</p><div>Quiero&nbsp;una cotizaci&oacute;n &amp; fecha</div><a href="http://x.com">link</a><br/>Gracias</body></html>';
    const { client } = fakeClient({ inbox: { get: () => detail([{ id: "m1", conversationId: "c1", from: "ana@x.com", direction: "inbound", createdAt: "t", html }]) } });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await cmd.get.run({ args: { domain: "dom_1", conversation: "c1" } });
    } finally {
      out.restore();
    }
    assert.doesNotMatch(out.text(), /<|>/);
    assert.match(out.text(), /Hola Ana,/);
    assert.match(out.text(), /Quiero una cotizaci&oacute;n & fecha|Quiero una cotización|Quiero una cotizaci/);
    assert.doesNotMatch(out.text(), /color:red/);
  });

  it("--json agrega `text` a cada mensaje", async () => {
    const { client } = fakeClient({ inbox: { get: () => detail([{ id: "m1", conversationId: "c1", from: "a", direction: "inbound", createdAt: "t", html: "<p>Hola</p>" }]) } });
    currentClient = client;
    const out = captureWrites(process.stdout);
    try {
      await cmd.get.run({ args: { domain: "dom_1", conversation: "c1", json: true } });
    } finally {
      out.restore();
    }
    assert.equal(JSON.parse(out.text()).messages[0].text, "Hola");
  });

  it("textoDeMensaje prefiere body, luego bodyDegraded, luego html", () => {
    assert.equal(textoDeMensaje({ body: "b", bodyDegraded: "d", html: "<p>h</p>" }), "b");
    assert.equal(textoDeMensaje({ bodyDegraded: "d", html: "<p>h</p>" }), "d");
    assert.equal(textoDeMensaje({ html: "<p>h</p>" }), "h");
    assert.equal(textoDeMensaje({}), "");
  });
});

describe("inbox reply y compose", () => {
  it("reply --yes llama inbox.reply con markdown, cc, bcc y quote:false", async () => {
    const { client, calls } = fakeClient({ inbox: { reply: () => ({ ok: true, messageId: "m2" }) } });
    currentClient = client;
    await cmd.reply.run({ args: { domain: "dom_1", conversation: "c1", markdown: "Va", cc: "a@x.com, b@x.com", bcc: "c@x.com", quote: false, yes: true } });
    assert.deepEqual(llamada(calls, "inbox.reply"), ["dom_1", "c1", { markdown: "Va", cc: ["a@x.com", "b@x.com"], bcc: ["c@x.com"], quote: false }]);
  });

  it("reply sin TTY ni --yes sale con 1 sin tocar la API (ni domains.list)", async () => {
    const { client, calls } = fakeClient({ inbox: { reply: () => ({ ok: true, messageId: "m2" }) } });
    currentClient = client;
    await sinTty(() => assert.rejects(() => cmd.reply.run({ args: { domain: "acme.com", conversation: "c1", markdown: "Va" } }), sale(1)));
    assert.equal(calls.length, 0);
  });

  it("compose --yes llama inbox.compose con --from como fromAlias", async () => {
    const { client, calls } = fakeClient({ inbox: { compose: () => ({ ok: true, conversationId: "c9", messageId: "m1" }) } });
    currentClient = client;
    await cmd.compose.run({ args: { domain: "dom_1", from: "ventas", to: "ana@x.com", subject: "Hola", markdown: "Texto", cc: "a@x.com", yes: true } });
    assert.deepEqual(llamada(calls, "inbox.compose"), ["dom_1", { fromAlias: "ventas", to: "ana@x.com", subject: "Hola", markdown: "Texto", cc: ["a@x.com"] }]);
  });

  it("compose sin TTY ni --yes sale con 1 sin tocar la API", async () => {
    const { client, calls } = fakeClient();
    currentClient = client;
    await sinTty(() => assert.rejects(() => cmd.compose.run({ args: { domain: "acme.com", from: "ventas", to: "a@x.com", subject: "s", markdown: "m" } }), sale(1)));
    assert.equal(calls.length, 0);
  });
});

describe("inbox update, read, assign, note", () => {
  it("update llama inbox.update con --snooze-until y --tags", async () => {
    const { client, calls } = fakeClient({ inbox: { update: () => conv } });
    currentClient = client;
    await cmd.update.run({ args: { domain: "dom_1", conversation: "c1", status: "snoozed", "snooze-until": "2026-10-20T09:00:00Z", tags: "vip,pago", priority: "urgent" } });
    assert.deepEqual(llamada(calls, "inbox.update"), ["dom_1", "c1", { status: "snoozed", snoozedUntil: "2026-10-20T09:00:00Z", tags: ["vip", "pago"], priority: "urgent" }]);
  });

  it("update --status snoozed sin --snooze-until sale con 1 sin tocar la API", async () => {
    const { client, calls } = fakeClient();
    currentClient = client;
    await assert.rejects(() => cmd.update.run({ args: { domain: "dom_1", conversation: "c1", status: "snoozed" } }), sale(1));
    assert.equal(calls.length, 0);
  });

  it("update sin ningún cambio o con --status inválido sale con 1", async () => {
    const { client, calls } = fakeClient();
    currentClient = client;
    await assert.rejects(() => cmd.update.run({ args: { domain: "dom_1", conversation: "c1" } }), sale(1));
    await assert.rejects(() => cmd.update.run({ args: { domain: "dom_1", conversation: "c1", status: "unread" } }), sale(1));
    assert.equal(calls.length, 0);
  });

  it("read llama inbox.markRead", async () => {
    const { client, calls } = fakeClient({ inbox: { markRead: () => ({ ok: true, unreadCount: 2 }) } });
    currentClient = client;
    await cmd.read.run({ args: { domain: "dom_1", conversation: "c1" } });
    assert.deepEqual(llamada(calls, "inbox.markRead"), ["dom_1", "c1"]);
  });

  it("assign con usuario llama inbox.assign; sin usuario desasigna", async () => {
    const { client, calls } = fakeClient({ inbox: { assign: () => conv } });
    currentClient = client;
    await cmd.assign.run({ args: { domain: "dom_1", conversation: "c1", user: "bo@acme.com" } });
    await cmd.assign.run({ args: { domain: "dom_1", conversation: "c1" } });
    const asignaciones = calls.filter((c) => c.method === "inbox.assign").map((c) => c.args);
    assert.deepEqual(asignaciones, [["dom_1", "c1", "bo@acme.com"], ["dom_1", "c1", undefined]]);
  });

  it("note llama inbox.addNote con el texto", async () => {
    const { client, calls } = fakeClient({ inbox: { addNote: () => ({ id: "n1" }) } });
    currentClient = client;
    await cmd.note.run({ args: { domain: "dom_1", conversation: "c1", text: "Llamar mañana" } });
    assert.deepEqual(llamada(calls, "inbox.addNote"), ["dom_1", "c1", "Llamar mañana"]);
  });
});

describe("inbox delete, restore, metrics", () => {
  it("delete toma los ids de args._ (con --json de por medio) y llama inbox.delete", async () => {
    const { client, calls } = fakeClient({ inbox: { delete: () => ({ ok: true, deleted: 3 }) } });
    currentClient = client;
    await cmd.delete.run({ args: { _: ["dom_1", "c1", "c2", "c3"], domain: "dom_1", id: "c1", json: true, yes: true } });
    assert.deepEqual(llamada(calls, "inbox.delete"), ["dom_1", ["c1", "c2", "c3"]]);
  });

  it("delete con 0 ids o con 201 sale con 1 sin tocar la API ni pedir llave", async () => {
    const { client, calls } = fakeClient();
    currentClient = client;
    await assert.rejects(() => cmd.delete.run({ args: { _: ["dom_1"], domain: "dom_1", yes: true } }), sale(1));
    const muchos = Array.from({ length: 201 }, (_, i) => `c${i}`);
    await assert.rejects(() => cmd.delete.run({ args: { _: ["dom_1", ...muchos], domain: "dom_1", yes: true } }), sale(1));
    assert.equal(calls.length, 0);
  });

  it("delete acepta justo 200 ids", async () => {
    const { client, calls } = fakeClient({ inbox: { delete: () => ({ ok: true, deleted: 200 }) } });
    currentClient = client;
    const ids = Array.from({ length: 200 }, (_, i) => `c${i}`);
    await cmd.delete.run({ args: { _: ["dom_1", ...ids], domain: "dom_1", yes: true } });
    assert.equal((llamada(calls, "inbox.delete")[1] as string[]).length, 200);
  });

  it("delete sin TTY ni --yes sale con 1 sin tocar la API", async () => {
    const { client, calls } = fakeClient();
    currentClient = client;
    await sinTty(() => assert.rejects(() => cmd.delete.run({ args: { _: ["acme.com", "c1"], domain: "acme.com" } }), sale(1)));
    assert.equal(calls.length, 0);
  });

  it("restore llama inbox.restore sin confirmación", async () => {
    const { client, calls } = fakeClient({ inbox: { restore: () => ({ ok: true }) } });
    currentClient = client;
    await sinTty(() => cmd.restore.run({ args: { domain: "dom_1", conversation: "c1" } }));
    assert.deepEqual(llamada(calls, "inbox.restore"), ["dom_1", "c1"]);
  });

  it("metrics llama inbox.metrics con --days", async () => {
    const { client, calls } = fakeClient({ inbox: { metrics: () => ({ total: 4 }) } });
    currentClient = client;
    await cmd.metrics.run({ args: { domain: "dom_1", days: "30" } });
    assert.deepEqual(llamada(calls, "inbox.metrics"), ["dom_1", { days: 30 }]);
  });
});

describe("inbox attachment", () => {
  const respuesta = (bytes: Uint8Array) => ({ ok: true, status: 200, statusText: "OK", arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) });

  it("con -o escribe los mismos bytes y llama inbox.attachment con el índice numérico", async () => {
    const bytes = Uint8Array.from([0, 255, 10, 13, 128, 7]);
    const { client, calls } = fakeClient({ inbox: { attachment: () => respuesta(bytes) } });
    currentClient = client;
    const ruta = join(mkdtempSync(join(tmpdir(), "mm-att-")), "a.bin");
    await cmd.attachment.run({ args: { domain: "dom_1", conversation: "c1", message: "m1", index: "0", output: ruta } });
    assert.deepEqual(llamada(calls, "inbox.attachment"), ["dom_1", "c1", "m1", 0]);
    assert.deepEqual([...readFileSync(ruta)], [...bytes]);
  });

  it("sin -o escribe los bytes a stdout", async () => {
    const bytes = Uint8Array.from([1, 2, 3]);
    const { client } = fakeClient({ inbox: { attachment: () => respuesta(bytes) } });
    currentClient = client;
    const escrito: Buffer[] = [];
    const write = mock.method(process.stdout, "write", ((chunk: unknown) => { if (Buffer.isBuffer(chunk)) escrito.push(chunk); return true; }) as never);
    try {
      await cmd.attachment.run({ args: { domain: "dom_1", conversation: "c1", message: "m1", index: "2" } });
    } finally {
      write.mock.restore();
    }
    assert.deepEqual([...Buffer.concat(escrito)], [1, 2, 3]);
  });

  it("un 404 sale con 4 y no deja ningún archivo creado", async () => {
    const { client } = fakeClient({ inbox: { attachment: () => { throw new MailMaskError(404, "no existe"); } } });
    currentClient = client;
    const ruta = join(mkdtempSync(join(tmpdir(), "mm-att-")), "a.bin");
    await assert.rejects(() => cmd.attachment.run({ args: { domain: "dom_1", conversation: "c1", message: "m1", index: "0", output: ruta } }), sale(4));
    assert.equal(existsSync(ruta), false);
  });

  it("una respuesta no ok que no lanzó también sale con 4 sin crear el archivo", async () => {
    const { client } = fakeClient({ inbox: { attachment: () => ({ ok: false, status: 404, statusText: "Not Found", arrayBuffer: async () => new ArrayBuffer(0) }) } });
    currentClient = client;
    const ruta = join(mkdtempSync(join(tmpdir(), "mm-att-")), "a.bin");
    await assert.rejects(() => cmd.attachment.run({ args: { domain: "dom_1", conversation: "c1", message: "m1", index: "0", output: ruta } }), sale(4));
    assert.equal(existsSync(ruta), false);
  });

  it("un <index> que no es entero ≥ 0 sale con 1 sin tocar la API", async () => {
    const { client, calls } = fakeClient();
    currentClient = client;
    for (const index of ["-1", "1.5", "x"]) {
      await assert.rejects(() => cmd.attachment.run({ args: { domain: "dom_1", conversation: "c1", message: "m1", index } }), sale(1));
    }
    assert.equal(calls.length, 0);
  });
});
