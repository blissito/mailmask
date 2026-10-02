// El relay LMTP de la caja de Stalwart (box/outbound-relay/relay.mjs) contra una app de
// mentira: traduce bien cada respuesta y, ante cualquier duda, contesta 451 para que
// Stalwart reintente en vez de perder el correo.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import * as net from "node:net";
import * as http from "node:http";
import { createHmac } from "node:crypto";
// @ts-ignore — módulo JS plano, sin tipos
import { startRelay, translate } from "./box/outbound-relay/relay.mjs";

const SECRET = "secreto-caja";
const plain = (u: string, p: string) => Buffer.from(`\0${u}\0${p}`).toString("base64");

type Reply = { status: number; body?: unknown; hang?: boolean };
let nextReply: Reply = { status: 200 };
const received: { headers: http.IncomingHttpHeaders; body: any; validSig: boolean }[] = [];

function lmtp(port: number) {
  const sock = net.connect(port, "127.0.0.1");
  let buf = "";
  const waiters: { n: number; got: string[]; resolve: (r: string[]) => void }[] = [];
  sock.on("data", (d) => {
    buf += d.toString();
    let i;
    while (waiters.length && (i = buf.search(/^\d{3} .*\r\n/m)) >= 0) {
      const end = buf.indexOf("\r\n", i) + 2;
      const w = waiters[0];
      w.got.push(buf.slice(0, end));
      buf = buf.slice(end);
      if (w.got.length === w.n) { waiters.shift(); w.resolve(w.got); }
    }
  });
  const wait = (n = 1) => new Promise<string[]>((resolve) => waiters.push({ n, got: [], resolve }));
  return {
    greeting: wait(),
    async cmd(line: string, n = 1): Promise<string[]> {
      const p = wait(n);
      sock.write(line + "\r\n");
      return await p;
    },
    close: () => sock.destroy(),
  };
}

const MSG = "From: ana@d.com\r\nTo: a@gmail.com\r\nSubject: x\r\nMessage-ID: <b1@apple>\r\n\r\nhola";

async function deliver(port: number, rcpts: string[], auth = true): Promise<string[]> {
  const c = lmtp(port);
  await c.greeting;
  await c.cmd("LHLO stalwart");
  if (auth) assert.match((await c.cmd(`AUTH PLAIN ${plain("stalwart", SECRET)}`))[0], /^235/);
  await c.cmd("MAIL FROM:<ana@d.com>");
  for (const r of rcpts) assert.match((await c.cmd(`RCPT TO:<${r}>`))[0], /^250/);
  assert.match((await c.cmd("DATA"))[0], /^354/);
  const out = await c.cmd(MSG + "\r\n.", rcpts.length);
  c.close();
  return out;
}

describe("Relay de la caja: traducción de respuestas", () => {
  // deno-lint-ignore no-explicit-any
  let app: http.Server; let relay: any; let relayDown: any;
  const appPort = 30000 + Math.floor(Math.random() * 10000);
  const relayPort = appPort + 1;
  const relayDownPort = appPort + 2;

  before(async () => {
    app = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const ts = String(req.headers["x-mailmask-timestamp"]);
        const expected = "sha256=" + createHmac("sha256", SECRET).update(`${ts}.${body}`).digest("hex");
        received.push({ headers: req.headers, body: JSON.parse(body), validSig: expected === req.headers["x-mailmask-signature"] });
        if (nextReply.hang) return; // nunca contesta
        res.writeHead(nextReply.status, { "content-type": "application/json" });
        res.end(JSON.stringify(nextReply.body ?? {}));
      });
    });
    await new Promise<void>((r) => app.listen(appPort, "127.0.0.1", r));
    relay = startRelay({ port: relayPort, host: "127.0.0.1", secret: SECRET, appUrl: `http://127.0.0.1:${appPort}/api/internal/outbound`, timeoutMs: 400 });
    // Una app que no existe: puerto cerrado.
    relayDown = startRelay({ port: relayDownPort, host: "127.0.0.1", secret: SECRET, appUrl: "http://127.0.0.1:1/x", timeoutMs: 400 });
    await new Promise((r) => setTimeout(r, 50));
  });
  after(async () => {
    app.closeAllConnections?.();
    await new Promise((r) => app.close(r));
    await new Promise((r) => relay.close(r));
    await new Promise((r) => relayDown.close(r));
  });

  it("sin AUTH no acepta remitente y con la clave mala da 535", async () => {
    const c = lmtp(relayPort);
    await c.greeting;
    await c.cmd("LHLO stalwart");
    assert.match((await c.cmd("MAIL FROM:<ana@d.com>"))[0], /^530/);
    assert.match((await c.cmd(`AUTH PLAIN ${plain("stalwart", "mala")}`))[0], /^535/);
    c.close();
  });

  it("200 → 250 por destinatario; firma HMAC válida y el MIME en base64", async () => {
    nextReply = { status: 200, body: { perRcpt: { "a@gmail.com": "ok", "b@gmail.com": "ok" }, sesMessageId: "ses-1" } };
    const out = await deliver(relayPort, ["a@gmail.com", "b@gmail.com"]);
    assert.equal(out.length, 2);
    for (const l of out) assert.match(l, /^250 /);
    const last = received.at(-1)!;
    assert.equal(last.validSig, true);
    assert.deepEqual(last.body.rcptTo, ["a@gmail.com", "b@gmail.com"]);
    assert.equal(last.body.mailFrom, "ana@d.com");
    assert.match(Buffer.from(last.body.raw, "base64").toString(), /Message-ID: <b1@apple>/);
  });

  it("200 mixto → 250 para uno y 550 para el suprimido", async () => {
    nextReply = { status: 200, body: { perRcpt: { "a@gmail.com": "ok", "rebota@gmail.com": "rejected:550 5.1.1 suprimido" } } };
    const out = await deliver(relayPort, ["a@gmail.com", "rebota@gmail.com"]);
    assert.match(out[0], /^250 /);
    assert.match(out[1], /^550 5\.1\.1 suprimido/);
  });

  it("422 de política → el 5xx que manda la app (Stalwart genera el DSN)", async () => {
    nextReply = { status: 422, body: { error: "5.7.0 Límite diario", code: 550 } };
    const out = await deliver(relayPort, ["a@gmail.com"]);
    assert.match(out[0], /^550 5\.7\.0 Límite diario/);
  });

  it("5xx de la app → 451", async () => {
    nextReply = { status: 503, body: { error: "SES caído", code: 451 } };
    assert.match((await deliver(relayPort, ["a@gmail.com"]))[0], /^451 /);
    nextReply = { status: 500 };
    assert.match((await deliver(relayPort, ["a@gmail.com"]))[0], /^451 /);
  });

  it("firma rechazada (401) → 451, no rebote: es un error de configuración", async () => {
    nextReply = { status: 401, body: { error: "Firma inválida" } };
    assert.match((await deliver(relayPort, ["a@gmail.com"]))[0], /^451 /);
  });

  it("la app no contesta (timeout) → 451", async () => {
    nextReply = { status: 200, hang: true };
    assert.match((await deliver(relayPort, ["a@gmail.com"]))[0], /^451 /);
    nextReply = { status: 200 };
  });

  it("la app no existe (conexión rechazada) → 451", async () => {
    assert.match((await deliver(relayDownPort, ["a@gmail.com"]))[0], /^451 /);
  });

  it("translate: un destinatario del que la app no dijo nada se reintenta", () => {
    const out = translate(200, { perRcpt: {} }, ["x@y.com"]);
    assert.equal(out[0].responseCode, 451);
    assert.equal(translate(422, { code: "abc" }, ["x@y.com"]).responseCode, 451);
  });
});
