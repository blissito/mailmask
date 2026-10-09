import assert from "node:assert/strict";
import { afterEach, describe, it, mock } from "node:test";
import { fakeClient, trapExit, ExitSignal } from "./test-helpers.js";

let currentClient: ReturnType<typeof fakeClient>["client"];

trapExit();
mock.module("../src/client.js", {
  namedExports: {
    requireClient: async () => ({ client: currentClient, auth: { apiKey: "mk_test", baseUrl: undefined, source: "env" as const } }),
    buildClient: () => currentClient,
  },
});

const logs = (await import("../src/commands/logs.js")).default as any;

const entradas = [
  { id: "1", domainId: "d", timestamp: "2026-10-08T10:00:00Z", from: "hola@acme.com", to: "x@y.com", subject: "Saliente", status: "delivered", forwardedTo: "", sizeBytes: 10 },
  { id: "2", domainId: "d", timestamp: "2026-10-08T09:00:00Z", from: "z@w.com", to: "hola@acme.com", subject: "Entrante", status: "forwarded", forwardedTo: "me@x.com", sizeBytes: 10 },
];

// Sólo se restauran los espías de stdout/stderr; el de process.exit y el de requireClient quedan para todo el archivo.
const restores: Array<() => void> = [];
function espiar(stream: NodeJS.WriteStream, onWrite: (chunk: string) => void): void {
  const spy = mock.method(stream, "write", ((chunk: unknown) => (onWrite(String(chunk)), true)) as never);
  restores.push(() => spy.mock.restore());
}
afterEach(() => {
  while (restores.length) restores.pop()!();
});

function salida() {
  let out = "";
  espiar(process.stdout, (c) => (out += c));
  return () => out;
}

describe("logs", () => {
  it("llama logs.list con el id resuelto y --limit", async () => {
    const { client, calls } = fakeClient({ domains: { list: () => [{ id: "dom_9", domain: "acme.com" }] }, logs: { list: () => entradas } });
    currentClient = client;
    const out = salida();
    await logs.run({ args: { domain: "acme.com", limit: "20" } });
    assert.deepEqual(calls.find((c) => c.method === "logs.list")!.args, ["dom_9", { limit: 20 }]);
    assert.match(out(), /Saliente/);
    assert.match(out(), /Entrante/);
    assert.match(out(), /delivered/);
  });

  it("sin --limit pide 50 (el default del SDK)", async () => {
    const { client, calls } = fakeClient({ logs: { list: () => [] } });
    currentClient = client;
    const out = salida();
    await logs.run({ args: { domain: "dom_1" } });
    assert.deepEqual(calls.find((c) => c.method === "logs.list")!.args, ["dom_1", { limit: 50 }]);
    assert.match(out(), /Sin correos/);
  });

  it("--json imprime las entradas tal cual", async () => {
    const { client } = fakeClient({ logs: { list: () => entradas } });
    currentClient = client;
    const out = salida();
    await logs.run({ args: { domain: "dom_1", json: true } });
    assert.deepEqual(JSON.parse(out()), entradas);
  });

  it("--limit 0, 101, 1.5 o abc sale con 1 sin llamar al SDK", async () => {
    const { client, calls } = fakeClient({ logs: { list: () => [] } });
    currentClient = client;
    for (const limit of ["0", "101", "1.5", "abc", "-3"]) {
      await assert.rejects(() => logs.run({ args: { domain: "dom_1", limit } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
    }
    assert.equal(calls.length, 0);
  });
});
