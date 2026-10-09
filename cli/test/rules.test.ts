import assert from "node:assert/strict";
import { describe, it, mock } from "node:test";
import { MailMaskError } from "@easybits.cloud/mailmask";
import { fakeClient, trapExit, ExitSignal } from "./test-helpers.js";

let currentClient: ReturnType<typeof fakeClient>["client"];
let requireClientCalls = 0;

trapExit();
mock.module("../src/client.js", {
  namedExports: {
    requireClient: async () => {
      requireClientCalls++;
      return { client: currentClient, auth: { apiKey: "mk_test", baseUrl: undefined, source: "env" as const } };
    },
    buildClient: () => currentClient,
  },
});

const { default: rules } = await import("../src/commands/rules.js");
const { list, create, update, delete: del } = rules.subCommands as Record<string, any>;

const rule = { id: "r1", domainId: "dom_1", field: "subject", match: "contains", value: "factura", action: "forward", target: "yo@acme.com", priority: 1, enabled: true, createdAt: "2026-01-01" };

async function usageError(cmd: any, args: Record<string, unknown>) {
  const { client, calls } = fakeClient({});
  currentClient = client;
  requireClientCalls = 0;
  await assert.rejects(() => cmd.run({ args }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
  assert.equal(calls.length, 0, "no debe llamar al SDK");
  assert.equal(requireClientCalls, 0, "no debe pedir cliente");
}

describe("rules create/update: flags → SDK", () => {
  it("create arma CreateRuleInput y --disabled manda enabled:false", async () => {
    const { client, calls } = fakeClient({ rules: { create: () => rule } });
    currentClient = client;
    await create.run({ args: { domain: "dom_1", field: "subject", match: "contains", value: "factura", action: "forward", target: "yo@acme.com", priority: "3", disabled: true } });
    assert.deepEqual(calls.find((c) => c.method === "rules.create")!.args, [
      "dom_1",
      { field: "subject", match: "contains", value: "factura", action: "forward", target: "yo@acme.com", priority: 3, enabled: false },
    ]);
  });

  it("create con discard no necesita --target y no manda enabled", async () => {
    const { client, calls } = fakeClient({ rules: { create: () => rule } });
    currentClient = client;
    await create.run({ args: { domain: "dom_1", field: "from", match: "equals", value: "spam@x.com", action: "discard" } });
    assert.deepEqual(calls.find((c) => c.method === "rules.create")!.args[1], { field: "from", match: "equals", value: "spam@x.com", action: "discard" });
  });

  it("update manda sólo lo que vino, y --enable/--disable mapean enabled", async () => {
    const { client, calls } = fakeClient({ rules: { update: () => rule } });
    currentClient = client;
    await update.run({ args: { domain: "dom_1", ruleId: "r1", value: "pago", disable: true } });
    assert.deepEqual(calls.find((c) => c.method === "rules.update")!.args, ["dom_1", "r1", { value: "pago", enabled: false }]);
  });

  it("resuelve el dominio por nombre", async () => {
    const { client, calls } = fakeClient({ domains: { list: () => [{ id: "dom_9", domain: "acme.com" }] }, rules: { list: () => [rule] } });
    currentClient = client;
    await list.run({ args: { domain: "acme.com" } });
    assert.deepEqual(calls.find((c) => c.method === "rules.list")!.args, ["dom_9"]);
  });
});

describe("rules: errores de uso salen con 1 sin llamar al SDK", () => {
  const base = { domain: "dom_1", field: "subject", match: "contains", value: "x", action: "discard" };
  it("create: field inválido", () => usageError(create, { ...base, field: "cc" }));
  it("create: match inválido", () => usageError(create, { ...base, match: "like" }));
  it("create: action inválida", () => usageError(create, { ...base, action: "borrar" }));
  it("create: priority no entera", () => usageError(create, { ...base, priority: "alta" }));
  it("create: forward sin target", () => usageError(create, { ...base, action: "forward" }));
  it("create: webhook sin target", () => usageError(create, { ...base, action: "webhook" }));
  it("create: faltan flags obligatorios", () => usageError(create, { domain: "dom_1", field: "to" }));
  it("update: sin ningún flag", () => usageError(update, { domain: "dom_1", ruleId: "r1" }));
  it("update: --enable y --disable juntos", () => usageError(update, { domain: "dom_1", ruleId: "r1", enable: true, disable: true }));
  it("update: cambiar a forward sin target", () => usageError(update, { domain: "dom_1", ruleId: "r1", action: "forward" }));
  it("update: priority inválida", () => usageError(update, { domain: "dom_1", ruleId: "r1", priority: "1.5" }));
});

describe("rules: regex peligrosa y borrado", () => {
  it("el 400 del servidor se imprime tal cual y sale con 1", async () => {
    const msg = "Regex peligrosa: backtracking exponencial";
    const { client } = fakeClient({ rules: { create: () => { throw new MailMaskError(400, msg); } } });
    currentClient = client;
    const errs: string[] = [];
    const original = process.stderr.write.bind(process.stderr) as (...a: unknown[]) => boolean;
    mock.method(process.stderr, "write", ((s: unknown, ...rest: unknown[]) => {
      if (typeof s !== "string") return original(s, ...rest);
      errs.push(s);
      return true;
    }) as never);
    await assert.rejects(
      () => create.run({ args: { domain: "dom_1", field: "subject", match: "regex", value: "(a+)+$", action: "discard", json: true } }),
      (e: unknown) => e instanceof ExitSignal && e.code === 1,
    );
    mock.restoreAll();
    trapExit();
    assert.deepEqual(JSON.parse(errs.join("")), { error: msg, status: 400 });
  });

  it("delete sin TTY ni --yes sale con 1 sin llamar a la API (ni domains.list)", async () => {
    const { client, calls } = fakeClient({ rules: { delete: () => ({ ok: true }) } });
    currentClient = client;
    const tty = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
    try {
      await assert.rejects(() => del.run({ args: { domain: "acme.com", ruleId: "r1" } }), (e: unknown) => e instanceof ExitSignal && e.code === 1);
    } finally {
      if (tty) Object.defineProperty(process.stdin, "isTTY", tty); else delete (process.stdin as any).isTTY;
    }
    assert.equal(calls.length, 0);
  });

  it("delete --yes llama rules.delete", async () => {
    const { client, calls } = fakeClient({ rules: { delete: () => ({ ok: true }) } });
    currentClient = client;
    await del.run({ args: { domain: "dom_1", ruleId: "r1", yes: true } });
    assert.deepEqual(calls.find((c) => c.method === "rules.delete")!.args, ["dom_1", "r1"]);
  });
});
