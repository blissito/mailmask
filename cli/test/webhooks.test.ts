import assert from "node:assert/strict";
import { describe, it, mock } from "node:test";
import { MailMaskError } from "@easybits.cloud/mailmask";
import { fakeClient, trapExit, ExitSignal } from "./test-helpers.js";

let currentClient: ReturnType<typeof fakeClient>["client"];

trapExit();
// El mock tiene que estar en pie ANTES del import dinámico (ver dns.test.ts).
mock.module("../src/client.js", {
  namedExports: {
    requireClient: async () => ({
      client: currentClient,
      auth: { apiKey: "mk_test", baseUrl: undefined, source: "env" as const },
    }),
    buildClient: () => currentClient,
  },
});

const { default: webhooks } = await import("../src/commands/webhooks.js");
const { list, create, update, delete: del, test, deliveries } = webhooks.subCommands as Record<string, any>;

const SECRET = "secreto-de-prueba";
const hook = { id: "wh_1", domainId: "dom_1", url: "https://acme.com/hook", events: ["email.received"], enabled: true, createdAt: "now" };

function captureStdout(): { text: () => string; restore: () => void } {
  let text = "";
  const fn = mock.method(process.stdout, "write", (chunk: string) => {
    text += chunk;
    return true;
  });
  return { text: () => text, restore: () => fn.mock.restore() };
}

describe("webhooks create", () => {
  it("llama webhooks.create con url y eventos, e imprime el secreto completo una vez", async () => {
    const { client, calls } = fakeClient({ webhooks: { create: () => ({ ...hook, secret: SECRET }) } });
    currentClient = client;
    const out = captureStdout();
    try {
      await create.run({ args: { domain: "dom_1", url: hook.url, events: "email.received,email.bounced" } });
    } finally {
      out.restore();
    }
    const call = calls.find((c) => c.method === "webhooks.create");
    assert.deepEqual(call!.args, ["dom_1", { url: hook.url, events: ["email.received", "email.bounced"] }]);
    assert.ok(out.text().includes(SECRET), "create debe mostrar el secreto completo");
    assert.match(out.text(), /no se vuelve a mostrar/i);
  });

  it("--json devuelve el objeto con el secreto", async () => {
    const { client } = fakeClient({ webhooks: { create: () => ({ ...hook, secret: SECRET }) } });
    currentClient = client;
    const out = captureStdout();
    try {
      await create.run({ args: { domain: "dom_1", url: hook.url, events: "email.received", json: true } });
    } finally {
      out.restore();
    }
    assert.equal(JSON.parse(out.text()).secret, SECRET);
  });

  it("un evento inválido sale con 1 sin llamar al SDK", async () => {
    const { client, calls } = fakeClient({ webhooks: { create: () => ({ ...hook, secret: SECRET }) } });
    currentClient = client;
    await assert.rejects(
      () => create.run({ args: { domain: "dom_1", url: hook.url, events: "email.received,email.explota" } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 1,
    );
    assert.equal(calls.length, 0);
  });

  it("sin --events sale con 1 sin llamar al SDK", async () => {
    const { client, calls } = fakeClient({});
    currentClient = client;
    await assert.rejects(
      () => create.run({ args: { domain: "dom_1", url: hook.url } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 1,
    );
    assert.equal(calls.length, 0);
  });

  it("409 → exit 3", async () => {
    const { client } = fakeClient({ webhooks: { create: () => { throw new MailMaskError(409, "tope alcanzado"); } } });
    currentClient = client;
    await assert.rejects(
      () => create.run({ args: { domain: "dom_1", url: hook.url, events: "email.received" } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 3,
    );
  });

  it("resuelve el dominio por nombre", async () => {
    const { client, calls } = fakeClient({
      domains: { list: () => [{ id: "dom_9", domain: "acme.com" }] },
      webhooks: { create: () => ({ ...hook, secret: SECRET }) },
    });
    currentClient = client;
    const out = captureStdout();
    try {
      await create.run({ args: { domain: "acme.com", url: hook.url, events: "email.received" } });
    } finally {
      out.restore();
    }
    assert.equal(calls.find((c) => c.method === "webhooks.create")!.args[0], "dom_9");
  });
});

describe("webhooks: ningún otro comando imprime un secreto", () => {
  // Defensa en profundidad: aunque la API devolviera `secret` en otra ruta, no sale.
  const leaky = { ...hook, secret: SECRET };

  it("list (texto y --json)", async () => {
    const { client } = fakeClient({ webhooks: { list: () => [leaky] } });
    currentClient = client;
    for (const json of [false, true]) {
      const out = captureStdout();
      try {
        await list.run({ args: { domain: "dom_1", json } });
      } finally {
        out.restore();
      }
      assert.doesNotMatch(out.text(), /secreto-de-prueba/);
      assert.match(out.text(), /wh_1/);
    }
  });

  it("update (texto y --json)", async () => {
    const { client, calls } = fakeClient({ webhooks: { update: () => leaky } });
    currentClient = client;
    for (const json of [false, true]) {
      const out = captureStdout();
      try {
        await update.run({ args: { domain: "dom_1", id: "wh_1", disable: true, events: "email.sent", json } });
      } finally {
        out.restore();
      }
      assert.doesNotMatch(out.text(), /secreto-de-prueba/);
    }
    assert.deepEqual(calls.find((c) => c.method === "webhooks.update")!.args, ["dom_1", "wh_1", { enabled: false, events: ["email.sent"] }]);
  });

  it("test y deliveries", async () => {
    const { client } = fakeClient({
      webhooks: {
        test: () => ({ ok: true, deliveryId: "dl_1", secret: SECRET }),
        deliveries: () => [{ id: "dl_1", webhookId: "wh_1", event: "ping", attempts: 1, status: "delivered", nextAt: "now", lastError: null, lastStatusCode: 200, createdAt: "now", secret: SECRET }],
      },
    });
    currentClient = client;
    for (const cmd of [test, deliveries]) {
      for (const json of [false, true]) {
        const out = captureStdout();
        try {
          await cmd.run({ args: { domain: "dom_1", id: "wh_1", json } });
        } finally {
          out.restore();
        }
        assert.doesNotMatch(out.text(), /secreto-de-prueba/);
        assert.match(out.text(), /dl_1/);
      }
    }
  });
});

describe("webhooks update: validación", () => {
  it("evento inválido → 1 y cero llamadas", async () => {
    const { client, calls } = fakeClient({});
    currentClient = client;
    await assert.rejects(
      () => update.run({ args: { domain: "dom_1", id: "wh_1", events: "nope" } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 1,
    );
    assert.equal(calls.length, 0);
  });

  it("--enable y --disable juntos → 1", async () => {
    const { client, calls } = fakeClient({});
    currentClient = client;
    await assert.rejects(
      () => update.run({ args: { domain: "dom_1", id: "wh_1", enable: true, disable: true } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 1,
    );
    assert.equal(calls.length, 0);
  });

  it("sin nada que cambiar → 1", async () => {
    const { client, calls } = fakeClient({});
    currentClient = client;
    await assert.rejects(
      () => update.run({ args: { domain: "dom_1", id: "wh_1" } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 1,
    );
    assert.equal(calls.length, 0);
  });

  it("404 → exit 4", async () => {
    const { client } = fakeClient({ webhooks: { update: () => { throw new MailMaskError(404, "no existe"); } } });
    currentClient = client;
    await assert.rejects(
      () => update.run({ args: { domain: "dom_1", id: "wh_x", enable: true } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 4,
    );
  });
});

describe("webhooks delete", () => {
  it("sin --yes y sin TTY sale con 1 y no llama a la API", async () => {
    const { client, calls } = fakeClient({ webhooks: { delete: () => ({ ok: true }) } });
    currentClient = client;
    await assert.rejects(
      () => del.run({ args: { domain: "dom_1", id: "wh_1" } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 1,
    );
    assert.equal(calls.length, 0);
  });

  it("con --yes llama webhooks.delete", async () => {
    const { client, calls } = fakeClient({ webhooks: { delete: () => ({ ok: true }) } });
    currentClient = client;
    const out = captureStdout();
    try {
      await del.run({ args: { domain: "dom_1", id: "wh_1", yes: true } });
    } finally {
      out.restore();
    }
    assert.deepEqual(calls.find((c) => c.method === "webhooks.delete")!.args, ["dom_1", "wh_1"]);
  });

  it("404 con --yes → exit 4", async () => {
    const { client } = fakeClient({ webhooks: { delete: () => { throw new MailMaskError(404, "no existe"); } } });
    currentClient = client;
    await assert.rejects(
      () => del.run({ args: { domain: "dom_1", id: "wh_x", yes: true, json: true } }),
      (err: unknown) => err instanceof ExitSignal && err.code === 4,
    );
  });
});
