// Puro: sin DB ni servidor. `createKey` se inyecta para no depender de
// `db.ts` (que exige DATABASE_PATH) — lo mismo que hace dns-records.test.ts.
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { createDeviceAuthStore } from "./cli-auth.ts";

function store(ttlMs?: number, maxPending?: number) {
  const created: string[] = [];
  return {
    created,
    store: createDeviceAuthStore({
      ttlMs,
      maxPending,
      createKey: async (email: string) => {
        created.push(email);
        return { plaintextKey: `mk_test_${email}` };
      },
    }),
  };
}

describe("cli-auth: device code", () => {
  it("genera un código de usuario con el formato XXXX-XXXX", () => {
    const { store: s } = store();
    const start = s.start("https://www.mailmask.studio");
    assert.match(start.userCode, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    assert.equal(start.verificationUriComplete, `https://www.mailmask.studio/cli/authorize?user_code=${start.userCode}`);
  });

  it("queda pending hasta que alguien confirma con su email", async () => {
    const { store: s, created } = store();
    const start = s.start("https://www.mailmask.studio");
    assert.deepEqual(s.poll(start.deviceCode), { status: "pending" });

    const ok = await s.confirm(start.userCode, "ana@example.com");
    assert.equal(ok, true);
    assert.deepEqual(created, ["ana@example.com"]);

    const polled = s.poll(start.deviceCode);
    assert.equal(polled.status, "approved");
    if (polled.status === "approved") {
      assert.equal(polled.email, "ana@example.com");
      assert.equal(polled.apiKey, "mk_test_ana@example.com");
    }
  });

  it("el poll sólo entrega la llave una vez", async () => {
    const { store: s } = store();
    const start = s.start("https://www.mailmask.studio");
    await s.confirm(start.userCode, "ana@example.com");
    s.poll(start.deviceCode);
    assert.deepEqual(s.poll(start.deviceCode), { status: "expired" });
  });

  it("rechaza un código que no existe o ya fue usado", async () => {
    const { store: s } = store();
    const start = s.start("https://www.mailmask.studio");
    assert.equal(await s.confirm("ZZZZ-ZZZZ", "ana@example.com"), false);

    await s.confirm(start.userCode, "ana@example.com");
    assert.equal(await s.confirm(start.userCode, "otro@example.com"), false);
  });

  it("no es sensible a mayúsculas ni a espacios al confirmar", async () => {
    const { store: s } = store();
    const start = s.start("https://www.mailmask.studio");
    const ok = await s.confirm(`  ${start.userCode.toLowerCase()}  `, "ana@example.com");
    assert.equal(ok, true);
  });

  it("expira el código pasado el TTL", async () => {
    const { store: s } = store(10);
    const start = s.start("https://www.mailmask.studio");
    await new Promise((r) => setTimeout(r, 20));
    assert.deepEqual(s.poll(start.deviceCode), { status: "expired" });
    assert.equal(await s.confirm(start.userCode, "ana@example.com"), false);
  });

  it("limita cuántos device-codes pueden quedar pendientes a la vez", () => {
    const { store: s } = store(undefined, 2);
    s.start("https://www.mailmask.studio");
    s.start("https://www.mailmask.studio");
    assert.throws(() => s.start("https://www.mailmask.studio"));
  });
});
