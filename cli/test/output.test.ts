import assert from "node:assert/strict";
import { describe, it, mock, test } from "node:test";
import { MailMaskError } from "@easybits.cloud/mailmask";
import { EXIT, confirmOrExit, failFromError, maskSecret } from "../src/output.js";
import { ExitSignal, trapExit } from "./test-helpers.js";

test("maskSecret conserva sólo cabeza y cola de llaves largas", () => {
  assert.equal(maskSecret("mk_abcdefghijklmnop"), "mk_abcd...mnop");
});

test("maskSecret oculta por completo una llave corta", () => {
  assert.equal(maskSecret("short"), "*****");
});

trapExit();

function captureStderr(): { text: () => string } {
  let text = "";
  mock.method(process.stderr, "write", (chunk: string) => {
    text += chunk;
    return true;
  });
  return { text: () => text };
}

describe("failFromError: taxonomía de exit codes", () => {
  it("404 → no encontrado (4)", () => {
    assert.throws(() => failFromError(new MailMaskError(404, "no existe")), (err: unknown) => err instanceof ExitSignal && err.code === EXIT.NOT_FOUND);
  });
  it("409 → conflicto (3)", () => {
    assert.throws(() => failFromError(new MailMaskError(409, "ya existe")), (err: unknown) => err instanceof ExitSignal && err.code === EXIT.CONFLICT);
  });
  it("429 → transitorio (5)", () => {
    assert.throws(() => failFromError(new MailMaskError(429, "too many requests")), (err: unknown) => err instanceof ExitSignal && err.code === EXIT.TRANSIENT);
  });
  it("500 → transitorio (5)", () => {
    assert.throws(() => failFromError(new MailMaskError(500, "boom")), (err: unknown) => err instanceof ExitSignal && err.code === EXIT.TRANSIENT);
  });
  it("401 → auth (2)", () => {
    assert.throws(() => failFromError(new MailMaskError(401, "sin llave")), (err: unknown) => err instanceof ExitSignal && err.code === EXIT.AUTH);
  });
  it("error sin status conocido → genérico (1)", () => {
    assert.throws(() => failFromError(new Error("lo que sea")), (err: unknown) => err instanceof ExitSignal && err.code === EXIT.ERROR);
  });
  it("error de RED (fetch failed, sin status) → transitorio 5", () => {
    assert.throws(() => failFromError(new TypeError("fetch failed")), (e: unknown) => e instanceof ExitSignal && e.code === EXIT.TRANSIENT);
  });
  it("error de red por código de causa (ECONNREFUSED) → transitorio 5", () => {
    const err = new TypeError("fetch failed");
    (err as unknown as { cause: unknown }).cause = Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" });
    assert.throws(() => failFromError(err), (e: unknown) => e instanceof ExitSignal && e.code === EXIT.TRANSIENT);
  });
});

describe("failFromError: --json imprime {error, status} a stderr", () => {
  it("con json:true imprime el objeto en vez de \"✖ ...\"", () => {
    const out = captureStderr();
    assert.throws(() => failFromError(new MailMaskError(404, "no existe"), { json: true }), ExitSignal);
    assert.deepEqual(JSON.parse(out.text()), { error: "no existe", status: 404 });
  });
});

describe("confirmOrExit", () => {
  it("con --yes no pregunta y no sale", async () => {
    await confirmOrExit("¿Seguro?", { yes: true });
  });

  it("sin --yes y sin TTY sale con 1 (texto)", async () => {
    await assert.rejects(
      () => confirmOrExit("¿Borrar todo?"),
      (err: unknown) => err instanceof ExitSignal && err.code === EXIT.ERROR,
    );
  });

  it("sin --yes y sin TTY, con json:true imprime {error} a stderr", async () => {
    const out = captureStderr();
    await assert.rejects(() => confirmOrExit("¿Borrar todo?", { json: true }), ExitSignal);
    const parsed = JSON.parse(out.text());
    assert.match(parsed.error, /--yes/);
  });
});
