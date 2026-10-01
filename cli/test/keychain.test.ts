import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";
import { isAvailable } from "../src/keychain.js";

afterEach(() => {
  delete process.env.MAILMASK_NO_KEYCHAIN;
});

test("isAvailable es false con MAILMASK_NO_KEYCHAIN fijada, sin importar la plataforma", async () => {
  process.env.MAILMASK_NO_KEYCHAIN = "1";
  assert.equal(await isAvailable(), false);
});

function withFakeBin(name: string, script: string) {
  const dir = mkdtempSync(join(tmpdir(), "mailmask-fake-bin-"));
  const bin = join(dir, name);
  writeFileSync(bin, `#!/bin/sh\n${script}\n`);
  chmodSync(bin, 0o755);
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("set() rechaza en vez de tronar el proceso si secret-tool sale antes de leer stdin", async () => {
  // Se fuerza "linux" (y no MAILMASK_NO_KEYCHAIN) porque esta prueba ejercita
  // justo el camino REAL del backend, determinista en cualquier host — mismo
  // espíritu que MAILMASK_NO_KEYCHAIN para el camino inverso.
  const originalPlatform = process.platform;
  const originalPath = process.env.PATH;
  Object.defineProperty(process, "platform", { value: "linux" });
  const fake = withFakeBin("secret-tool", "exit 1");
  process.env.PATH = `${fake.dir}:${originalPath}`;
  try {
    const { set } = await import("../src/keychain.js");
    await assert.rejects(() => set("mk_test_123"));
  } finally {
    process.env.PATH = originalPath;
    fake.cleanup();
    Object.defineProperty(process, "platform", { value: originalPlatform });
  }
});
