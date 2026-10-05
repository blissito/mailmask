import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, test } from "node:test";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "mailmask-cli-"));
  process.env.MAILMASK_CONFIG_DIR = dir;
  // Determinista en cualquier máquina (con o sin Keychain/Secret Service real):
  // estas pruebas ejercitan el camino de archivo a propósito.
  process.env.MAILMASK_NO_KEYCHAIN = "1";
  delete process.env.MAILMASK_API_KEY;
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  delete process.env.MAILMASK_CONFIG_DIR;
  delete process.env.MAILMASK_NO_KEYCHAIN;
  delete process.env.MAILMASK_API_KEY;
});

describe("config: sin keychain (MAILMASK_NO_KEYCHAIN)", () => {
  test("resolveAuth es null sin nada guardado", async () => {
    const { resolveAuth } = await import("../src/config.js");
    assert.equal(await resolveAuth(), null);
  });

  test("writeCredentials cae al archivo, con permisos 600", async () => {
    const { writeCredentials, resolveAuth, credentialsFilePath } = await import("../src/config.js");
    const { source } = await writeCredentials({ apiKey: "mk_test_123" });
    assert.equal(source, "file");

    const auth = await resolveAuth();
    assert.equal(auth?.apiKey, "mk_test_123");
    assert.equal(auth?.source, "file");
    assert.equal(auth?.baseUrl, undefined);

    const { statSync } = await import("node:fs");
    const mode = statSync(credentialsFilePath()).mode & 0o777;
    assert.equal(mode, 0o600);
  });

  test("writeCredentials + resolveAuth conservan baseUrl", async () => {
    const { writeCredentials, resolveAuth } = await import("../src/config.js");
    await writeCredentials({ apiKey: "mk_test_123", baseUrl: "http://localhost:8000" });
    const auth = await resolveAuth();
    assert.equal(auth?.baseUrl, "http://localhost:8000");
  });

  test("MAILMASK_API_KEY gana sobre lo guardado en archivo", async () => {
    const { writeCredentials, resolveAuth } = await import("../src/config.js");
    await writeCredentials({ apiKey: "mk_from_file" });
    process.env.MAILMASK_API_KEY = "mk_from_env";
    const auth = await resolveAuth();
    assert.equal(auth?.apiKey, "mk_from_env");
    assert.equal(auth?.source, "env");
  });

  test("clearCredentials borra el archivo y avisa si no había nada", async () => {
    const { writeCredentials, clearCredentials } = await import("../src/config.js");
    assert.equal(await clearCredentials(), false);
    await writeCredentials({ apiKey: "mk_test_123" });
    assert.equal(await clearCredentials(), true);
    assert.equal(await clearCredentials(), false);
  });
});

describe("config: el keychain está disponible pero falla al escribir", () => {
  test("writeCredentials cae a archivo si secret-tool sale sin leer stdin (no se queda a medias)", async () => {
    // A diferencia del describe de arriba, aquí SÍ queremos que resolveAuth
    // intente el keychain real — por eso se quita MAILMASK_NO_KEYCHAIN y se
    // fuerza "linux" para que la prueba sea determinista en cualquier host.
    delete process.env.MAILMASK_NO_KEYCHAIN;
    const originalPlatform = process.platform;
    const originalPath = process.env.PATH;
    Object.defineProperty(process, "platform", { value: "linux" });
    const fakeDir = mkdtempSync(join(tmpdir(), "mailmask-fake-bin-"));
    writeFileSync(join(fakeDir, "secret-tool"), "#!/bin/sh\nexit 1\n");
    chmodSync(join(fakeDir, "secret-tool"), 0o755);
    process.env.PATH = `${fakeDir}:${originalPath}`;
    try {
      const { writeCredentials, resolveAuth, credentialsFilePath } = await import("../src/config.js");
      const { source } = await writeCredentials({ apiKey: "mk_test_456" });
      assert.equal(source, "file");

      const auth = await resolveAuth();
      assert.equal(auth?.apiKey, "mk_test_456");
      assert.equal(auth?.source, "file");

      const { statSync } = await import("node:fs");
      const mode = statSync(credentialsFilePath()).mode & 0o777;
      assert.equal(mode, 0o600);
    } finally {
      process.env.PATH = originalPath;
      rmSync(fakeDir, { recursive: true, force: true });
      Object.defineProperty(process, "platform", { value: originalPlatform });
      process.env.MAILMASK_NO_KEYCHAIN = "1";
    }
  });
});
