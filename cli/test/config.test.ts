import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, test } from "node:test";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "mailmask-cli-"));
  process.env.MAILMASK_CONFIG_DIR = dir;
  delete process.env.MAILMASK_API_KEY;
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  delete process.env.MAILMASK_CONFIG_DIR;
  delete process.env.MAILMASK_API_KEY;
});

describe("config", () => {
  test("resolveAuth es null sin nada guardado", async () => {
    const { resolveAuth } = await import("../src/config.js");
    assert.equal(resolveAuth(), null);
  });

  test("writeCredentials + resolveAuth hace roundtrip, con permisos 600", async () => {
    const { writeCredentials, resolveAuth, credentialsFilePath } = await import("../src/config.js");
    writeCredentials({ apiKey: "mk_test_123" });
    const auth = resolveAuth();
    assert.equal(auth?.apiKey, "mk_test_123");
    assert.equal(auth?.source, "file");
    assert.equal(auth?.baseUrl, undefined);

    const { statSync } = await import("node:fs");
    const mode = statSync(credentialsFilePath()).mode & 0o777;
    assert.equal(mode, 0o600);
  });

  test("MAILMASK_API_KEY gana sobre lo guardado", async () => {
    const { writeCredentials, resolveAuth } = await import("../src/config.js");
    writeCredentials({ apiKey: "mk_from_file" });
    process.env.MAILMASK_API_KEY = "mk_from_env";
    const auth = resolveAuth();
    assert.equal(auth?.apiKey, "mk_from_env");
    assert.equal(auth?.source, "env");
  });

  test("clearCredentials borra el archivo y avisa si no había nada", async () => {
    const { writeCredentials, clearCredentials } = await import("../src/config.js");
    assert.equal(clearCredentials(), false);
    writeCredentials({ apiKey: "mk_test_123" });
    assert.equal(clearCredentials(), true);
    assert.equal(clearCredentials(), false);
  });
});
