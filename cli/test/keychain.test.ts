import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { isAvailable } from "../src/keychain.js";

afterEach(() => {
  delete process.env.MAILMASK_NO_KEYCHAIN;
});

test("isAvailable es false con MAILMASK_NO_KEYCHAIN fijada, sin importar la plataforma", async () => {
  process.env.MAILMASK_NO_KEYCHAIN = "1";
  assert.equal(await isAvailable(), false);
});
