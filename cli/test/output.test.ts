import assert from "node:assert/strict";
import { test } from "node:test";
import { maskSecret } from "../src/output.js";

test("maskSecret conserva sólo cabeza y cola de llaves largas", () => {
  assert.equal(maskSecret("mk_abcdefghijklmnop"), "mk_abcd...mnop");
});

test("maskSecret oculta por completo una llave corta", () => {
  assert.equal(maskSecret("short"), "*****");
});
