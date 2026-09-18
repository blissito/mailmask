// Valida las skills públicas (`public/skills/*/SKILL.md`) con el mismo empaquetador que
// corre en el Dockerfile: un frontmatter roto no debe llegar al deploy.
import { test } from "node:test";
import assert from "node:assert/strict";
import { pack } from "./scripts/skills-pack.mts";

test("las skills públicas pasan la validación del índice", () => {
  const { problems, count } = pack(false);
  assert.deepEqual(problems, []);
  assert.ok(count >= 5, `se esperaban al menos 5 skills, hay ${count}`);
});
