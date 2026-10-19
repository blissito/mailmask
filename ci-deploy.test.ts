import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

// Pedido 62: el deploy vive como job dentro de ci.yml, con needs de los tres verify*.
// Lee el YAML como texto (no hay parser de YAML declarado en el paquete raíz).
const ci = readFileSync(".github/workflows/ci.yml", "utf8");

// Bloque de un job de primer nivel: desde "  <nombre>:" hasta el siguiente job.
function job(nombre: string): string {
  const lineas = ci.split("\n");
  const i = lineas.findIndex((l) => l === `  ${nombre}:`);
  assert.notEqual(i, -1, `falta el job ${nombre} en ci.yml`);
  const fin = lineas.findIndex((l, k) => k > i && /^  [a-z][a-z-]*:$/.test(l));
  return lineas.slice(i, fin === -1 ? undefined : fin).join("\n");
}

test("ya no existe un deploy.yml paralelo", () => {
  assert.equal(existsSync(".github/workflows/deploy.yml"), false);
});

test("el job deploy espera a los tres verify con needs", () => {
  const d = job("deploy");
  assert.match(d, /needs:\s*\[\s*verify,\s*verify-cli,\s*verify-sdk\s*\]/);
});

test("docker y security no bloquean el deploy", () => {
  const d = job("deploy");
  assert.doesNotMatch(d, /needs:[^\n]*(docker|security)/);
});

test("el deploy sólo corre en push o manual sobre main", () => {
  const d = job("deploy");
  assert.match(d, /if:.*github\.event_name == 'push'/);
  assert.match(d, /if:.*refs\/heads\/main/);
  assert.match(d, /workflow_dispatch/);
});

test("el disparo manual está en ci.yml", () => {
  assert.match(ci.split("jobs:")[0], /workflow_dispatch:/);
});

test("el deploy conserva environment, concurrency y permisos de packages", () => {
  const d = job("deploy");
  assert.match(d, /environment: production/);
  assert.match(d, /concurrency: deploy-group/);
  assert.match(d, /packages: write/);
});

test("el deploy publica :sha y :main en GHCR y espera el rollout", () => {
  const d = job("deploy");
  assert.match(d, /ghcr\.io\/blissito\/mailmask:\$\{\{ github\.sha \}\}/);
  assert.match(d, /ghcr\.io\/blissito\/mailmask:main/);
  assert.match(d, /mailmask\.studio\/version/);
});

test("las actions del job deploy van fijadas por SHA", () => {
  const d = job("deploy");
  assert.doesNotMatch(d, /uses: [^\n]*@v\d/);
});
