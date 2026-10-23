// Fija lo básico del simulador de precio del agente: determinista, sin correo no cuesta, y el costo de
// clasificar del escenario optimista es el medido en producción.
import { it } from "node:test";
import assert from "node:assert/strict";
import { simulate, domainMonth, OPTIONS, SCENARIOS } from "./sim-agente-precio.mts";

it("misma semilla, mismo resultado", () => {
  assert.deepEqual(simulate(OPTIONS[0], SCENARIOS[1], 7, 2000), simulate(OPTIONS[0], SCENARIOS[1], 7, 2000));
});

it("sin correo no hay turnos ni respuestas", () => {
  assert.deepEqual(domainMonth(0, "medio"), { classify: 0, drafts: 0, responses: 0, sends: 0, billable: 0 });
});

it("el optimista usa el costo medido de clasificar ($0.0017 por turno)", () => {
  assert.equal(SCENARIOS[0].classifyUsd, 0.0017);
  assert.equal(SCENARIOS[0].ghostyMult, 0);
});
