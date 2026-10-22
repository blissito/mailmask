// Topes del agente por dominio y mes (agent-quota.ts): la suma es atómica, el tope del cliente
// baja el automático a borrador, el interno pausa y alerta una sola vez, y el dueño recibe el
// aviso del 80 % una vez por mes. Los avisos van a un notificador simulado.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";

let q: typeof import("./agent-quota.ts");
let dbmod: typeof import("./db.ts");
const alerts: { type: string; message: string }[] = [];
const ownerMails: { to: string; kind: string; used: number }[] = [];
const suffix = Date.now().toString(36);
let seq = 0;

describe("Topes del agente por dominio", () => {
  let owner = "";
  const newDomain = () => dbmod.createDomain(owner, `aq-${suffix}-${++seq}.test`, ["k"], "v").id;

  before(async () => {
    q = await import("./agent-quota.ts");
    dbmod = await import("./db.ts");
    q.setAgentQuotaNotifiers({
      alert: (type, message) => { alerts.push({ type, message }); },
      owner: (to, kind, d) => { ownerMails.push({ to, kind, used: d.used }); },
    });
    owner = `aq-owner-${suffix}@example.com`;
    dbmod.createUser(owner, "x");
  });
  after(() => q?.setAgentQuotaNotifiers(null));

  it("suma en una sola fila por dominio y mes, sin perder turnos", async () => {
    const id = newDomain();
    // Muchos registros seguidos (y en paralelo) sobre la misma fila: el UPSERT suma.
    await Promise.all(Array.from({ length: 40 }, () => Promise.resolve().then(() =>
      q.recordAgentUsage({ domainId: id, threads: 1, turns: 1, toolCalls: 2, costUsd: 0.0017 }))));
    const u = q.getAgentUsage(id);
    assert.equal(u.threads, 40);
    assert.equal(u.turns, 40);
    assert.equal(u.toolCalls, 80);
    assert.ok(Math.abs(u.costUsd - 0.068) < 1e-6, String(u.costUsd));
    // Otro mes es otra fila.
    q.recordAgentUsage({ domainId: id, turns: 1, toolCalls: 0, costUsd: 1, month: "2020-01" });
    assert.equal(q.getAgentUsage(id).turns, 40);
    assert.equal(q.getAgentUsage(id, "2020-01").turns, 1);
    assert.equal(q.checkAgentBudget(id).mode, "auto");
  });

  it("valores basura no restan ni rompen la suma", () => {
    const id = newDomain();
    q.recordAgentUsage({ domainId: id, threads: -5, turns: Number.NaN, toolCalls: -1, costUsd: -3 });
    assert.deepEqual({ ...q.getAgentUsage(id), domainId: "" }, { domainId: "", month: q.currentMonth(), threads: 0, turns: 0, toolCalls: 0, costUsd: 0 });
  });

  it("aviso al 80 % de los hilos, una sola vez por mes", () => {
    const id = newDomain();
    const n = ownerMails.length;
    q.recordAgentUsage({ domainId: id, threads: Math.ceil(q.AGENT_INCLUDED_THREADS * 0.8) - 1, turns: 1, toolCalls: 0, costUsd: 0 });
    assert.equal(ownerMails.length, n, "debajo del 80 % no avisa");
    q.recordAgentUsage({ domainId: id, threads: 1, turns: 1, toolCalls: 0, costUsd: 0 });
    assert.equal(ownerMails.length, n + 1);
    assert.equal(ownerMails.at(-1)!.kind, "warn");
    assert.equal(ownerMails.at(-1)!.to, owner);
    q.recordAgentUsage({ domainId: id, threads: 1, turns: 1, toolCalls: 0, costUsd: 0 });
    q.checkAgentBudget(id);
    assert.equal(ownerMails.length, n + 1, "no repite el aviso");
    assert.equal(q.checkAgentBudget(id).mode, "auto");
  });

  it("al llegar a los hilos incluidos el automático baja a borrador y avisa al 100 %", () => {
    const id = newDomain();
    const n = ownerMails.length;
    q.recordAgentUsage({ domainId: id, threads: q.AGENT_INCLUDED_THREADS, turns: 1, toolCalls: 0, costUsd: 0 });
    const b = q.checkAgentBudget(id);
    assert.equal(b.mode, "draft_only");
    assert.equal(b.allowed, true);
    assert.equal(b.threadsPct, 100);
    assert.equal(ownerMails.length, n + 1, "un solo aviso aunque haya brincado el 80 %");
    assert.equal(ownerMails.at(-1)!.kind, "reached");
    q.checkAgentBudget(id);
    assert.equal(ownerMails.length, n + 1);
  });

  it("el tope interno de gasto pausa y alerta al equipo una sola vez", () => {
    const id = newDomain();
    const cap = q.internalCapUsd();
    assert.ok(cap > 1 && cap < 3, `20 % de $199 MXN en USD: ${cap}`);
    const n = alerts.length;
    q.recordAgentUsage({ domainId: id, turns: 1, toolCalls: 3, costUsd: cap * 0.5 });
    assert.equal(q.checkAgentBudget(id).mode, "auto");
    assert.equal(alerts.length, n);
    q.recordAgentUsage({ domainId: id, turns: 1, toolCalls: 3, costUsd: cap * 0.6 });
    const b = q.checkAgentBudget(id);
    assert.equal(b.mode, "paused");
    assert.equal(b.allowed, false);
    assert.ok(b.internalPct >= 100);
    assert.equal(alerts.length, n + 1);
    assert.match(alerts.at(-1)!.type, /^agent-paused:/);
    q.recordAgentUsage({ domainId: id, turns: 1, toolCalls: 0, costUsd: 0.01 });
    q.checkAgentBudget(id);
    assert.equal(alerts.length, n + 1, "no repite la alerta en el mes");
  });

  it("costo: real si Ghosty lo manda, si no la estimación por tipo de turno", () => {
    assert.equal(q.turnCostUsd({ toolCalls: 5, usage: { costUsd: 0.0123 } }, "panel"), 0.0123);
    assert.equal(q.turnCostUsd({ toolCalls: 0 }, "classify"), q.EST_CLASSIFY_USD);
    assert.equal(q.turnCostUsd({ toolCalls: 0 }, "draft"), q.EST_DRAFT_USD);
    assert.ok(Math.abs(q.turnCostUsd({ toolCalls: 3 }, "panel") - (0.005 + 3 * 0.004)) < 1e-9);
    assert.ok(Math.abs(q.turnCostUsd({ toolCalls: 1, usage: { costUsd: Number.NaN } }, "panel") - 0.009) < 1e-9);
  });
});
