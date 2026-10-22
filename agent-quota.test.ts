// Presupuesto de Mascarito por dominio (agent-quota.ts): ventana móvil de 5 h y semana que corta
// el lunes 00:00 de CDMX, multiplicador del add-on, tope interno, dominio de la casa sin tope,
// bloqueo al 100 % y avisos una sola vez. Los avisos van a un notificador simulado.
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";

let q: typeof import("./agent-quota.ts");
let dbmod: typeof import("./db.ts");
const alerts: { type: string; message: string }[] = [];
const ownerMails: { to: string; kind: string; pct: number }[] = [];
const suffix = Date.now().toString(36);
let seq = 0;

describe("Presupuesto de Mascarito por dominio", () => {
  let owner = "";
  const newDomain = (name = `aq-${suffix}-${++seq}.test`) => dbmod.createDomain(owner, name, ["k"], "v").id;
  const giveAddon = (domainId: string) => dbmod.createCourtesyAddon({
    userEmail: owner, kind: "agent", domainId, currentPeriodEnd: new Date(Date.now() + 30 * 864e5).toISOString(),
  });

  before(async () => {
    q = await import("./agent-quota.ts");
    dbmod = await import("./db.ts");
    q.setAgentQuotaNotifiers({
      alert: (type, message) => { alerts.push({ type, message }); },
      owner: (to, kind, d) => { ownerMails.push({ to, kind, pct: d.pct }); },
    });
    owner = `aq-owner-${suffix}@example.com`;
    dbmod.createUser(owner, "x");
  });
  after(() => q?.setAgentQuotaNotifiers(null));

  it("la semana corta el lunes 00:00 de CDMX y se nombra como semana ISO", () => {
    const sunNight = Date.parse("2026-10-26T05:59:00Z"); // domingo 23:59 en CDMX
    const monday = Date.parse("2026-10-26T06:00:00Z"); // lunes 00:00 en CDMX
    assert.equal(q.weekKey(sunNight), "2026-W43");
    assert.equal(q.weekKey(monday), "2026-W44");
    assert.equal(q.weekStart(sunNight), Date.parse("2026-10-19T06:00:00Z"));
    assert.equal(q.weekStart(monday), monday);
    assert.equal(q.weekKey(Date.parse("2027-01-01T12:00:00Z")), "2026-W53");
  });

  it("ventana de 5 h: lo viejo sale de la suma y resetsAt es cuándo se libera", () => {
    const now = Date.parse("2026-10-22T12:30:00Z");
    const buckets = [
      { hour: "2026-10-22T06", costUsd: 1 }, // hace más de 5 h: fuera
      { hour: "2026-10-22T08", costUsd: 0.05 },
      { hour: "2026-10-22T10", costUsd: 0.02 },
      { hour: "2026-10-22T12", costUsd: 0.01 },
    ];
    const under = q.windowUsage(buckets, 1, now);
    assert.ok(Math.abs(under.costUsd - 0.08) < 1e-9);
    assert.equal(under.resetsAt, "2026-10-22T13:00:00.000Z", "por debajo: cuando sale la primera hora");
    // por encima del tope (0.02): hay que esperar a que salgan 08 y 10
    assert.equal(q.windowUsage(buckets, 0.02, now).resetsAt, "2026-10-22T15:00:00.000Z");
    assert.equal(q.windowUsage(buckets, 0.06, now).resetsAt, "2026-10-22T13:00:00.000Z");
    assert.deepEqual(q.windowUsage([], 1, now), { costUsd: 0, resetsAt: null });
  });

  it("suma por canal en una sola fila por semana, sin perder turnos", async () => {
    const id = newDomain();
    await Promise.all(Array.from({ length: 40 }, () => Promise.resolve().then(() =>
      q.recordAgentUsage({ domainId: id, channel: "mail", threads: 1, toolCalls: 0, costUsd: 0.0001 }))));
    for (let i = 0; i < 3; i++) q.recordAgentUsage({ domainId: id, channel: "panel", toolCalls: 2, costUsd: 0.0001 });
    const u = q.getWeekUsage(id);
    assert.equal(u.threads, 40);
    assert.equal(u.mailTurns, 40);
    assert.equal(u.panelTurns, 3);
    assert.equal(u.toolCalls, 6);
    assert.ok(Math.abs(u.costUsd - 0.0043) < 1e-9, String(u.costUsd));
    const b = q.agentBudgetStatus(id, "panel");
    assert.equal(b.threads, 40);
    assert.equal(b.actions, 3);
    assert.ok(Math.abs(b.window5h.costUsd - 0.0043) < 1e-9, "la hora también suma");
  });

  it("valores basura no restan ni rompen la suma", () => {
    const id = newDomain();
    q.recordAgentUsage({ domainId: id, channel: "panel", threads: -5, turns: Number.NaN, toolCalls: -1, costUsd: -3 });
    const u = q.getWeekUsage(id);
    assert.deepEqual([u.threads, u.panelTurns, u.toolCalls, u.costUsd], [0, 0, 0, 0]);
  });

  it("el add-on multiplica el presupuesto y la semana nunca pasa del 40 % del dominio + 20 % del add-on", () => {
    const base = q.domainLimits(false), plus = q.domainLimits(true);
    assert.ok(Math.abs(plus.window5hUsd - base.window5hUsd * q.AGENT_ADDON_MULTIPLIER) < 1e-9);
    assert.ok(plus.weekUsd > base.weekUsd);
    const fx = 21; // sin lecturas en fx_rates, tipoDeCambio() usa su respaldo
    assert.ok(base.weekUsd <= (99 * 0.4) / Math.min(fx, 18) / (52 / 12) + 1e-9);
    assert.ok(plus.weekUsd <= (99 * 0.4 + 199 * 0.2) / Math.min(fx, 18) / (52 / 12) + 1e-9);
    const id = newDomain();
    assert.equal(q.agentBudgetStatus(id, "panel").hasAgentAddon, false);
    giveAddon(id);
    const b = q.agentBudgetStatus(id, "panel");
    assert.equal(b.hasAgentAddon, true);
    assert.ok(Math.abs(b.window5h.limitUsd - plus.window5hUsd) < 1e-9);
  });

  it("sin el add-on el canal de correo no corre; el panel sí", () => {
    const id = newDomain();
    assert.equal(q.checkAgentBudget(id, "mail").reason, "no_addon");
    assert.equal(q.checkAgentBudget(id, "panel").allowed, true);
  });

  it("al 100 % de la ventana de 5 h se bloquea en los dos canales, con hora de renovación", () => {
    const id = newDomain();
    giveAddon(id);
    const lim = q.agentBudgetStatus(id, "panel").window5h.limitUsd;
    q.recordAgentUsage({ domainId: id, channel: "panel", toolCalls: 1, costUsd: lim });
    for (const ch of ["panel", "mail"] as const) {
      const b = q.checkAgentBudget(id, ch);
      assert.equal(b.allowed, false);
      assert.equal(b.reason, "window5h");
      assert.ok(b.window5h.pct >= 100);
      assert.ok(Date.parse(b.window5h.resetsAt!) > Date.now());
    }
    assert.match(q.renewalPhrase(q.agentBudgetStatus(id, "panel")), /^a las \d{2}:\d{2}/);
  });

  it("al 100 % de la semana se bloquea hasta el lunes, avisa al dueño y alerta al equipo una vez", () => {
    const id = newDomain();
    giveAddon(id);
    const lim = q.agentBudgetStatus(id, "panel").week.limitUsd;
    const nMail = ownerMails.length, nAlert = alerts.length;
    // registrado al arrancar la semana: cuenta para la semana aunque ya salió de la ventana de 5 h
    q.recordAgentUsage({ domainId: id, channel: "mail", threads: 1, toolCalls: 0, costUsd: lim, now: q.weekStart() + 1000 });
    const b = q.checkAgentBudget(id, "mail");
    assert.equal(b.reason, "week");
    assert.equal(b.week.resetsAt, new Date(q.weekStart() + 7 * 864e5).toISOString());
    assert.match(q.renewalPhrase(b), /lunes/);
    q.checkAgentBudget(id, "panel");
    assert.equal(ownerMails.length, nMail + 1, "un solo correo al dueño aunque haya brincado el 80 %");
    assert.equal(ownerMails.at(-1)!.kind, "reached");
    assert.equal(alerts.length, nAlert + 1);
    assert.match(alerts.at(-1)!.type, /^agent-week:/);
  });

  it("aviso al 80 % de la semana, una sola vez", () => {
    const id = newDomain();
    giveAddon(id);
    const lim = q.agentBudgetStatus(id, "panel").week.limitUsd;
    const n = ownerMails.length;
    q.recordAgentUsage({ domainId: id, channel: "mail", threads: 1, toolCalls: 0, costUsd: lim * 0.79, now: q.weekStart() + 1000 });
    assert.equal(ownerMails.length, n, "debajo del 80 % no avisa");
    q.recordAgentUsage({ domainId: id, channel: "mail", threads: 1, toolCalls: 0, costUsd: lim * 0.02, now: q.weekStart() + 1000 });
    assert.equal(ownerMails.length, n + 1);
    assert.equal(ownerMails.at(-1)!.kind, "warn");
    assert.equal(ownerMails.at(-1)!.to, owner);
    q.checkAgentBudget(id, "mail");
    assert.equal(ownerMails.length, n + 1, "no repite");
    assert.equal(q.checkAgentBudget(id, "mail").allowed, true);
  });

  it("un dominio de la casa se cuenta pero nunca se topa; alerta una vez si el mes pasa de $40", () => {
    const name = `casa-${suffix}.test`;
    const id = newDomain(name);
    const prev = process.env.AGENT_UNCAPPED_DOMAINS;
    process.env.AGENT_UNCAPPED_DOMAINS = `mailmask.studio, ${name}`;
    try {
      const n = alerts.length, nMail = ownerMails.length;
      q.recordAgentUsage({ domainId: id, channel: "mail", threads: 1, toolCalls: 0, costUsd: 10 });
      const b = q.checkAgentBudget(id, "mail");
      assert.equal(b.uncapped, true);
      assert.equal(b.allowed, true, "sin add-on y arriba del tope, igual pasa");
      assert.equal(alerts.length, n);
      q.recordAgentUsage({ domainId: id, channel: "panel", toolCalls: 0, costUsd: 31 });
      q.checkAgentBudget(id, "panel");
      assert.equal(alerts.length, n + 1);
      assert.match(alerts.at(-1)!.type, /^agent-uncapped:/);
      assert.equal(ownerMails.length, nMail, "al dueño de la casa no se le manda aviso de tope");
      assert.equal(q.getWeekUsage(id).threads, 1, "sí se cuenta");
    } finally {
      if (prev === undefined) delete process.env.AGENT_UNCAPPED_DOMAINS; else process.env.AGENT_UNCAPPED_DOMAINS = prev;
    }
  });

  it("la vista del panel: sólo porcentajes y fechas; USD sólo para admins", () => {
    const id = newDomain();
    const b = q.agentBudgetStatus(id, "panel");
    const v = q.agentUsageView(b, false);
    assert.deepEqual(Object.keys(v).sort(), ["actions", "hasAgentAddon", "threads", "uncapped", "week", "window5h"]);
    assert.deepEqual(Object.keys(v.week as object).sort(), ["pct", "resetsAt"]);
    assert.ok("costUsd" in q.agentUsageView(b, true));
  });

  it("costo: real si Ghosty lo manda, si no la estimación por tipo de turno", () => {
    assert.equal(q.turnCostUsd({ toolCalls: 5, usage: { costUsd: 0.0123 } }, "panel"), 0.0123);
    assert.equal(q.turnCostUsd({ toolCalls: 0 }, "classify"), q.EST_CLASSIFY_USD);
    assert.equal(q.turnCostUsd({ toolCalls: 0 }, "draft"), q.EST_DRAFT_USD);
    assert.ok(Math.abs(q.turnCostUsd({ toolCalls: 3 }, "panel") - (0.005 + 3 * 0.004)) < 1e-9);
    assert.ok(Math.abs(q.turnCostUsd({ toolCalls: 1, usage: { costUsd: Number.NaN } }, "panel") - 0.009) < 1e-9);
  });
});
