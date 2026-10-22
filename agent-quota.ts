// Topes del agente (Mascarito) por dominio y mes.
//
// Se cobra dentro del límite del plan, nunca lo gastado: cada turno se anota en `agent_usage`
// (UPSERT que suma) y antes de llamar al modelo se pregunta `checkAgentBudget`. Dos topes:
// 1. **Del cliente**: hilos incluidos en el plan. Al llegar, el automático baja a borrador
//    (`draft_only`) y se le ofrece un bloque. Avisos al dueño al 80 % y al 100 %, una vez por mes.
// 2. **Interno**: el gasto del mes no pasa del 20 % del precio del agente. Al llegar se pausa
//    (`paused`: no se llama al modelo) y se alerta al equipo, una vez por mes.
// Mismo patrón que `monthlyForwards` en `forwarding.ts`: contador por mes + `claimOnce`.
import { sqlite } from "./pg.js";
import { claimOnce, getDomain } from "./db.js";
import { sendAlert } from "./ses.js";
import { sendTemplate, agentQuotaWarning, agentQuotaReached } from "./emails.js";
import { tipoDeCambio } from "./fx.js";
import { log } from "./logger.js";

/** Precio del agente por dominio al mes. */
export const AGENT_PRICE_MXN = 199;
/** Parte del precio que puede irse en modelo antes de pausar. */
export const AGENT_INTERNAL_COST_SHARE = 0.2;
/** Hilos que el plan atiende solo al mes. Provisional hasta el bench (fase 3 del plan). */
export const AGENT_INCLUDED_THREADS = 300;
/** Tipo de cambio si fx.ts no tiene dato utilizable. */
const FALLBACK_USD_MXN = 18;

// Costo estimado por turno cuando Ghosty no manda `done.usage` (versión vieja).
// Provisional hasta el bench: clasificar y borrador están medidos sin herramientas; el turno
// del panel con herramientas todavía es una suposición.
export const EST_CLASSIFY_USD = 0.0017;
export const EST_DRAFT_USD = 0.005;
export const EST_PANEL_BASE_USD = 0.005;
export const EST_PANEL_PER_TOOL_USD = 0.004;

export type AgentTurnKind = "classify" | "draft" | "panel";

/** Lo que Ghosty manda en `done.usage` (fase 1). Todo opcional: se valida al leerlo. */
export type AgentTurnUsage = {
  inputTokens?: number;
  cacheReadTokens?: number;
  cacheWriteTokens?: number;
  outputTokens?: number;
  toolCalls?: number;
  model?: string;
  costUsd?: number;
};

export function estimateTurnCostUsd(kind: AgentTurnKind, toolCalls = 0): number {
  if (kind === "classify") return EST_CLASSIFY_USD;
  if (kind === "draft") return EST_DRAFT_USD;
  return EST_PANEL_BASE_USD + EST_PANEL_PER_TOOL_USD * Math.max(0, toolCalls);
}

/** Costo real si Ghosty lo reportó; si no, la estimación por tipo de turno. */
export function turnCostUsd(o: { toolCalls: number; usage?: AgentTurnUsage }, kind: AgentTurnKind): number {
  const real = o.usage?.costUsd;
  if (typeof real === "number" && Number.isFinite(real) && real >= 0) return real;
  return estimateTurnCostUsd(kind, o.toolCalls);
}

export const currentMonth = (now = new Date()): string => now.toISOString().slice(0, 7);

/** Tope interno en USD: 20 % del precio en pesos al tipo de cambio de cotización. */
export function internalCapUsd(): number {
  let fx = FALLBACK_USD_MXN;
  try {
    const r = tipoDeCambio();
    if (Number.isFinite(r) && r > 0) fx = r;
  } catch { /* sin tabla o sin dato: respaldo */ }
  return (AGENT_PRICE_MXN * AGENT_INTERNAL_COST_SHARE) / fx;
}

export type AgentUsageRow = { domainId: string; month: string; threads: number; turns: number; toolCalls: number; costUsd: number };

export function getAgentUsage(domainId: string, month = currentMonth()): AgentUsageRow {
  const r = sqlite.prepare(
    "SELECT threads, turns, tool_calls AS toolCalls, cost_micro_usd AS micro FROM agent_usage WHERE domain_id = ? AND month = ?",
  ).get(domainId, month) as { threads: number; turns: number; toolCalls: number; micro: number } | undefined;
  return { domainId, month, threads: r?.threads ?? 0, turns: r?.turns ?? 0, toolCalls: r?.toolCalls ?? 0, costUsd: (r?.micro ?? 0) / 1e6 };
}

const nonNeg = (n: number | undefined): number => (Number.isFinite(n) && (n as number) > 0 ? Math.round(n as number) : 0);

/** Suma el consumo de un turno al mes del dominio. Atómico: un solo UPSERT, sin leer antes. */
export function recordAgentUsage(u: { domainId: string; threads?: number; turns: number; toolCalls: number; costUsd: number; month?: string }): AgentUsageRow {
  const month = u.month ?? currentMonth();
  const micro = Number.isFinite(u.costUsd) && u.costUsd > 0 ? Math.round(u.costUsd * 1e6) : 0;
  sqlite.prepare(
    `INSERT INTO agent_usage (domain_id, month, threads, turns, tool_calls, cost_micro_usd, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(domain_id, month) DO UPDATE SET
       threads = threads + excluded.threads,
       turns = turns + excluded.turns,
       tool_calls = tool_calls + excluded.tool_calls,
       cost_micro_usd = cost_micro_usd + excluded.cost_micro_usd,
       updated_at = excluded.updated_at`,
  ).run(u.domainId, month, nonNeg(u.threads), nonNeg(u.turns), nonNeg(u.toolCalls), micro, new Date().toISOString());
  const row = getAgentUsage(u.domainId, month);
  notifyThresholds(row);
  return row;
}

export type AgentBudget = {
  allowed: boolean;
  mode: "auto" | "draft_only" | "paused";
  reason: string;
  threadsPct: number;
  internalPct: number;
};

/** Estado puro (sin avisos): lo usan `checkAgentBudget` y la lectura del panel. */
export function agentBudgetStatus(row: AgentUsageRow): AgentBudget {
  const cap = internalCapUsd();
  const threadsPct = Math.round((row.threads / AGENT_INCLUDED_THREADS) * 100);
  const internalPct = Math.round((row.costUsd / cap) * 100);
  if (row.costUsd >= cap) return { allowed: false, mode: "paused", reason: "tope interno de gasto del mes", threadsPct, internalPct };
  if (row.threads >= AGENT_INCLUDED_THREADS) return { allowed: true, mode: "draft_only", reason: "hilos incluidos del mes agotados", threadsPct, internalPct };
  return { allowed: true, mode: "auto", reason: "ok", threadsPct, internalPct };
}

/** Antes de llamar al modelo. Si toca, avisa (una vez por mes) además de contestar. */
export function checkAgentBudget(domainId: string): AgentBudget {
  const row = getAgentUsage(domainId);
  notifyThresholds(row);
  return agentBudgetStatus(row);
}

// --- Avisos (inyectables para las pruebas) ---

type Notifiers = {
  alert: (type: string, message: string) => unknown;
  owner: (to: string, kind: "warn" | "reached", d: { domain: string; used: number; cap: number }) => unknown;
};
const defaultNotifiers: Notifiers = {
  alert: (type, message) => sendAlert(type, message).catch(() => false),
  owner: (to, kind, d) =>
    sendTemplate(to, kind === "warn" ? agentQuotaWarning(d) : agentQuotaReached(d)).catch(() => ""),
};
let notifiers = defaultNotifiers;
export function setAgentQuotaNotifiers(n: Partial<Notifiers> | null): void {
  notifiers = n ? { ...defaultNotifiers, ...n } : defaultNotifiers;
}

function notifyThresholds(row: AgentUsageRow): void {
  const key = `${row.domainId}:${row.month}`;
  const cap = internalCapUsd();
  if (row.costUsd >= cap && claimOnce("agent-cost-paused", key)) {
    const name = getDomain(row.domainId)?.domain ?? row.domainId;
    log("warn", "assistant", "Agente en pausa por tope interno de gasto", { domainId: row.domainId, costUsd: row.costUsd, capUsd: cap });
    notifiers.alert(`agent-paused:${row.domainId}`,
      `Mascarito se pausó en ${name}: gastó $${row.costUsd.toFixed(2)} USD este mes (${row.month}), tope interno $${cap.toFixed(2)} USD (20 % de $${AGENT_PRICE_MXN} MXN). ${row.threads} hilos, ${row.turns} turnos, ${row.toolCalls} tool calls.`);
  }
  const used = row.threads;
  const capThreads = AGENT_INCLUDED_THREADS;
  const reached = used >= capThreads;
  const warn = used >= Math.ceil(capThreads * 0.8);
  if (!warn) return;
  const kind = reached ? "agent-threads-reached" : "agent-threads-warn";
  if (!claimOnce(kind, key)) return;
  // Si salta directo al 100 %, el aviso del 80 % ya no tiene caso.
  if (reached) claimOnce("agent-threads-warn", key);
  const domain = getDomain(row.domainId);
  if (!domain) return;
  notifiers.owner(domain.ownerEmail, reached ? "reached" : "warn", { domain: domain.domain, used, cap: capThreads });
}
