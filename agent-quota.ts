// Presupuesto del agente (Mascarito) por dominio.
//
// Un solo presupuesto por dominio, compartido por Mascarito en el panel (soporte) y Mascarito en
// el correo. El cliente lo ve en porcentajes, al estilo de Claude, medido en costo; nunca ve
// tokens ni dólares. Dos límites:
// - ventana móvil de 5 h (cubetas por hora en `agent_usage_hourly`);
// - semana (fila por semana ISO en `agent_usage`; corta el lunes 00:00 de CDMX).
// Al 100 % de cualquiera: el panel contesta con la hora de renovación sin llamar a Ghosty y el
// correo deja el hilo a una persona. Avisos al dueño al 80 % y 100 % de la semana, una vez por
// semana (`claimOnce`). El de 5 h sólo se ve en la UI: un correo cada 5 h sería ruido.
//
// El dominio activado ($99) trae el presupuesto base; el add-on `agent` ($199) habilita el canal
// de correo y lo multiplica. Nunca hay excedente: si se queda corto, se ofrece subir.
// El tope interno: lo gastado en una semana nunca pasa del 20 % del ingreso semanal del dominio.
// Los dominios de la casa (`AGENT_UNCAPPED_DOMAINS`) se cuentan pero no se topan; se vigila su
// gasto del mes.
import { sqlite } from "./pg.js";
import { claimOnce, getDomain, listEffectiveAddonsForDomain } from "./db.js";
import { sendAlert } from "./ses.js";
import { sendTemplate, agentQuotaWarning, agentQuotaReached } from "./emails.js";
import { tipoDeCambio } from "./fx.js";
import { AGENT_ADDON } from "./plans.js";
import { log } from "./logger.js";

// --- Constantes medidas con el bench del 22-oct-2026 ---
// Tarea del panel con herramientas ≈ $0.021 USD (Haiku, 3–6 llamadas); pregunta sin herramientas ≈ $0.004.

/** Presupuesto base de la ventana de 5 h, en USD (≈ 10 tareas). */
export const BASE_5H_USD = 0.2;
/** Presupuesto base de la semana, en USD (≈ 24 tareas; el tope interno lo recorta si hace falta). */
export const BASE_WEEK_USD = 0.5;
/** Cuánto sube el presupuesto con el add-on `agent`. */
export const AGENT_ADDON_MULTIPLIER = 2;
/** Parte de los $99 del dominio que puede irse en modelo (decisión de bliss: casi nadie llena el tope). */
export const DOMAIN_COST_SHARE = 0.4;
/** Parte del add-on que puede irse en modelo. */
export const INTERNAL_COST_SHARE = 0.2;
export const DOMAIN_PRICE_MXN = 99;
export const AGENT_ADDON_PRICE_MXN = AGENT_ADDON.price / 100;
/** Alerta al equipo si un dominio de la casa pasa de esto en el mes. */
export const UNCAPPED_ALERT_MONTH_USD = 40;
const WEEKS_PER_MONTH = 52 / 12;
const FALLBACK_USD_MXN = 18;
const HOURLY_RETENTION_DAYS = 35;
const WINDOW_HOURS = 5;
/** CDMX no tiene horario de verano desde 2022: UTC−6 fijo. */
const CDMX_OFFSET_H = -6;

// Costo estimado por turno cuando Ghosty no manda `done.usage` (versión vieja). Clasificar y
// borrador están medidos sin herramientas; el turno del panel con herramientas es suposición.
export const EST_CLASSIFY_USD = 0.0017;
export const EST_DRAFT_USD = 0.005;
export const EST_PANEL_BASE_USD = 0.005;
export const EST_PANEL_PER_TOOL_USD = 0.004;

export type AgentTurnKind = "classify" | "draft" | "panel";
export type AgentChannel = "mail" | "panel";

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

// --- Calendario ---

const HOUR_MS = 3600_000;

export const hourKey = (t: number): string => new Date(t).toISOString().slice(0, 13);
const hourStart = (key: string): number => Date.parse(`${key}:00:00.000Z`);

/** Lunes 00:00 de CDMX de la semana de `now`, en ms UTC. */
export function weekStart(now = Date.now()): number {
  const local = new Date(now + CDMX_OFFSET_H * HOUR_MS);
  const dow = (local.getUTCDay() + 6) % 7; // lunes = 0
  const midnight = Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate()) - dow * 86400_000;
  return midnight - CDMX_OFFSET_H * HOUR_MS;
}

/** Semana ISO (`2026-W43`) del lunes de CDMX de `now`. */
export function weekKey(now = Date.now()): string {
  const monday = new Date(weekStart(now) + CDMX_OFFSET_H * HOUR_MS); // fecha local del lunes
  const thursday = new Date(Date.UTC(monday.getUTCFullYear(), monday.getUTCMonth(), monday.getUTCDate() + 3));
  const year = thursday.getUTCFullYear();
  const week = 1 + Math.floor((thursday.getTime() - Date.UTC(year, 0, 1)) / (7 * 86400_000));
  return `${year}-W${String(week).padStart(2, "0")}`;
}

// --- Límites ---

function fxRate(): number {
  try {
    const r = tipoDeCambio();
    if (Number.isFinite(r) && r > 0) return r;
  } catch { /* sin tabla o sin dato */ }
  return FALLBACK_USD_MXN;
}

export function uncappedDomainNames(): string[] {
  return (process.env.AGENT_UNCAPPED_DOMAINS ?? "mailmask.studio").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
}

export function isUncappedDomain(domainId: string): boolean {
  const name = getDomain(domainId)?.domain?.toLowerCase();
  return !!name && uncappedDomainNames().includes(name);
}

export function hasAgentAddon(domainId: string): boolean {
  return listEffectiveAddonsForDomain(domainId).some((a) => a.kind === AGENT_ADDON.kind);
}

/** Topes en USD del dominio: base × multiplicador, y la semana recortada al 40 % del dominio + 20 % del add-on. */
export function domainLimits(withAddon: boolean): { window5hUsd: number; weekUsd: number } {
  const mult = withAddon ? AGENT_ADDON_MULTIPLIER : 1;
  const costMxn = DOMAIN_PRICE_MXN * DOMAIN_COST_SHARE + (withAddon ? AGENT_ADDON_PRICE_MXN * INTERNAL_COST_SHARE : 0);
  const internalWeekUsd = costMxn / fxRate() / WEEKS_PER_MONTH;
  return { window5hUsd: BASE_5H_USD * mult, weekUsd: Math.min(BASE_WEEK_USD * mult, internalWeekUsd) };
}

// --- Lectura ---

export type HourBucket = { hour: string; costUsd: number };

/**
 * Suma de la ventana móvil (la hora en curso y las 4 anteriores) y cuándo se renueva:
 * por encima del tope, cuándo sale la cubeta que la deja por debajo; por debajo, cuándo se
 * libera la primera hora. Sin uso, `null`.
 */
export function windowUsage(buckets: HourBucket[], limitUsd: number, now = Date.now()): { costUsd: number; resetsAt: string | null } {
  const from = Math.floor(now / HOUR_MS) * HOUR_MS - (WINDOW_HOURS - 1) * HOUR_MS;
  const inWindow = buckets.filter((b) => hourStart(b.hour) >= from && b.costUsd > 0).sort((a, b) => a.hour.localeCompare(b.hour));
  const costUsd = inWindow.reduce((s, b) => s + b.costUsd, 0);
  if (!inWindow.length) return { costUsd: 0, resetsAt: null };
  let release = inWindow[0];
  if (costUsd >= limitUsd) {
    let remaining = costUsd;
    for (const b of inWindow) {
      remaining -= b.costUsd;
      release = b;
      if (remaining < limitUsd) break;
    }
  }
  return { costUsd, resetsAt: new Date(hourStart(release.hour) + WINDOW_HOURS * HOUR_MS).toISOString() };
}

export type WeekRow = { domainId: string; week: string; threads: number; mailTurns: number; panelTurns: number; toolCalls: number; costUsd: number };

export function getWeekUsage(domainId: string, week = weekKey()): WeekRow {
  const r = sqlite.prepare(
    `SELECT threads, mail_turns AS mailTurns, panel_turns AS panelTurns, tool_calls AS toolCalls, cost_micro_usd AS micro
     FROM agent_usage WHERE domain_id = ? AND week = ?`,
  ).get(domainId, week) as Omit<WeekRow, "domainId" | "week" | "costUsd"> & { micro: number } | undefined;
  return {
    domainId, week, threads: r?.threads ?? 0, mailTurns: r?.mailTurns ?? 0, panelTurns: r?.panelTurns ?? 0,
    toolCalls: r?.toolCalls ?? 0, costUsd: (r?.micro ?? 0) / 1e6,
  };
}

function hourBuckets(domainId: string, sinceMs: number): HourBucket[] {
  return (sqlite.prepare("SELECT hour, cost_micro_usd AS micro FROM agent_usage_hourly WHERE domain_id = ? AND hour >= ?")
    .all(domainId, hourKey(sinceMs)) as { hour: string; micro: number }[])
    .map((r) => ({ hour: r.hour, costUsd: r.micro / 1e6 }));
}

/** Gasto del mes calendario UTC (para vigilar los dominios de la casa). */
export function monthCostUsd(domainId: string, now = Date.now()): number {
  const d = new Date(now);
  return hourBuckets(domainId, Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1)).reduce((s, b) => s + b.costUsd, 0);
}

// --- Escritura ---

const nonNeg = (n: number | undefined): number => (Number.isFinite(n) && (n as number) > 0 ? Math.round(n as number) : 0);

/** Suma un turno a la semana y a la hora. Atómico: dos UPSERT en una transacción, sin leer antes. */
export function recordAgentUsage(u: { domainId: string; channel: AgentChannel; threads?: number; turns?: number; toolCalls: number; costUsd: number; now?: number }): WeekRow {
  const now = u.now ?? Date.now();
  const week = weekKey(now);
  const micro = Number.isFinite(u.costUsd) && u.costUsd > 0 ? Math.round(u.costUsd * 1e6) : 0;
  const turns = u.turns === undefined ? 1 : nonNeg(u.turns);
  sqlite.transaction(() => {
    sqlite.prepare(
      `INSERT INTO agent_usage (domain_id, week, threads, mail_turns, panel_turns, tool_calls, cost_micro_usd, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(domain_id, week) DO UPDATE SET
         threads = threads + excluded.threads,
         mail_turns = mail_turns + excluded.mail_turns,
         panel_turns = panel_turns + excluded.panel_turns,
         tool_calls = tool_calls + excluded.tool_calls,
         cost_micro_usd = cost_micro_usd + excluded.cost_micro_usd,
         updated_at = excluded.updated_at`,
    ).run(u.domainId, week, nonNeg(u.threads), u.channel === "mail" ? turns : 0, u.channel === "panel" ? turns : 0,
      nonNeg(u.toolCalls), micro, new Date(now).toISOString());
    if (micro > 0) {
      sqlite.prepare(
        `INSERT INTO agent_usage_hourly (domain_id, hour, cost_micro_usd) VALUES (?, ?, ?)
         ON CONFLICT(domain_id, hour) DO UPDATE SET cost_micro_usd = cost_micro_usd + excluded.cost_micro_usd`,
      ).run(u.domainId, hourKey(now), micro);
    }
    sqlite.prepare("DELETE FROM agent_usage_hourly WHERE domain_id = ? AND hour < ?")
      .run(u.domainId, hourKey(now - HOURLY_RETENTION_DAYS * 86400_000));
  })();
  notifyThresholds(agentBudgetStatus(u.domainId, "panel", now));
  return getWeekUsage(u.domainId, week);
}

// --- Estado ---

export type AgentBudget = {
  domainId: string;
  allowed: boolean;
  /** Qué bloquea: ok, window5h, week o no_addon (canal de correo sin el add-on). */
  reason: "ok" | "window5h" | "week" | "no_addon";
  uncapped: boolean;
  hasAgentAddon: boolean;
  window5h: { pct: number; resetsAt: string | null; costUsd: number; limitUsd: number };
  week: { pct: number; resetsAt: string; key: string; costUsd: number; limitUsd: number };
  threads: number;
  actions: number;
};

const pctOf = (cost: number, limit: number): number => (limit > 0 ? Math.round((cost / limit) * 100) : 100);

/** Estado sin avisos: lo usan `checkAgentBudget` y las lecturas del panel y del dock. */
export function agentBudgetStatus(domainId: string, channel: AgentChannel, now = Date.now()): AgentBudget {
  const addon = hasAgentAddon(domainId);
  const uncapped = isUncappedDomain(domainId);
  const limits = domainLimits(addon);
  const w = windowUsage(hourBuckets(domainId, now - WINDOW_HOURS * HOUR_MS), limits.window5hUsd, now);
  const wk = getWeekUsage(domainId, weekKey(now));
  const window5h = { pct: pctOf(w.costUsd, limits.window5hUsd), resetsAt: w.resetsAt, costUsd: w.costUsd, limitUsd: limits.window5hUsd };
  const week = { pct: pctOf(wk.costUsd, limits.weekUsd), resetsAt: new Date(weekStart(now) + 7 * 86400_000).toISOString(), key: wk.week, costUsd: wk.costUsd, limitUsd: limits.weekUsd };
  let reason: AgentBudget["reason"] = "ok";
  if (!uncapped) {
    if (channel === "mail" && !addon) reason = "no_addon";
    else if (week.pct >= 100) reason = "week";
    else if (window5h.pct >= 100) reason = "window5h";
  }
  return { domainId, allowed: reason === "ok", reason, uncapped, hasAgentAddon: addon, window5h, week, threads: wk.threads, actions: wk.panelTurns };
}

/** Antes de llamar al modelo. Si toca, avisa (una vez por semana o por mes) además de contestar. */
export function checkAgentBudget(domainId: string, channel: AgentChannel): AgentBudget {
  const b = agentBudgetStatus(domainId, channel);
  notifyThresholds(b);
  return b;
}

/** «a las 14:00» (5 h) o «el lunes a las 00:00» (semana), en hora de CDMX. */
export function renewalPhrase(b: AgentBudget): string {
  if (b.reason === "week") return "el lunes a las 00:00 (hora del centro de México)";
  if (!b.window5h.resetsAt) return "en unas horas";
  const hhmm = new Date(b.window5h.resetsAt).toLocaleTimeString("es-MX", { timeZone: "America/Mexico_City", hour: "2-digit", minute: "2-digit", hour12: false });
  return `a las ${hhmm} (hora del centro de México)`;
}

// --- Avisos (inyectables para las pruebas) ---

type Notifiers = {
  alert: (type: string, message: string) => unknown;
  owner: (to: string, kind: "warn" | "reached", d: { domain: string; pct: number; hasAgentAddon: boolean }) => unknown;
};
const defaultNotifiers: Notifiers = {
  alert: (type, message) => sendAlert(type, message).catch(() => false),
  owner: (to, kind, d) => sendTemplate(to, kind === "warn" ? agentQuotaWarning(d) : agentQuotaReached(d)).catch(() => ""),
};
let notifiers = defaultNotifiers;
export function setAgentQuotaNotifiers(n: Partial<Notifiers> | null): void {
  notifiers = n ? { ...defaultNotifiers, ...n } : defaultNotifiers;
}

const CLAIM_WEEK_DAYS = 10;

function notifyThresholds(b: AgentBudget): void {
  const name = () => getDomain(b.domainId)?.domain ?? b.domainId;
  if (b.uncapped) {
    const month = new Date().toISOString().slice(0, 7);
    const spent = monthCostUsd(b.domainId);
    if (spent > UNCAPPED_ALERT_MONTH_USD && claimOnce("agent-uncapped-month", `${b.domainId}:${month}`)) {
      notifiers.alert(`agent-uncapped:${b.domainId}`, `Mascarito en ${name()} (dominio de la casa, sin tope) ya gastó $${spent.toFixed(2)} USD en ${month}, arriba de $${UNCAPPED_ALERT_MONTH_USD}.`);
    }
    return;
  }
  const key = `${b.domainId}:${b.week.key}`;
  if (b.week.pct < 80) return;
  const reached = b.week.pct >= 100;
  if (reached && claimOnce("agent-week-reached-team", key, CLAIM_WEEK_DAYS)) {
    log("warn", "assistant", "Agente en su tope de la semana", { domainId: b.domainId, costUsd: b.week.costUsd, limitUsd: b.week.limitUsd });
    notifiers.alert(`agent-week:${b.domainId}`,
      `Mascarito llegó a su tope de la semana ${b.week.key} en ${name()}: $${b.week.costUsd.toFixed(2)} de $${b.week.limitUsd.toFixed(2)} USD (add-on: ${b.hasAgentAddon ? "sí" : "no"}). ${b.threads} hilos, ${b.actions} acciones.`);
  }
  if (!claimOnce(reached ? "agent-week-reached" : "agent-week-warn", key, CLAIM_WEEK_DAYS)) return;
  // Si salta directo al 100 %, el aviso del 80 % ya no tiene caso.
  if (reached) claimOnce("agent-week-warn", key, CLAIM_WEEK_DAYS);
  const domain = getDomain(b.domainId);
  if (!domain) return;
  notifiers.owner(domain.ownerEmail, reached ? "reached" : "warn", { domain: domain.domain, pct: b.week.pct, hasAgentAddon: b.hasAgentAddon });
}

/** Lo que ve el panel y el dock: porcentajes y fechas. El costo en USD sólo para admins. */
export function agentUsageView(b: AgentBudget, admin: boolean): Record<string, unknown> {
  return {
    window5h: { pct: b.window5h.pct, resetsAt: b.window5h.resetsAt },
    week: { pct: b.week.pct, resetsAt: b.week.resetsAt },
    threads: b.threads,
    actions: b.actions,
    hasAgentAddon: b.hasAgentAddon,
    uncapped: b.uncapped,
    ...(admin ? { costUsd: { window5h: b.window5h.costUsd, week: b.week.costUsd, weekLimit: b.week.limitUsd, window5hLimit: b.window5h.limitUsd } } : {}),
  };
}
