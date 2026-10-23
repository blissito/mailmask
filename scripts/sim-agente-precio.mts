// Simula un mes de «Mascarito en tu correo» sobre 10,000 dominios para comparar opciones de precio.
// Determinista con --seed. Parámetros con fuente en la investigación del 22-oct-2026 (ver el plan y la página
// «Precio de Mascarito»); [E] = estimación. Uso: npx tsx scripts/sim-agente-precio.mts [--seed 1] [--csv out.csv]
import { writeFileSync } from "node:fs";

export type Level = "bajo" | "medio" | "alto";
export type Scenario = { name: string; level: Level; classifyUsd: number; draftUsd: number; ghostyMult: number; peak: number };
export type PriceOption = { name: string; tier: "borradores" | "automatico"; baseMxn: number; included: number; blockMxn: number; blockSize: number };

// Correos de PERSONAS al mes por dominio (mediana por segmento) y mezcla de segmentos [E].
const SEGMENTS = [
  { name: "freelancer", share: 0.5, median: { bajo: 8, medio: 20, alto: 40 } },
  { name: "pyme", share: 0.35, median: { bajo: 20, medio: 60, alto: 120 } },
  { name: "pyme con equipo", share: 0.15, median: { bajo: 150, medio: 300, alto: 600 } },
];
const P = {
  nonHuman: { bajo: 0.5, medio: 0.7, alto: 0.87 }, // Hostinger [S]
  repetitive: { bajo: 0.2, medio: 0.35, alto: 0.6 }, // Chatarmin [S]
  handoff: { bajo: 0.25, medio: 0.4, alto: 0.5 }, // [E]
  gatesCatchNonHuman: 0.8, // las puertas (listas, Auto-Submitted, noreply, DMARC) frenan la mayoría sin modelo [E]
  assignedNonHuman: 0.4, // sólo direcciones asignadas (hola@, ventas@): llega ~40 % de los boletines y avisos [E]
  draftAsk: 0.4, // de los hilos que no son plantilla ni traspaso, en cuántos alguien pide borrador [E]
  sigma: 0.9, // dispersión log-normal: p90/mediana ≈ 3.2 [E]
  sesUsdPerMsg: 0.0001, // SES $0.10 por 1,000 envíos
};
export const USD_MXN = Number(process.env.USD_MXN ?? 18);

// Se cobran HILOS DE PERSONAS atendidos (lo automático y el spam no cuentan). Al tope, quien no compra bloque
// baja a modo borrador; aquí se asume que quien se pasa compra el bloque (ingreso máximo, costo completo).
export const OPTIONS: PriceOption[] = [
  { name: "Borradores · $99 · 300 hilos + bloques de 500 por $99", tier: "borradores", baseMxn: 99, included: 300, blockMxn: 99, blockSize: 500 },
  { name: "Automático · $199 · 300 hilos + bloques de 500 por $99", tier: "automatico", baseMxn: 199, included: 300, blockMxn: 99, blockSize: 500 },
];
// Medido en producción con Haiku 5.5 (22-oct): clasificar $0.0017/turno, redactar un borrador ~$0.005/turno,
// ambos con caché alto. Con muchos clientes el caché rinde menos: ×1.5 base, ×3 pesimista [E].
// Ghosty partner: tarifa desconocida, se barre 0× / 1× / 3× del costo del modelo.
export const SCENARIOS: Scenario[] = [
  { name: "optimista", level: "bajo", classifyUsd: 0.0017, draftUsd: 0.005, ghostyMult: 0, peak: 1.2 },
  { name: "base", level: "medio", classifyUsd: 0.0026, draftUsd: 0.0075, ghostyMult: 1, peak: 1.5 },
  { name: "pesimista", level: "alto", classifyUsd: 0.0051, draftUsd: 0.015, ghostyMult: 3, peak: 2 },
];

function rng(seed: number) { // mulberry32
  return () => { seed |= 0; seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const normal = (r: () => number) => Math.sqrt(-2 * Math.log(1 - r())) * Math.cos(2 * Math.PI * r());

/** Un dominio, un mes: clasificaciones (siempre, para priorizar), borradores (a pedido), envíos y hilos cobrables. */
export function domainMonth(humanMails: number, level: Level, tier: PriceOption["tier"] = "borradores") {
  const nonHuman = humanMails * P.nonHuman[level] / (1 - P.nonHuman[level]) * P.assignedNonHuman;
  const classify = humanMails + nonHuman * (1 - P.gatesCatchNonHuman); // cada hilo que pasa las puertas se clasifica
  const repetitive = humanMails * P.repetitive[level];
  const rest = humanMails * (1 - P.repetitive[level]) * (1 - P.handoff[level]);
  // borradores: la plantilla también es un borrador que alguien pide; automático: la plantilla sale sola
  const drafts = tier === "automatico" ? rest * P.draftAsk : (repetitive + rest) * P.draftAsk;
  const sends = tier === "automatico" ? repetitive : 0; // los borradores aprobados salen como respuesta de la Bandeja
  return { classify, drafts, responses: drafts + sends, sends, billable: humanMails };
}

export function simulate(opt: PriceOption, sc: Scenario, seed = 1, n = 10_000) {
  const r = rng(seed);
  let revenue = 0, cost = 0, buyBlock = 0, under10 = 0;
  for (let i = 0; i < n; i++) {
    let x = r(), seg = SEGMENTS[0];
    for (const s of SEGMENTS) { if (x < s.share) { seg = s; break; } x -= s.share; }
    const human = Math.max(0, seg.median[sc.level] * Math.exp(P.sigma * normal(r))) * (r() < 1 / 12 ? sc.peak : 1);
    const m = domainMonth(human, sc.level, opt.tier);
    const blocks = Math.max(0, Math.ceil((m.billable - opt.included) / opt.blockSize));
    revenue += opt.baseMxn + blocks * opt.blockMxn;
    cost += ((m.classify * sc.classifyUsd + m.drafts * sc.draftUsd) * (1 + sc.ghostyMult) + m.sends * P.sesUsdPerMsg) * USD_MXN;
    if (blocks > 0) buyBlock++;
    if (m.billable < opt.included * 0.1) under10++;
  }
  return { option: opt.name, scenario: sc.name, revenuePerDomain: revenue / n, costPerDomain: cost / n,
    costShare: cost / revenue, margin: 1 - cost / revenue, buyBlockPct: buyBlock / n, under10Pct: under10 / n };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const seed = Number(process.argv[process.argv.indexOf("--seed") + 1] || 1);
  const rows = OPTIONS.flatMap((o) => SCENARIOS.map((s) => simulate(o, s, seed)));
  const pct = (v: number) => `${(v * 100).toFixed(1)} %`;
  console.table(rows.map((x) => ({ opción: x.option, escenario: x.scenario, "ingreso/dominio": x.revenuePerDomain.toFixed(0),
    "costo/dominio": x.costPerDomain.toFixed(2), "costo/ingreso": pct(x.costShare), "compra bloque": pct(x.buyBlockPct), "usa <10 %": pct(x.under10Pct) })));
  const csvAt = process.argv.indexOf("--csv");
  if (csvAt > 0) writeFileSync(process.argv[csvAt + 1], ["option,scenario,revenue,cost,costShare,buyBlock,under10",
    ...rows.map((x) => [JSON.stringify(x.option), x.scenario, x.revenuePerDomain.toFixed(2), x.costPerDomain.toFixed(4), x.costShare.toFixed(4), x.buyBlockPct.toFixed(4), x.under10Pct.toFixed(4)].join(","))].join("\n"));
}
