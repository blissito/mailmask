// Partitura del comercial semanal de MailMask, semana 42 · v2 «la cortina» (vertical 1080×1920).
// La voz manda: cada animación se ancla a la palabra que la nombra (voice/lines.json, whisper large-v3)
// y cada escena, ya completa, se sostiene antes de la cortinilla.
import { readFileSync, writeFileSync } from "node:fs";

const LINES = JSON.parse(readFileSync(new URL("./voice/lines.json", import.meta.url)));
const L = Object.fromEntries(LINES.map((l) => [l.scene, l]));
const HOLD = 1.0, WIPE = 0.65, R = (x) => +x.toFixed(3);
const norm = (s) => s.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]/g, "");

const DEF = [
  { id: "hook", lines: [["hookA", 0.15], ["hookB", 0.25]] },
  { id: "web", lines: [["webA", 0.55], ["webB", 0.25], ["apply", 0.3]] },
  { id: "cierre", lines: [["cierre", 0.5], ["cta", 0.35]], last: true },
];
const VOICE = {};
const W = (line, which, edge = "s") => {
  const ws = L[line].words;
  const w = typeof which === "number" ? ws[which] : ws.find((x) => norm(x.w).startsWith(norm(which)));
  if (!w) throw new Error(`palabra «${which}» no está en ${line}`);
  return R(VOICE[line] + (edge === "s" ? w.s : w.e));
};
const ANIM = {
  hook: () => ({ env: W("hookA", "correo"), flag: W("hookA", "dominio"), shake: W("hookB", "cortina"), sign: W("hookB", "abajo") }),
  web: (s) => ({ card: s.t0, r0: W("webA", "dice"), r1: W("webA", "lleva"), r2: W("webA", "parte"),
                 vercel: W("webB", "vercel"), netlify: W("webB", "netlify"), easybits: W("webB", "easybits"),
                 tap: W("webB", "easybits", "e") + 0.1, preview: W("webB", "antes"),
                 apply: W("apply", "aplicar"), done: W("apply", "registros") }),
  cierre: (s) => ({ card: s.t0, up: W("cierre", "pagina"), shop: W("cierre", "misma"), env: W("cierre", "direccion"),
                    cta: W("cta", "sube"), url: W("cta", "mailmask") }),
};
let t0 = 0; const SCENES = []; const T = {};
for (const d of DEF) {
  let cur = t0;
  d.lines.forEach(([name, gap]) => { VOICE[name] = R(cur + gap); cur = VOICE[name] + L[name].dur; });
  const a = ANIM[d.id]({ t0 });
  const lastAnim = Math.max(...Object.values(a));
  const voiceEnd = Math.max(...d.lines.map(([n]) => VOICE[n] + L[n].words.at(-1).e));
  const t1 = d.last ? R(Math.max(voiceEnd + 2.4, lastAnim + 2.6)) : R(Math.max(voiceEnd + 0.75, lastAnim + HOLD + WIPE));
  for (const [k, v] of Object.entries(a)) T[`${d.id}.${k}`] = R(v);
  SCENES.push({ id: d.id, t0, t1 });
  t0 = t1;
}
const DURATION = t0;
const SC = Object.fromEntries(SCENES.map((s) => [s.id, s]));
T.words = LINES.map((l) => ({ line: l.scene, words: l.words.map((w) => ({ w: w.w, s: R(VOICE[l.scene] + w.s), e: R(VOICE[l.scene] + w.e) })) }));

// ---- cortinillas: dos de WebGPU (celdas que crecen desde el centro) y una de rebanadas; el glifo sella el corte ----
// gpu: cubre de c−0.65 a c−0.15, se sostiene con el glifo encima y descubre de c+0.05 a c+0.5
T.cuts = [
  { id: "web", kind: "gpu", c: SC.web.t0, glyph: "www", seed: 3 },
  { id: "cierre", kind: "gpu", c: SC.cierre.t0, glyph: "mask", seed: 11 },
].map((x) => ({ ...x, sealAt: R(x.c - 0.28) }));

// ---- efectos: uno por animación, nunca el mismo dos veces seguidas ----
const sfx = [];
const fx = (t, file, gain = 0.7) => sfx.push({ t: R(Math.max(0, t)), file, gain });
const t = (k) => T[k];
fx(t("hook.env"), "paper", 0.6); fx(t("hook.flag"), "pin", 0.5); fx(t("hook.shake"), "block"); fx(t("hook.sign"), "turn", 0.5);
fx(t("web.card"), "card", 0.6);
["r0", "r1", "r2"].forEach((k, i) => fx(t("web." + k), i % 2 ? "tick" : "pop", 0.6));
[["vercel", "8bit-blip"], ["netlify", "pop"], ["easybits", "8bit-blip"]].forEach(([k, f]) => fx(t("web." + k), f, 0.55));
fx(t("web.tap"), "tick", 0.7); fx(t("web.preview"), "paper", 0.6); fx(t("web.apply"), "pin", 0.6); fx(t("web.done"), "8bit-coin", 0.5);
fx(t("cierre.card"), "land", 0.6);
// la cortina sube 0.9 s: traqueteo de lámina (clics alternados) sobre un riser que dura lo mismo
fx(t("cierre.up"), "riser", 0.35);
T["cierre.rattle"] = [0, 1, 2, 3, 4, 5].map((i) => R(t("cierre.up") + 0.05 + i * 0.14));
T["cierre.rattle"].forEach((x, i) => fx(x, i % 2 ? "block" : "tick", i % 2 ? 0.3 : 0.5));
fx(t("cierre.shop"), "pop", 0.6); fx(t("cierre.env"), "ding", 0.5); fx(t("cierre.cta"), "8bit-pickup", 0.5); fx(t("cierre.url"), "coin", 0.5);
const CUTFX = { web: ["riser", "hit-sub"], cierre: ["whoosh-fly", "hit-low"] };
for (const c of T.cuts) { const [sw, hit] = CUTFX[c.id]; fx(c.c - 0.65, sw, 0.5); fx(c.sealAt + 0.3 / 2.8, hit, 0.6); }
sfx.sort((a, b) => a.t - b.t);
for (let i = 1; i < sfx.length; i++) if (sfx[i].file === sfx[i - 1].file) throw new Error(`efecto repetido seguido: ${sfx[i].file} en ${sfx[i].t}`);

const voice = LINES.map((l) => ({ t: VOICE[l.scene], file: l.file }));
const music = { drop: SC.cierre.t0 };
writeFileSync(new URL("./score.gen.json", import.meta.url), JSON.stringify({ duration: DURATION, scenes: SCENES, T, sfx, voice, music }, null, 1));
writeFileSync(new URL("./score.gen.js", import.meta.url), `// generado por score.mjs\nwindow.SCORE = ${JSON.stringify({ duration: DURATION, scenes: SCENES, T })};\n`);
console.log(`${DURATION} s · ${sfx.length} efectos`);
console.log(SCENES.map((s) => `${s.id} ${s.t0}–${s.t1}`).join("\n"));
