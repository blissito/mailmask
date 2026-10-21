// Partitura del short «Buzones» de MailMask (vertical 1080×1920).
// La voz manda: cada animación se ancla a la palabra que la nombra (voice/lines.json, whisper large-v3)
// y cada escena, ya completa, se sostiene antes de la cortinilla.
import { readFileSync, writeFileSync } from "node:fs";

const LINES = JSON.parse(readFileSync(new URL("./voice/lines.json", import.meta.url)));
const L = Object.fromEntries(LINES.map((l) => [l.scene, l]));
const HOLD = 1.0, WIPE = 0.6, R = (x) => +x.toFixed(3);
const norm = (s) => s.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]/g, "");

const DEF = [
  { id: "hook", lines: [["hookA", 0.15], ["hookB", 0.3]] },
  { id: "buzon", lines: [["buzon", 0.5]] },
  { id: "ilim", lines: [["ilim", 0.45]] },
  { id: "cierre", lines: [["cierreA", 0.45], ["cierreB", 0.25], ["cta", 0.45]], last: true },
];
const VOICE = {};
const W = (line, which, edge = "s") => {
  const ws = L[line].words;
  const w = typeof which === "number" ? ws[which] : ws.find((x) => norm(x.w).startsWith(norm(which)));
  if (!w) throw new Error(`palabra «${which}» no está en ${line}`);
  return R(VOICE[line] + (edge === "s" ? w.s : w.e));
};
const ANIM = {
  hook: (s) => ({ wobble: s.t0 + 0.3, people: W("hookA", "personas"), r1: W("hookB", "975"), total: W("hookB", "975", "e"),
                  ours: W("hookB", "mes") + 0.35 }),
  buzon: (s) => ({ card: s.t0, brand: W("buzon", "mailmask"), dom: W("buzon", "dominio"), apple: W("buzon", "apple"), outlook: W("buzon", "outlook"),
                   phone: W("buzon", "telefono") }),
  ilim: (s) => ({ a0: s.t0 + 0.1, a1: W("ilim", "buzones") + 0.25, a2: W("ilim", "ilimitados"), a3: W("ilim", "ilimitados", "e") - 0.15,
                  a4: W("ilim", "suma"), a5: W("ilim", "quien"), tag: W("ilim", "pagar") }),
  cierre: (s) => ({ card: s.t0, belt: W("cierreA", "precio"), price: W("cierreB", "99"), cta: W("cta", "activalo"), url: W("cta", "mailmask") }),
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

// ---- efectos: uno por animación, nunca el mismo dos veces seguidas ----
const sfx = [];
const fx = (t, file, gain = 0.7) => sfx.push({ t: R(Math.max(0, t)), file, gain });
const t = (k) => T[k];
fx(t("hook.wobble"), "paper", 0.6); fx(t("hook.people"), "pop");
// cuenta $195 → $975 en cinco pasos mientras la voz dice «novecientos setenta y cinco»
T["hook.steps"] = [0, 1, 2, 3, 4].map((i) => R(t("hook.r1") + (t("hook.total") - 0.12 - t("hook.r1")) * i / 4));
T["hook.steps"].forEach((x, i) => fx(x, i % 2 ? "8bit-blip" : "tick", i % 2 ? 0.45 : 0.6));
fx(t("hook.total") + 0.1, "stamp"); fx(t("hook.ours"), "coin", 0.6);
fx(t("buzon.card"), "card", 0.6); fx(t("buzon.brand"), "pop"); fx(t("buzon.dom"), "stamp", 0.5);
// el sobre vuela 0.35 s antes de que la etiqueta aparezca
[["apple", "8bit-blip"], ["outlook", "pop"], ["phone", "ding"]].forEach(([k, f]) => { fx(t("buzon." + k) - 0.35, "whoosh-short", 0.45); fx(t("buzon." + k), f, 0.6); });
["a0", "a1", "a2", "a3", "a4", "a5"].forEach((k, i) => fx(t("ilim." + k), i % 2 ? "tick" : "pop", i % 2 ? 0.55 : 0.6));
fx(t("ilim.tag"), "8bit-coin", 0.5); fx(t("ilim.tag") + 0.5, "turn", 0.4);
fx(t("cierre.card"), "land", 0.6); fx(t("cierre.belt"), "pin"); fx(t("cierre.belt") + 0.08, "pop", 0.5); fx(t("cierre.price") + 0.1, "stamp"); fx(t("cierre.cta"), "8bit-pickup", 0.5); fx(t("cierre.url"), "tick", 0.6);
// cortinillas: whoosh/riser mientras cierran; golpe cuando el glifo sella (back.out(1.8): impacto a 1/(s+1) del tween)
const CUTS = { buzon: ["whoosh-fly", "hit-sub"], ilim: ["riser", "hit-low"], cierre: ["whoosh-fly", "hit-sub"] };
T.seal = {};
for (const [id, [sw, hit]] of Object.entries(CUTS)) {
  const c = SC[id].t0, sealAt = R(c - 0.2);
  T.seal[id] = sealAt;
  fx(c - 0.62, sw, 0.5); fx(sealAt + 0.3 / 2.8, hit, 0.6);
}
sfx.sort((a, b) => a.t - b.t);
for (let i = 1; i < sfx.length; i++) if (sfx[i].file === sfx[i - 1].file) throw new Error(`efecto repetido seguido: ${sfx[i].file} en ${sfx[i].t}`);

const voice = LINES.map((l) => ({ t: VOICE[l.scene], file: l.file }));
const music = { drop: SC.cierre.t0 };
writeFileSync(new URL("./score.gen.json", import.meta.url), JSON.stringify({ duration: DURATION, scenes: SCENES, T, sfx, voice, music }, null, 1));
writeFileSync(new URL("./score.gen.js", import.meta.url), `// generado por score.mjs\nwindow.SCORE = ${JSON.stringify({ duration: DURATION, scenes: SCENES, T })};\n`);
console.log(`${DURATION} s · ${sfx.length} efectos`);
console.log(SCENES.map((s) => `${s.id} ${s.t0}–${s.t1}`).join("\n"));
