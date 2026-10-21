// Partitura del short «Crea un correo nuevo en el dominio que ya tienes» (vertical 1080×1920).
// La voz manda: cada animación se ancla a la palabra que la nombra (voice/lines.json, whisper large-v3)
// y cada escena, ya completa, se sostiene antes de la cortinilla (zoom-punch por un glifo).
import { readFileSync, writeFileSync } from "node:fs";

const LINES = JSON.parse(readFileSync(new URL("./voice/lines.json", import.meta.url)));
const L = Object.fromEntries(LINES.map((l) => [l.scene, l]));
const HOLD = 0.7, CUT = 0.45, R = (x) => +x.toFixed(3);
const norm = (s) => s.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9@]/g, "");

// [línea, pausa antes de la línea]
const DEF = [
  { id: "hook", lines: [["hookA", 0.2], ["hookB", 0.12]] },
  { id: "plan", lines: [["plan1", 0.3], ["plan2", 0.25], ["plan3", 0.25]] },
  { id: "bandeja", lines: [["bandeja", 0.3]] },
  { id: "gratis", lines: [["gratis", 0.3]] },
  { id: "cierre", lines: [["cierre", 0.35], ["cta", 0.3]], last: true },
];
const VOICE = {};
const W = (line, which, edge = "s") => {
  const ws = L[line].words;
  const w = typeof which === "number" ? ws.at(which) : ws.find((x) => norm(x.w).startsWith(norm(which)));
  if (!w) throw new Error(`palabra «${which}» no está en ${line}`);
  return R(VOICE[line] + (edge === "s" ? w.s : w.e));
};
const ANIM = {
  hook: () => ({ underline: W("hookA", "tuestudio"), quote: W("hookA", "tuestudio") + 0.2, circle: W("hookB", "gmail"), stamp: W("hookB", -1, "e") + 0.1 }),
  plan: (s) => ({ panel: s.t0, typeA: W("plan1", "dominio"), typeB: W("plan1", "mailmask"), tags: W("plan2", "nameservers"), checks: W("plan2", "ahora"), agent: W("plan2", "asistente"),
                  dns: W("plan2", "registros"), mail: W("plan2", "correos"), web: W("plan2", "landing"), agentOk: W("plan2", -1, "e"),
                  badge: W("plan3", "hola@") }),
  bandeja: (s) => ({ tray: s.t0, env: W("bandeja", "escribe"), to: W("bandeja", "hola@"), reply: W("bandeja", "respondes"), plane: W("bandeja", "bandeja") }),
  gratis: (s) => ({ ring: s.t0, tag: W("gratis", "gratis"), badges: W("gratis", "hasta"), badgesEnd: W("gratis", "direcciones", "e") }),
  cierre: (s) => ({ card: s.t0, rewrite: W("cierre", "correo"), underline: W("cierre", "tuestudio"), sticker: W("cierre", "agente"),
                    cta: W("cta", "crea"), url: W("cta", "mailmask"), postit: W("cta", -1, "e") + 0.55 }),
};
let t0 = 0; const SCENES = []; const T = {};
for (const d of DEF) {
  let cur = t0;
  d.lines.forEach(([name, gap]) => { VOICE[name] = R(cur + gap); cur = VOICE[name] + L[name].words.at(-1).e; });
  const a = ANIM[d.id]({ t0 });
  const lastAnim = Math.max(...Object.values(a));
  const voiceEnd = Math.max(...d.lines.map(([n]) => VOICE[n] + L[n].words.at(-1).e));
  const t1 = d.last ? R(Math.max(voiceEnd + 2.4, lastAnim + 1.9)) : R(Math.max(voiceEnd + 0.4, lastAnim + HOLD) + CUT);
  for (const [k, v] of Object.entries(a)) T[`${d.id}.${k}`] = R(v);
  SCENES.push({ id: d.id, t0, t1 });
  t0 = t1;
}
const DURATION = t0;
const SC = Object.fromEntries(SCENES.map((s) => [s.id, s]));
T.words = LINES.map((l) => ({ line: l.scene, words: l.words.map((w) => ({ w: w.w, s: R(VOICE[l.scene] + w.s), e: R(VOICE[l.scene] + w.e) })) }));
// letras de «tuestudio.mx» repartidas entre «dominio» y «MailMask»
T["plan.letters"] = [...Array(12)].map((_, i) => R(T["plan.typeA"] + (T["plan.typeB"] - T["plan.typeA"]) * i / 11));

// ---- efectos: uno por animación, nunca el mismo dos veces seguidas ----
// los que no hay en el catálogo CC0 (plumón, tecla, cinta, tintineo) los sintetiza sfx.py con la duración del movimiento
const sfx = [];
// cada efecto lleva qué se ve (para SFX-LISTA.md); burbujas y swings sólo donde no hay un objeto con sonido propio
let WHAT = "";
const fx = (t, file, gain = 0.7, dur) => sfx.push({ t: R(Math.max(0, t)), file, gain, ...(dur ? { dur } : {}), what: WHAT });
const on = (what) => (WHAT = what);
const t = (k) => T[k];
on("gancho: tuestudio.mx late en la tarjeta"); fx(t("hook.underline"), "bubble", 0.6);
on("gancho: la cotización se levanta (papel)"); fx(t("hook.quote"), "paper", 0.55);
on("gancho: gmail.com se enciende en rojo (tarjeta)"); fx(t("hook.circle"), "bubble2", 0.6);
on("gancho: gmail.com se enciende en rojo (cotización)"); fx(t("hook.circle") + 0.25, "bubble3", 0.6);
on("gancho: cae el sello «¿ES REAL?»"); fx(t("hook.stamp") + 0.45 / 3, "stamp", 0.7);
on("plan: entra el panel (tarjeta)"); fx(t("plan.panel") + 0.1, "card", 0.55);
on("plan: se teclea tuestudio.mx"); T["plan.letters"].forEach((x, i) => fx(x, i % 2 ? "key2" : "key", 0.5));
on("plan: etiqueta NS con cinta"); fx(t("plan.tags"), "tape", 0.6);
on("plan: palomita de NS"); fx(t("plan.checks"), "bubble", 0.55);
on("plan: etiqueta Agente con cinta"); fx(t("plan.agent"), "tape2", 0.6);
on("plan: fichero de tarjetas (Registros DNS)"); fx(t("plan.dns") + 0.4 / 2.7, "card", 0.6); fx(t("plan.dns") + 0.3, "bubble2", 0.4);
on("plan: buzón suelta sobres (Correos nuevos)"); fx(t("plan.mail") + 0.4 / 2.7, "bubble3", 0.55); fx(t("plan.mail") + 0.35, "whoosh-short", 0.45);
on("plan: navegador se arma (Landing)"); fx(t("plan.web") + 0.4 / 2.7, "paper", 0.6); fx(t("plan.web") + 0.35, "bubble", 0.4);
on("plan: palomita del Agente"); fx(t("plan.agentOk"), "bubble2", 0.55);
on("plan: cae el gafete hola@"); fx(t("plan.badge") + 0.4 / 2.7, "bubble3", 0.65); fx(t("plan.badge") + 0.35, "jingle", 0.4, 0.6);
on("bandeja: la charola rebota"); fx(t("bandeja.tray") + 0.15, "land", 0.6);
on("bandeja: cae el sobre a la charola"); fx(t("bandeja.env") + 0.3, "paper", 0.6); fx(t("bandeja.env") + 0.42, "block", 0.35);
on("bandeja: hola@ del sobre se enciende en rojo"); fx(t("bandeja.to"), "bubble", 0.5);
on("bandeja: se escribe la respuesta"); fx(t("bandeja.reply"), "pencil", 0.55, 1.1);
on("bandeja: sale el avión de papel"); fx(t("bandeja.plane"), "whoosh-short", 0.55); fx(t("bandeja.plane") + 0.5, "8bit-pickup", 0.4);
on("gratis: gira el aro"); fx(t("gratis.ring") + 0.1, "jingle", 0.45, 0.5);
on("gratis: cae la etiqueta $0"); fx(t("gratis.tag"), "turn", 0.5);
T["gratis.badgeAt"] = [0, 1, 2, 3, 4].map((i) => R(t("gratis.badges") + (t("gratis.badgesEnd") - 0.3 - t("gratis.badges")) * i / 4));
on("gratis: gafetes al aro"); T["gratis.badgeAt"].forEach((x, i) => fx(x + 0.1, i % 2 ? "jingle2" : "jingle", 0.35 + i * 0.04, 0.35 + i * 0.03));
on("cierre: entra la tarjeta"); fx(t("cierre.card") + 0.1, "card", 0.5);
on("cierre: el correo viejo se va y entra hola@"); fx(t("cierre.rewrite"), "whoosh-short", 0.45);
on("cierre: tuestudio.mx en rojo en los dos renglones"); fx(t("cierre.underline"), "bubble2", 0.5); fx(t("cierre.underline") + 0.15, "bubble3", 0.45);
on("cierre: se pega la calcomanía"); fx(t("cierre.sticker") + 0.4 / 3, "stamp", 0.65);
on("cierre: botón «Crea tu correo gratis»"); fx(t("cierre.cta") + 0.35 / 3.2, "bubble", 0.65);
on("cierre: aparece la URL"); fx(t("cierre.url"), "ding", 0.5);
on("cierre: se pega el pósit"); fx(t("cierre.postit"), "slap", 0.6);
// cortinillas: riser mientras la cámara se clava en el glifo; golpe cuando el sello cae (back.out(1.8): impacto a 1/2.8 del tween)
const CUTS = { plan: ["riser", "hit-sub"], bandeja: ["whoosh-fly", "hit-low"], gratis: ["riser", "hit-sub"], cierre: ["whoosh-fly", "glitch"] };
T.seal = {};
for (const [id, [sw, hit]] of Object.entries(CUTS)) {
  const c = SC[id].t0, sealAt = R(c - 0.16);
  T.seal[id] = sealAt;
  on(`cortinilla hacia ${id}`); fx(c - 0.5, sw, 0.5); fx(sealAt + 0.3 / 2.8, hit, 0.6);
}
sfx.sort((a, b) => a.t - b.t);
for (let i = 1; i < sfx.length; i++) if (sfx[i].file === sfx[i - 1].file) throw new Error(`efecto repetido seguido: ${sfx[i].file} en ${sfx[i].t}`);

const voice = LINES.map((l) => ({ t: VOICE[l.scene], file: l.file }));
const music = { drop: T["cierre.cta"] };
writeFileSync(new URL("./score.gen.json", import.meta.url), JSON.stringify({ duration: DURATION, scenes: SCENES, T, sfx, voice, music }, null, 1));
writeFileSync(new URL("./score.gen.js", import.meta.url), `// generado por score.mjs\nwindow.SCORE = ${JSON.stringify({ duration: DURATION, scenes: SCENES, T })};\n`);
// el renderizador lee data-duration estático: se reescribe aquí para que nunca quede viejo
const IDX = new URL("./index.html", import.meta.url);
writeFileSync(IDX, readFileSync(IDX, "utf8").replace(/(id="root"[^>]*data-duration=")[\d.]+"/, `$1${DURATION}"`));
const NEW = new Set(["bubble", "bubble2", "bubble3", "swing", "swing2"]);
writeFileSync(new URL("./SFX-LISTA.md", import.meta.url), `# Efectos de sonido (generado por score.mjs)\n\nNuevo = burbuja o swing que entró el 21-oct; original = el que ya estaba.\n\n| t (s) | Qué se ve | Sonido | Original / nuevo |\n|---|---|---|---|\n` +
  sfx.map((e) => `| ${e.t.toFixed(2)} | ${e.what} | ${e.file} | ${NEW.has(e.file) ? "nuevo" : "original"} |`).join("\n") + "\n");
console.log(`${DURATION} s · ${sfx.length} efectos`);
console.log(SCENES.map((s) => `${s.id} ${s.t0}–${s.t1}`).join("\n"));
