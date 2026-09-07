// Generates index.html for the MailMask short 01. Style: "goodies" (two panels per
// scene, column wipe on cuts, frame 0 complete) with the MailMask skin.
import fs from "node:fs";
import { voice, dur, start, TOTAL, BREATH, at, CUTS } from "./timing.mjs";

const BG = "#faf6ee", ELEV = "#fffdf9", INSET = "#f2ecdf", LINE = "#e4dccd";
const FG = "#1c1917", MUTED = "#57534e", SUBTLE = "#78716c";
const RED = "#d7263d", RED_DARK = "#a0182c", GOLD = "#f2b705", GREEN = "#059669";

const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");
const mask = fs.readFileSync(new URL("./assets/mask.svg", import.meta.url), "utf8").replace(/<\?xml[^>]*>/, "");
const f = (n) => n.toFixed(3);

const WIPE_IN = 0.34, WIPE_OUT = 0.36, HOLD = 0.12;

// Karaoke: short lines (max ~22 chars, 4 words), one at a time; the line lives from its first word to the next line
const MAXC = 22, MAXW = 4;
const lines = [];
voice.forEach((words, i) => {
  let cur = [];
  const flush = () => { if (cur.length) { lines.push({ scene: i, words: cur }); cur = []; } };
  words.forEach((w) => {
    const len = cur.reduce((n, x) => n + x.text.length + 1, 0) + w.text.length;
    if (cur.length && (len > MAXC || cur.length >= MAXW || /[.,:]$/.test(cur[cur.length - 1].text))) flush();
    cur.push(w);
  });
  flush();
});
// Orphans: a lone short word ("a", "un", "en") joins the previous line of the same scene
for (let k = lines.length - 1; k > 0; k--) {
  const l = lines[k], prev = lines[k - 1];
  if (l.words.length === 1 && l.words[0].text.length <= 3 && prev.scene === l.scene) { prev.words.push(...l.words); lines.splice(k, 1); }
}
// And a line that ends in a short function word pushes it to the next line
for (let k = 0; k < lines.length - 1; k++) {
  const l = lines[k], next = lines[k + 1];
  const last = l.words[l.words.length - 1];
  if (l.words.length > 2 && next.scene === l.scene && /^(a|un|una|en|de|y|por|el|la|tu|sin|con)$/i.test(last.text)) { l.words.pop(); next.words.unshift(last); }
}
lines.forEach((l, k) => {
  const base = start[l.scene] + BREATH;
  l.s = base + l.words[0].start - 0.12;
  const next = lines[k + 1];
  l.e = next && next.scene === l.scene ? base + next.words[0].start - 0.12 : base + l.words[l.words.length - 1].end + 0.9;
});
const caps = lines.map((l, k) => {
  const spans = l.words.map((w, j) => `<span class="w" id="w${k}_${j}">${esc(w.text)}</span>`).join(" ");
  return `<div class="clip cap" id="cap${k}" data-start="${f(l.s)}" data-duration="${f(l.e - l.s)}"><div class="capin">${spans}</div></div>`;
}).join("\n      ");

const audio = voice.map((_, i) =>
  `<audio id="v${i}" src="assets/voice/em_santa/s${i}.wav" data-start="${f(start[i] + BREATH)}" data-duration="${f(dur[i])}"></audio>`).join("\n      ");

const scene = (i, a, b) => {
  const s = start[i], d = (i < 4 ? start[i + 1] : TOTAL) - s;
  return `<div class="clip scene" id="s${i}" data-start="${f(s)}" data-duration="${f(d)}">
        <div class="panel" id="s${i}-a">${a}</div>
        <div class="panel b" id="s${i}-b">${b}</div>
      </div>`;
};

const mail = (cls, app, from, to, extra = "") => `
  <div class="mail ${cls}">
    <div class="mailbar"><i></i><i></i><i></i><span class="app">${app}</span><span>· Nuevo mensaje</span></div>
    <div class="fromline"><b>De</b><span class="from">${esc(from)}</span></div>
    <div class="row"><b>Para</b><span>${esc(to)}</span></div>
    <div class="row"><b>Asunto</b><span>Cotización sitio web</span></div>
    <div class="body"><i style="width:82%"></i><i style="width:64%"></i><i style="width:71%"></i></div>
    ${extra}
  </div>`;

const html = `<!doctype html>
<html lang="es" data-resolution="portrait">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=1080, height=1920" />
    <link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wdth,wght@12..96,96,800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet" />
    <script src="https://cdn.jsdelivr.net/npm/gsap@3.14.2/dist/gsap.min.js"></script>
    <style>
      * { margin: 0; padding: 0; box-sizing: border-box; }
      html, body { width: 1080px; height: 1920px; overflow: hidden; background: ${BG}; }
      body { font-family: "Bricolage Grotesque", system-ui, sans-serif; font-weight: 800; color: ${FG}; }
      .clip { position: absolute; inset: 0; }
      .mono { font-family: "JetBrains Mono", monospace; font-weight: 700; }

      /* background: cream, soft grid moving one cell, two breathing blobs, vignette */
      #bgfill { position: absolute; inset: 0; background: ${BG}; }
      #grid { position: absolute; left: -60px; top: -60px; width: 1200px; height: 2040px; opacity: .55;
        background-image: linear-gradient(${LINE} 2px, transparent 2px), linear-gradient(90deg, ${LINE} 2px, transparent 2px); background-size: 60px 60px; }
      .blob { position: absolute; width: 900px; height: 900px; border-radius: 50%; filter: blur(120px); opacity: .22; }
      #blob1 { left: -300px; top: 100px; background: ${RED}; }
      #blob2 { left: 500px; top: 1100px; background: ${GOLD}; }
      #vig { position: absolute; inset: 0; background: radial-gradient(ellipse at 50% 48%, rgba(250,246,238,0) 45%, rgba(60,30,20,.16) 100%); }

      /* scenes: two panels, vertically centred */
      .scene { z-index: 10; }
      .panel { position: absolute; inset: 0; padding: 200px 80px 660px; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; gap: 40px; }
      .panel.b { opacity: 0; }
      .kicker { font-family: "JetBrains Mono", monospace; font-weight: 700; font-size: 26px; letter-spacing: .22em; text-transform: uppercase; color: ${SUBTLE}; }
      h1 { font-size: 108px; line-height: .95; letter-spacing: -.03em; font-weight: 800; width: 920px; }
      h1 em, .big em { font-style: normal; color: ${RED}; }
      .big { font-size: 220px; line-height: .9; letter-spacing: -.04em; }
      .huge { font-size: 340px; line-height: .85; letter-spacing: -.06em; color: ${RED}; }
      .note { font-family: "JetBrains Mono", monospace; font-weight: 400; font-size: 30px; color: ${MUTED}; letter-spacing: .04em; }

      /* email card */
      .mail { width: 920px; background: ${ELEV}; border: 3px solid ${LINE}; border-radius: 28px; overflow: hidden; text-align: left; position: relative;
        box-shadow: 0 30px 60px -30px rgba(60,30,20,.3); font-family: "JetBrains Mono", monospace; font-weight: 400; font-size: 32px; color: ${FG}; }
      .mailbar { display: flex; align-items: center; gap: 12px; background: ${INSET}; border-bottom: 2px solid ${LINE}; padding: 22px 30px; font-size: 24px; color: ${MUTED}; }
      .mailbar i { width: 16px; height: 16px; border-radius: 50%; background: ${LINE}; display: block; }
      .mailbar span { margin-left: 12px; }
      .mailbar .app { font-weight: 700; font-size: 28px; color: ${FG}; margin-left: 16px; }
      .mail.old .mailbar .app { color: #c5221f; }
      .fromline { display: flex; flex-direction: column; gap: 10px; padding: 26px 34px 22px; border-bottom: 2px solid ${LINE}; }
      .fromline b { color: ${SUBTLE}; font-weight: 700; font-size: 24px; letter-spacing: .18em; text-transform: uppercase; }
      .fromline .from { font-size: 40px; font-weight: 700; letter-spacing: -.02em; }
      #gtag { position: absolute; right: 30px; top: 96px; padding: 10px 22px; background: ${INSET}; border: 3px solid ${LINE}; border-radius: 999px; font-size: 26px; font-weight: 700; color: ${MUTED}; opacity: 0; }
      .row { display: flex; gap: 24px; padding: 22px 34px; border-bottom: 2px solid ${LINE}; }
      .row b { width: 130px; color: ${SUBTLE}; font-weight: 700; }
      .body { padding: 36px 34px 44px; display: flex; flex-direction: column; gap: 18px; }
      .body i { display: block; height: 18px; border-radius: 9px; background: ${INSET}; }
      .mail.old { filter: grayscale(1); opacity: .92; }
      .mail.old .from { color: ${MUTED}; }
      .mail.old .fromline .from { color: ${FG}; }
      .mail.new { border-color: ${RED}; }
      .mail.new .from { color: ${RED}; font-weight: 700; }
      .mail.new .mailbar { background: ${RED}; color: #fff; }
      .mail.new .mailbar i { background: rgba(255,255,255,.5); }
      #circle { position: absolute; left: 395px; top: 84px; width: 190px; height: 90px; opacity: 0; }
      #stamp { position: absolute; right: 40px; bottom: 36px; padding: 10px 24px; border: 6px solid ${RED}; color: ${RED}; border-radius: 14px;
        font-family: "Bricolage Grotesque"; font-weight: 800; font-size: 46px; letter-spacing: -.02em; opacity: 0; }
      .chips { display: flex; gap: 16px; padding: 0 34px 36px; }
      .chip { font-size: 24px; font-weight: 700; color: ${GREEN}; background: rgba(16,185,129,.12); border: 2px solid rgba(5,150,105,.3); border-radius: 999px; padding: 8px 18px; }

      /* mask */
      .maskwrap { width: 420px; height: 420px; }
      .maskwrap svg { width: 100%; height: 100%; display: block; filter: drop-shadow(0 30px 40px rgba(160,24,44,.35)); }

      /* DNS rows */
      .dns { width: 920px; display: flex; flex-direction: column; gap: 18px; text-align: left; font-family: "JetBrains Mono", monospace; font-weight: 400; font-size: 34px; }
      .dns div { display: flex; align-items: center; gap: 24px; background: ${ELEV}; border: 3px solid ${LINE}; border-radius: 20px; padding: 26px 30px; }
      .dns b { width: 130px; color: ${SUBTLE}; font-weight: 700; }
      .dns span { flex: 1; color: ${FG}; }
      .dns .ok { width: 56px; height: 56px; border-radius: 50%; background: ${GREEN}; color: #fff; display: flex; align-items: center; justify-content: center; font-size: 34px; font-weight: 700; }

      /* inbox */
      .inbox { width: 920px; background: ${ELEV}; border: 3px solid ${LINE}; border-radius: 28px; overflow: hidden; text-align: left; font-family: "JetBrains Mono", monospace; font-weight: 400; font-size: 30px; box-shadow: 0 30px 60px -30px rgba(60,30,20,.3); }
      .inbox .hd { padding: 22px 30px; background: ${INSET}; border-bottom: 2px solid ${LINE}; color: ${MUTED}; font-size: 24px; letter-spacing: .18em; text-transform: uppercase; font-weight: 700; }
      .th { padding: 22px 30px; border-bottom: 2px solid ${LINE}; display: flex; justify-content: space-between; color: ${MUTED}; }
      .th.sel { background: rgba(215,38,61,.08); color: ${FG}; border-left: 8px solid ${RED}; }
      .th b { font-weight: 700; }
      .notewrap { padding: 26px 30px; display: flex; flex-direction: column; gap: 18px; }
      .inote { background: #fff4c2; border: 2px solid #f2b705; border-radius: 16px; padding: 20px 24px; font-size: 28px; color: #5a4300; }
      .assign { align-self: flex-start; font-size: 26px; font-weight: 700; color: ${RED}; border: 3px solid ${RED}; border-radius: 999px; padding: 10px 22px; }

      /* comparison */
      .cmp { display: flex; gap: 28px; width: 940px; }
      .col { flex: 1; border-radius: 28px; padding: 44px 30px; display: flex; flex-direction: column; gap: 22px; align-items: center; }
      .col .name { font-family: "JetBrains Mono"; font-size: 26px; letter-spacing: .18em; text-transform: uppercase; font-weight: 700; }
      .col .price { font-size: 72px; line-height: 1; letter-spacing: -.03em; }
      .col .sub { font-family: "JetBrains Mono"; font-weight: 400; font-size: 26px; }
      .col.g { background: ${INSET}; border: 3px solid ${LINE}; color: ${MUTED}; }
      .col.m { background: ${RED}; color: #fff; box-shadow: 0 30px 60px -30px rgba(160,24,44,.6); }
      .col.m .sub { color: rgba(255,255,255,.85); }
      #strike { position: absolute; left: 10%; top: 50%; width: 80%; height: 10px; background: ${RED}; border-radius: 5px; transform-origin: left center; }

      /* CTA */
      .btn { background: ${RED}; color: #fff; border-radius: 999px; padding: 30px 70px; font-size: 64px; letter-spacing: -.02em; box-shadow: 0 30px 60px -25px rgba(160,24,44,.7); }
      .url { font-family: "JetBrains Mono"; font-weight: 700; font-size: 52px; color: ${FG}; letter-spacing: -.02em; }

      /* karaoke */
      .cap { position: absolute; inset: auto; left: 60px; right: 60px; top: 1330px; height: 320px; z-index: 40; display: flex; align-items: center; justify-content: center; text-align: center; }
      .capin { font-size: 104px; line-height: 1.05; letter-spacing: -.03em; }
      .w { display: inline-block; color: ${SUBTLE}; opacity: .6; }

      /* wipe columns */
      #wipes { position: absolute; inset: 0; z-index: 60; pointer-events: none; }
      .colw { position: absolute; top: 0; width: 182px; height: 1920px; background: ${RED};
        background-image: linear-gradient(rgba(160,24,44,.5) 2px, transparent 2px), linear-gradient(90deg, rgba(160,24,44,.5) 2px, transparent 2px); background-size: 60px 60px; }
    </style>
  </head>
  <body>
    <div data-composition-id="mailmask-short-01" data-start="0" data-duration="${f(TOTAL)}" data-width="1080" data-height="1920" style="position:relative;width:1080px;height:1920px;overflow:hidden">
      <div class="clip" id="bg" data-start="0" data-duration="${f(TOTAL)}">
        <div id="bgfill"></div><div id="grid"></div><div class="blob" id="blob1"></div><div class="blob" id="blob2"></div><div id="vig"></div>
      </div>

      ${scene(0,
        `<div class="kicker">MailMask · correo con tu dominio</div><h1>Todavía escribes desde un <em>Gmail personal</em></h1>`,
        mail("old", "Gmail", "pedro.diseño2011@gmail.com", "cliente@empresa.com",
          `<div id="gtag">cuenta personal</div><div id="stamp">¿EN SERIO?</div>`))}

      ${scene(1,
        `<div class="maskwrap" id="mask1">${mask}</div><h1>Con MailMask escribes desde <em>tu dominio</em></h1>`,
        mail("new", "MailMask", "pedro@tuestudio.mx", "cliente@empresa.com",
          `<div class="chips"><span class="chip" id="chip-dkim">DKIM ✓</span><span class="chip" id="chip-spf">SPF ✓</span><span class="chip" id="chip-nota" style="color:${RED};background:rgba(215,38,61,.1);border-color:rgba(215,38,61,.3)">se nota</span></div>`))}

      ${scene(2,
        `<h1 id="s2-title">Tu dominio recibe <em>correo</em></h1>
         <div class="dns">
           <div id="dns0"><b>MX</b><span>inbound-smtp.us-east-1…</span><i class="ok">✓</i></div>
           <div id="dns1"><b>TXT</b><span>v=spf1 include:amazonses…</span><i class="ok">✓</i></div>
           <div id="dns2"><b>CNAME</b><span>dkim._domainkey…</span><i class="ok">✓</i></div>
         </div>`,
        `<div class="big">Desde <em id="hoy">hoy</em></div><div class="note" id="tarjeta">sin tarjeta · un dominio gratis</div>`)}

      ${scene(3,
        `<div class="inbox" id="inbox">
           <div class="hd">Bandeja · tuestudio.mx</div>
           <div class="th"><span>Luis Ortega</span><span>Factura agosto</span></div>
           <div class="th sel"><b>Ana García</b><span>Cotización sitio web</span></div>
           <div class="th"><span>Tienda MX</span><span>Pedido #1042</span></div>
           <div class="notewrap"><div class="inote">Nota interna · ya le mandé precios, falta el hosting — Pedro</div><div class="assign" id="assign">Asignado a Ana</div></div>
         </div>`,
        `<div class="cmp">
           <div class="col g" id="colg" style="position:relative"><div class="name">Google</div><div class="price" id="gprice">$140</div><div class="sub">× persona · al mes</div><div id="strike"></div></div>
           <div class="col m" id="colm"><div class="name">MailMask</div><div class="price">∞</div><div class="sub">personas · un solo pago</div></div>
         </div>`)}

      ${scene(4,
        `<div class="huge" id="price">$99</div><div class="big" style="font-size:96px" id="pordom">por <em>dominio</em></div><div class="note" id="todo">todo incluido · personas ilimitadas · al mes</div>`,
        `<div class="maskwrap" style="width:300px;height:300px" id="mask4">${mask}</div><div class="btn" id="btn">Empieza gratis</div><div class="url" id="url">mailmask.studio</div>`)}

      ${caps}

      <div class="clip" id="wipeclip" data-start="0" data-duration="${f(TOTAL)}">
        <div id="wipes">${[0,1,2,3,4,5].map((i) => `<div class="colw" id="c${i}" style="left:${i * 180}px"></div>`).join("")}</div>
      </div>

      ${audio}
    </div>

    <script>
      window.__timelines = window.__timelines || {};
      const tl = gsap.timeline({ paused: true });
      const RED = "${RED}", SUBTLE = "${SUBTLE}", FG = "${FG}";
      const START = ${JSON.stringify(start.map((s) => +s.toFixed(3)))};

      // ---- background: grid travels exactly one cell; blobs breathe (finite repeats)
      tl.to("#grid", { x: 60, y: 60, duration: 3, ease: "none", repeat: 9 }, 0);
      tl.to("#blob1", { scale: 1.18, x: 60, duration: 2.6, ease: "sine.inOut", yoyo: true, repeat: 11 }, 0);
      tl.to("#blob2", { scale: .86, y: -60, duration: 3.1, ease: "sine.inOut", yoyo: true, repeat: 9 }, 0.4);

      // ---- wipes: columns fall with 35 ms stagger, cover the cut, keep going down
      tl.set(".colw", { yPercent: -100 }, 0);
      ${CUTS.map((c) => `
      tl.to(".colw", { yPercent: 0, duration: ${WIPE_IN}, ease: "power3.in", stagger: .035 }, ${f(c - WIPE_IN - 0.035 * 5 - HOLD)});
      tl.to(".colw", { yPercent: 100, duration: ${WIPE_OUT}, ease: "power3.out", stagger: .035 }, ${f(c + HOLD)});
      tl.set(".colw", { yPercent: -100 }, ${f(c + HOLD + WIPE_OUT + 0.035 * 5 + 0.1)});`).join("")}

      // ---- panel handoff: A leaves left, B enters right (0.42 s power4.inOut)
      function swap(i, t) {
        tl.set("#s" + i + "-b", { xPercent: 100, opacity: 1 }, t - .01);
        tl.to("#s" + i + "-a", { xPercent: -200, duration: .42, ease: "power4.inOut" }, t);
        tl.to("#s" + i + "-b", { xPercent: 0, duration: .42, ease: "power4.inOut" }, t);
      }
      const PULSES = [];
      function pulse(sel, t, s) { PULSES.push(t); tl.to(sel, { scale: s || 1.22, duration: .18, ease: "back.out(3)", repeat: 1, yoyo: true }, t); }
      function settle(sel, t) { tl.from(sel, { y: 26, duration: .5, ease: "power3.out" }, t); }

      // ---- s0 · «Todavía@${at(0,0).toFixed(2)} clientes@${at(0,5).toFixed(2)} desde@${at(0,6).toFixed(2)} Gmail@${at(0,8).toFixed(2)} personal@${at(0,9).toFixed(2)}»
      settle("#s0-a h1", 0.1);
      settle("#s0-a .kicker", 0);
      pulse("#s0-a h1 em", ${f(at(0,8))});
      swap(0, ${f(at(0,6) - 0.3)});
      pulse("#s0-b .from", ${f(at(0,8))}, 1.08);
      tl.to("#gtag", { opacity: 1, duration: .01 }, ${f(at(0,9))}).from("#gtag", { scale: .6, duration: .3, ease: "back.out(2)" }, ${f(at(0,9))});
      tl.to("#stamp", { opacity: 1, duration: .01 }, ${f(at(0,9) + 0.7)}).from("#stamp", { scale: 2.2, rotate: -14, duration: .3, ease: "power4.in" }, ${f(at(0,9) + 0.7)});
      tl.to("#s0-b .mail", { x: 8, duration: .05, yoyo: true, repeat: 5 }, ${f(at(0,9) + 0.98)});

      // ---- s1 · «Con@${at(1,0).toFixed(2)} MailMask@${at(1,1).toFixed(2)} escribes@${at(1,3).toFixed(2)} dominio@${at(1,6).toFixed(2)} nota@${at(1,9).toFixed(2)}»
      tl.from("#mask1", { x: -700, rotate: -30, duration: .7, ease: "back.out(1.4)" }, START[1] + .5);
      settle("#s1-a h1", START[1] + .6);
      tl.to("#mask1", { rotate: -6, y: -10, duration: .5, ease: "sine.inOut", yoyo: true, repeat: 5 }, START[1] + 1.2);
      pulse("#mask1", ${f(at(1,1))}, 1.15);
      pulse("#s1-a h1 em", ${f(at(1,6) - 0.02)});
      swap(1, ${f(at(1,3) + 0.2)});
      pulse("#s1-b .from", ${f(at(1,6))}, 1.08);
      pulse("#chip-dkim", ${f(at(1,6) + 0.3)}, 1.15); pulse("#chip-spf", ${f(at(1,6) + 0.45)}, 1.15);
      tl.from("#chip-nota", { scale: 0, duration: .35, ease: "back.out(2.5)" }, ${f(at(1,9))});

      // ---- s2 · «dominio@${at(2,1).toFixed(2)} recibe@${at(2,2).toFixed(2)} correo@${at(2,3).toFixed(2)} desde@${at(2,4).toFixed(2)} hoy@${at(2,5).toFixed(2)} tarjeta@${at(2,7).toFixed(2)}»
      settle("#s2-title", START[2] + .35);
      settle(".dns", START[2] + .45);
      pulse("#dns0", ${f(at(2,1))}, 1.06); pulse("#dns1", ${f(at(2,2))}, 1.06); pulse("#dns2", ${f(at(2,3))}, 1.06);
      swap(2, ${f(at(2,4) - 0.35)});
      pulse("#hoy", ${f(at(2,5))}, 1.3);
      pulse("#tarjeta", ${f(at(2,7))}, 1.12);

      // ---- s3 · «equipo@${at(3,1).toFixed(2)} bandeja@${at(3,6).toFixed(2)} Google@${at(3,7).toFixed(2)} persona@${at(3,10).toFixed(2)} no@${at(3,12).toFixed(2)}»
      settle("#inbox", START[3] + .35);
      tl.from(".th", { x: -30, opacity: 0, duration: .3, stagger: .08, ease: "power2.out" }, START[3] + .15);
      pulse("#inbox", ${f(at(3,1))}, 1.03);
      pulse("#assign", ${f(at(3,6))}, 1.18);
      swap(3, ${f(at(3,7) - 0.45)});
      pulse("#gprice", ${f(at(3,10))}, 1.25);
      tl.fromTo("#strike", { scaleX: 0 }, { scaleX: 1, duration: .25, ease: "power3.out" }, ${f(at(3,12))});
      pulse("#colm", ${f(at(3,12))}, 1.08);

      // ---- s4 · «99@${at(4,0).toFixed(2)} pesos@${at(4,1).toFixed(2)} dominio@${at(4,3).toFixed(2)} incluido@${at(4,5).toFixed(2)} empieza@${at(4,6).toFixed(2)} gratis@${at(4,7).toFixed(2)} url@${at(4,9).toFixed(2)}»
      tl.from("#price", { scale: .5, duration: .55, ease: "back.out(1.8)" }, START[4] + .35);
      settle("#pordom", START[4] + .5); settle("#todo", START[4] + .6);
      pulse("#price", ${f(at(4,1))}, 1.1);
      pulse("#pordom em", ${f(at(4,3))});
      pulse("#todo", ${f(at(4,5))}, 1.1);
      swap(4, ${f(at(4,6) - 0.4)});
      tl.from("#mask4", { rotate: -25, scale: .6, duration: .5, ease: "back.out(1.6)" }, ${f(at(4,6) - 0.2)});
      pulse("#btn", ${f(at(4,7))}, 1.12);
      pulse("#url", ${f(at(4,9))}, 1.1);
      tl.to("#mask4", { rotate: 6, duration: .6, ease: "sine.inOut", yoyo: true, repeat: 5 }, ${f(at(4,7))});

      // ---- karaoke: the current word pops red, then stays ink
      const LINES = ${JSON.stringify(lines.map((l, k) => ({ k, s: +l.s.toFixed(3), base: +(start[l.scene] + BREATH).toFixed(3), words: l.words.map((w, j) => ({ id: `w${k}_${j}`, s: +w.start.toFixed(3), e: +w.end.toFixed(3) })) })))};
      LINES.forEach((l) => {
        tl.from("#cap" + l.k + " .capin", { y: 24, scale: .9, duration: .22, ease: "back.out(1.8)" }, l.s);
        l.words.forEach((w) => {
          tl.set("#" + w.id, { color: RED, opacity: 1 }, l.base + w.s)
            .fromTo("#" + w.id, { scale: 1.3, y: -8 }, { scale: 1.06, y: 0, duration: .22, immediateRender: false, ease: "back.out(2)" }, l.base + w.s)
            .set("#" + w.id, { color: FG, scale: 1, y: 0 }, l.base + w.e);
        });
      });

      tl.set({}, {}, ${f(TOTAL)});
      window.__timelines["mailmask-short-01"] = tl;
      window.__pulses = PULSES;
    </script>
  </body>
</html>
`;

fs.writeFileSync(new URL("./index.html", import.meta.url), html);
console.log("index.html", html.length, "bytes · total", TOTAL, "s");

// Times for the SFX mixer: wipes and pulses, read back from the generated timeline
const pulses = [...html.matchAll(/pulse\("[^"]+", ([0-9.]+)/g)].map((m) => +m[1]);
const swaps = [...html.matchAll(/swap\(\d, ([0-9.]+)\)/g)].map((m) => +m[1]);
fs.writeFileSync(new URL("./sfx-times.json", import.meta.url), JSON.stringify({ TOTAL, cuts: CUTS, wipeIn: WIPE_IN, pulses, swaps, voiceStarts: start.map((s) => s + BREATH) }, null, 1));
