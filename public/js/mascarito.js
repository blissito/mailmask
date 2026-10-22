// Mascarito: la máscara de MailMask en piezas con ids estables y un rig pequeño de gestos (mismas reglas que el
// ghosty-rig de ghosty-reel: se anima, no se muta; los ojos se mueven completos, párpado y pupila; el aplastado va a
// lo largo del movimiento, con área constante y tope de 6 %). Web, con WAAPI: sirve con la CSP (sin estilos ni
// scripts en línea). Uso: <div data-mascarito></div> + este script; las páginas llaman Mascarito.react("…").
(() => {
  const NS = "http://www.w3.org/2000/svg";
  const SVG = `
<svg xmlns="${NS}" viewBox="4 6 72 86" width="96" height="114" role="img" aria-label="Mascarito, la mascota de MailMask">
  <ellipse id="mShadow" cx="40" cy="86" rx="22" ry="3.2" fill="#1c1917" opacity=".14"/>
  <g id="mHop"><g id="mBody">
    <ellipse cx="40" cy="48" rx="28" ry="24" fill="#a0182c"/>
    <ellipse cx="40" cy="44" rx="28" ry="22" fill="#d7263d"/>
    <g id="mAnt">
      <path d="M40 24 L40 32" stroke="#f2b705" stroke-width="2.2" stroke-linecap="round"/>
      <path d="M36 25 L40 32 L44 25" stroke="#f2b705" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
    </g>
    <g id="mFollow"><g id="mEyes">
      <g id="mEyeL">
        <ellipse cx="28" cy="42" rx="8" ry="6.3" fill="#fff" stroke="#f2b705" stroke-width="1.8"/>
        <g class="mGaze"><g class="mPup"><circle cx="28.6" cy="42.4" r="5.2" fill="#a97142"/><circle cx="28.6" cy="42.4" r="2.6" fill="#3b2412"/><circle cx="30.2" cy="40.9" r="1.9" fill="#fff"/></g></g>
        <path class="mHappy" d="M22 44 Q28 37 34 44" stroke="#3b2412" stroke-width="2.4" fill="none" stroke-linecap="round" opacity="0"/>
      </g>
      <g id="mEyeR">
        <ellipse cx="52" cy="42" rx="8" ry="6.3" fill="#fff" stroke="#f2b705" stroke-width="1.8"/>
        <g class="mGaze"><g class="mPup"><circle cx="52.6" cy="42.4" r="5.2" fill="#a97142"/><circle cx="52.6" cy="42.4" r="2.6" fill="#3b2412"/><circle cx="54.2" cy="40.9" r="1.9" fill="#fff"/></g></g>
        <path class="mHappy" d="M46 44 Q52 37 58 44" stroke="#3b2412" stroke-width="2.4" fill="none" stroke-linecap="round" opacity="0"/>
      </g>
    </g></g>
  </g></g>
</svg>`;

  // --- seguir el cursor con los ojos ---
  let lastMove = 0;
  let pointer = null;
  const MAX_PUPIL = 2.6; // px del vector: más y la pupila se sale del blanco del ojo
  window.addEventListener("pointermove", (e) => { pointer = [e.clientX, e.clientY]; lastMove = performance.now(); }, { passive: true });
  function gazeLoop() {
    const following = performance.now() - lastMove < 2500;
    for (const r of rigs) {
      if (following && pointer) {
        const b = r.svg.getBoundingClientRect();
        const dx = pointer[0] - (b.left + b.width / 2), dy = pointer[1] - (b.top + b.height * .45);
        const dist = Math.hypot(dx, dy) || 1;
        const k = Math.min(dist / 140, 1) * MAX_PUPIL; // cerca del centro mira poco, lejos llega al tope
        r.target = [(dx / dist) * k, (dy / dist) * k * .75];
      } else r.target = [0, 0];
      r.cur = [r.cur[0] + (r.target[0] - r.cur[0]) * .18, r.cur[1] + (r.target[1] - r.cur[1]) * .18];
      r.gaze.forEach((g) => (g.style.transform = `translate(${r.cur[0].toFixed(2)}px, ${r.cur[1].toFixed(2)}px)`));
      // el ojo completo acompaña un poco a la pupila
      r.follow.style.transform = `translate(${(r.cur[0] * .3).toFixed(2)}px, ${(r.cur[1] * .3).toFixed(2)}px)`;
    }
    requestAnimationFrame(gazeLoop);
  }
  requestAnimationFrame(gazeLoop);

  const reduced = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  const rigs = [];

  function piece(root, sel, origin) {
    const el = root.querySelector(sel);
    if (el && origin) { el.style.transformBox = "fill-box"; el.style.transformOrigin = origin; }
    return el;
  }

  function mount(host) {
    host.innerHTML = SVG;
    const svg = host.querySelector("svg");
    const r = {
      hop: piece(svg, "#mHop"),
      body: piece(svg, "#mBody", "50% 100%"), // aplasta desde la base
      ant: piece(svg, "#mAnt", "50% 100%"),
      eyes: piece(svg, "#mEyes"),
      pups: [...svg.querySelectorAll(".mPup")],
      // el parpadeo cierra el ojo completo (blanco, iris y pupila), no lo tapa con un párpado pintado encima
      eyeL: piece(svg, "#mEyeL", "50% 55%"),
      eyeR: piece(svg, "#mEyeR", "50% 55%"),
      happy: [...svg.querySelectorAll(".mHappy")],
      shadow: piece(svg, "#mShadow", "50% 50%"),
      busy: false,
      svg,
      follow: svg.querySelector("#mFollow"),
      gaze: [...svg.querySelectorAll(".mGaze")],
      cur: [0, 0], // mirada actual (px del vector), se acerca a `target` cuadro a cuadro
      target: [0, 0],
    };
    rigs.push(r);
    if (!reduced()) idle(r);
    schedule(r);
    return r;
  }

  const anim = (el, frames, o) => el?.animate(frames, { fill: "forwards", easing: "ease-in-out", ...o });

  // --- gestos ---
  function idle(r) {
    // flota y mece la antena; la sombra acompaña (se aleja cuando sube)
    anim(r.hop, [{ transform: "translateY(0)" }, { transform: "translateY(-3px)" }, { transform: "translateY(0)" }], { duration: 2400, iterations: Infinity, fill: "none" });
    anim(r.shadow, [{ transform: "scaleX(1)", opacity: .14 }, { transform: "scaleX(.9)", opacity: .1 }, { transform: "scaleX(1)", opacity: .14 }], { duration: 2400, iterations: Infinity, fill: "none" });
    anim(r.ant, [{ transform: "rotate(0)" }, { transform: "rotate(-7deg)" }, { transform: "rotate(5deg)" }, { transform: "rotate(0)" }], { duration: 2400, iterations: Infinity, fill: "none" });
  }
  function blink(r, double = false) {
    // se aplana hasta una rayita y vuelve; con fill "none" para no pelear con otras poses del ojo
    const f = [{ transform: "scaleY(1)" }, { transform: "scaleY(.08)", offset: .45 }, { transform: "scaleY(1)" }];
    const frames = double ? [{ transform: "scaleY(1)" }, { transform: "scaleY(.08)", offset: .22 }, { transform: "scaleY(1)", offset: .5 }, { transform: "scaleY(.08)", offset: .72 }, { transform: "scaleY(1)" }] : f;
    [r.eyeL, r.eyeR].forEach((e) => anim(e, frames, { duration: double ? 320 : 160, easing: "ease-in-out", fill: "none" }));
  }
  function look(r, dir = "center", dur = 220) {
    const d = { center: [0, 0], left: [-2.6, 0], right: [2.6, 0], up: [0, -1.6], down: [0, 1.8], downLeft: [-2, 1.6], downRight: [2, 1.6] }[dir] ?? [0, 0];
    // ojos completos un poco, pupilas más (el ojo acompaña a la mirada)
    anim(r.eyes, [{ transform: `translate(${d[0] * .35}px, ${d[1] * .35}px)` }], { duration: dur });
    r.pups.forEach((p) => anim(p, [{ transform: `translate(${d[0]}px, ${d[1]}px)` }], { duration: dur }));
  }
  function happy(r, hold = 900) {
    r.pups.forEach((p) => anim(p, [{ opacity: 1 }, { opacity: 0, offset: .1 }, { opacity: 0, offset: .9 }, { opacity: 1 }], { duration: hold }));
    r.happy.forEach((h) => anim(h, [{ opacity: 0 }, { opacity: 1, offset: .1 }, { opacity: 1, offset: .9 }, { opacity: 0 }], { duration: hold, fill: "none" }));
  }
  function hop(r, h = 14, dur = 520) {
    // se agacha, sube estirándose (≤6 %, área constante), aterriza con aplastado amortiguado
    anim(r.body, [
      { transform: "scale(1,1)" }, { transform: "scale(1.06,.943)", offset: .14 }, { transform: "scale(.96,1.042)", offset: .3 },
      { transform: "scale(1,1)", offset: .55 }, { transform: "scale(1.06,.943)", offset: .82 }, { transform: "scale(1,1)" },
    ], { duration: dur + 160 });
    anim(r.hop, [{ transform: "translateY(0)" }, { transform: "translateY(0)", offset: .14 }, { transform: `translateY(-${h}px)`, offset: .5, easing: "ease-in" }, { transform: "translateY(0)", offset: .82 }, { transform: "translateY(0)" }], { duration: dur + 160, fill: "none", composite: "add" });
    anim(r.shadow, [{ transform: "scaleX(1)" }, { transform: "scaleX(.7)", offset: .5 }, { transform: "scaleX(1)", offset: .82 }, { transform: "scaleX(1)" }], { duration: dur + 160, fill: "none", composite: "add" });
  }
  function shake(r, times = 3, deg = 6) {
    // «no»: balanceo desde la base; las pupilas hacen contra-giro con retraso
    const f = [{ transform: "rotate(0)" }];
    for (let i = 0; i < times; i++) f.push({ transform: `rotate(${deg}deg)` }, { transform: `rotate(${-deg}deg)` });
    f.push({ transform: "rotate(0)" });
    anim(r.body, f, { duration: 760 });
    r.pups.forEach((p) => anim(p, [{ transform: "translate(0,0)" }, { transform: "translate(-1.6px,0)", offset: .3 }, { transform: "translate(1.6px,0)", offset: .65 }, { transform: "translate(0,0)" }], { duration: 860, delay: 60 }));
  }
  function shy(r) {
    anim(r.body, [{ transform: "rotate(0) scale(1,1)" }, { transform: "rotate(-6deg) scale(1.02,.98)", offset: .2 }, { transform: "rotate(-6deg) scale(1.02,.98)", offset: .8 }, { transform: "rotate(0) scale(1,1)" }], { duration: 1100 });
    look(r, "downLeft");
    setTimeout(() => look(r, "center"), 900);
  }

  // --- reacciones que piden las páginas ---
  const REACTIONS = {
    lookDown: (r) => look(r, "down"),
    lookAround: (r) => { look(r, "left"); setTimeout(() => look(r, "right"), 700); setTimeout(() => look(r, "center"), 1400); },
    blink: (r) => blink(r),
    no: (r) => { shake(r); setTimeout(() => shy(r), 850); },
    yes: (r) => { happy(r, 1100); hop(r, 10); },
    celebrate: (r) => { happy(r, 1800); hop(r, 14); setTimeout(() => hop(r, 20), 640); },
  };
  function react(name) {
    const fn = REACTIONS[name];
    if (!fn) return;
    for (const r of rigs) { if (reduced() && name !== "blink") { blink(r); continue; } fn(r); }
  }

  // vida propia: parpadeos y miradas al azar, finitos entre reacciones
  function schedule(r) {
    const next = () => setTimeout(() => {
      if (!document.hidden) {
        const x = Math.random();
        if (x < .6) blink(r, x < .15);
        else if (!reduced() && performance.now() - lastMove > 2500) REACTIONS.lookAround(r);
      }
      next();
    }, 2200 + Math.random() * 2600);
    next();
  }

  window.Mascarito = { react };
  const boot = () => document.querySelectorAll("[data-mascarito]").forEach((h) => mount(h));
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
