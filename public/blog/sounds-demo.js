let _ctx = null;
function _ensureCtx() {
  if (!_ctx) _ctx = new (window.AudioContext || window.webkitAudioContext)();
  if (_ctx.state === "suspended") _ctx.resume();
  return _ctx;
}

function demoSound(type) {
  const ctx = _ensureCtx();
  const t = ctx.currentTime;
  if (type === "success") {
    [520, 660, 840].forEach((freq, i) => {
      const o = ctx.createOscillator(), g = ctx.createGain();
      o.type = "sine"; o.frequency.value = freq; g.gain.value = 0.12;
      o.connect(g); g.connect(ctx.destination);
      o.start(t + i * 0.12);
      g.gain.exponentialRampToValueAtTime(0.001, t + i * 0.12 + 0.2);
      o.stop(t + i * 0.12 + 0.2);
    });
  } else if (type === "pop") {
    const o = ctx.createOscillator(), g = ctx.createGain();
    o.type = "sine"; o.frequency.setValueAtTime(400, t);
    o.frequency.exponentialRampToValueAtTime(600, t + 0.05);
    g.gain.value = 0.13; o.connect(g); g.connect(ctx.destination);
    o.start(t); g.gain.exponentialRampToValueAtTime(0.001, t + 0.08); o.stop(t + 0.08);
  } else if (type === "whoosh") {
    const bs = ctx.sampleRate * 0.12, buf = ctx.createBuffer(1, bs, ctx.sampleRate);
    const d = buf.getChannelData(0); for (let i = 0; i < bs; i++) d[i] = Math.random() * 2 - 1;
    const s = ctx.createBufferSource(); s.buffer = buf;
    const f = ctx.createBiquadFilter(); f.type = "bandpass"; f.frequency.value = 1200; f.Q.value = 0.8;
    const g = ctx.createGain(); g.gain.setValueAtTime(0.1, t);
    g.gain.exponentialRampToValueAtTime(0.001, t + 0.12);
    s.connect(f); f.connect(g); g.connect(ctx.destination); s.start(t); s.stop(t + 0.12);
  } else if (type === "error") {
    const o = ctx.createOscillator(), g = ctx.createGain();
    o.type = "sine"; o.frequency.value = 200; g.gain.value = 0.15;
    o.connect(g); g.connect(ctx.destination);
    o.start(t); g.gain.exponentialRampToValueAtTime(0.001, t + 0.1); o.stop(t + 0.1);
  } else if (type === "notif") {
    const o = ctx.createOscillator(), g = ctx.createGain();
    o.type = "sine"; o.frequency.value = 800; g.gain.value = 0.15;
    o.connect(g); g.connect(ctx.destination);
    o.start(t); g.gain.exponentialRampToValueAtTime(0.001, t + 0.1); o.stop(t + 0.1);
  }
}

document.querySelectorAll("[data-sound]").forEach(btn => {
  btn.addEventListener("click", () => demoSound(btn.dataset.sound));
});
