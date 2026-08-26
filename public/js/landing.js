// Con un modal abierto, el fondo no debe desplazarse.
let openModals = 0;
function lockBodyScroll() {
  if (openModals === 0) {
    const gap = window.innerWidth - document.documentElement.clientWidth;
    document.body.dataset.prevOverflow = document.body.style.overflow || "";
    document.body.style.overflow = "hidden";
    if (gap > 0) document.body.style.paddingRight = `${gap}px`;
  }
  openModals++;
}
function unlockBodyScroll() {
  openModals = Math.max(0, openModals - 1);
  if (openModals === 0) {
    document.body.style.overflow = document.body.dataset.prevOverflow ?? "";
    document.body.style.paddingRight = "";
    delete document.body.dataset.prevOverflow;
  }
}

// Session detection (non-blocking)
let _loggedInUser = null;
fetch("/api/auth/me").then(r => r.ok ? r.json() : null).then(u => {
  if (!u) return;
  _loggedInUser = u;
  // Update all nav login links to "Mi cuenta"
  document.querySelectorAll('a[href="/login"]').forEach(a => {
    if (a.textContent.trim() === "Iniciar sesión") {
      a.href = "/app";
      a.textContent = "Mi cuenta";
    }
  });
}).catch(() => {});

// Capture referral slug from URL
const _refParam = new URLSearchParams(location.search).get("ref");
if (_refParam) {
  localStorage.setItem("mailmask_ref", _refParam);
  fetch("/api/referrals/track", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ slug: _refParam }) }).catch(() => {});
}

// Success banner (guest checkout redirect)
if (new URLSearchParams(location.search).get("success") === "1") {
  document.getElementById("success-banner")?.classList.remove("hidden");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// Billing toggle
let currentBilling = "monthly";

function animatePrice(el, from, to, duration = 1500) {
  const start = performance.now();
  const step = (now) => {
    const t = Math.min((now - start) / duration, 1);
    const ease = 1 - Math.pow(1 - t, 3);
    const current = Math.round(from + (to - from) * ease);
    el.textContent = "$" + current.toLocaleString("es-MX");
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function parsePrice(text) {
  return parseInt(text.replace(/[$,\.]/g, ""), 10) || 0;
}

function toggleBilling() {
  currentBilling = currentBilling === "monthly" ? "yearly" : "monthly";
  const isYearly = currentBilling === "yearly";
  const dot = document.getElementById("toggle-dot");
  const toggle = document.getElementById("billing-toggle");
  const labelM = document.getElementById("label-monthly");
  const labelY = document.getElementById("label-yearly");
  const badge = document.getElementById("promo-badge");

  dot.style.transform = isYearly ? "translateX(28px)" : "translateX(0)";
  toggle.className = "relative w-14 h-7 " + (isYearly ? "bg-green-600" : "bg-zinc-700") + " rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-mask-500";
  labelM.className = "text-sm font-semibold " + (isYearly ? "text-zinc-500" : "text-zinc-100");
  labelY.className = "text-sm font-semibold " + (isYearly ? "text-zinc-100" : "text-zinc-500");
  badge.textContent = isYearly ? "2 meses gratis" : "Primer mes gratis";

  document.querySelectorAll(".pricing-card[data-plan]").forEach((card) => {
    // Skip coupon card — applyCouponToCard handles it
    if (loadedCoupon && card.dataset.plan === loadedCoupon.plan) return;

    const price = card.querySelector(".plan-price");
    const period = card.querySelector(".plan-period");
    const savings = card.querySelector(".plan-savings");

    const oldNum = parsePrice(price.textContent);
    const newNum = isYearly
      ? parsePrice(card.dataset.yearly)
      : parseInt(card.dataset.monthly, 10);

    animatePrice(price, oldNum, newNum);

    if (isYearly) {
      period.textContent = "/año";
      savings.textContent = "Ahorras $" + card.dataset.savings;
      savings.classList.remove("hidden");
      savings.animate([
        { opacity: 0, transform: "translateY(6px)" },
        { opacity: 1, transform: "translateY(0)" },
      ], { duration: 300, easing: "ease-out", fill: "forwards" });
    } else {
      period.textContent = "/mes";
      savings.classList.add("hidden");
    }
  });

  badge.animate([
    { opacity: 0, transform: "scale(0.9)" },
    { opacity: 1, transform: "scale(1)" },
  ], { duration: 250, easing: "ease-out", fill: "forwards" });

  // Re-apply coupon price after toggle overwrites it
  applyCouponToCard();
}

// `mode` distingue los dos usos del mismo modal:
//   "guest" — invitado sin cuenta: el correo sirve para crear la cuenta Y como payer_email.
//   "mp"    — ya tiene sesión: solo pedimos el correo de su cuenta de MercadoPago, porque
//             MP rechaza el pago si el payer_email no es el de la cuenta con la que paga
//             ("Tu e-mail no coincide con el de la suscripción") y el campo es obligatorio
//             en su API, así que no hay forma de omitirlo.
function showEmailModal(plan, billing, btn, mode = "guest") {
  const modal = document.getElementById("email-modal");
  const input = document.getElementById("email-modal-input");
  const error = document.getElementById("email-modal-error");
  const title = document.getElementById("email-modal-title");
  const hint = document.getElementById("email-modal-hint");
  if (mode === "mp") {
    title.textContent = "Tu correo de MercadoPago";
    hint.textContent = "Debe ser el correo de la cuenta de MercadoPago con la que vas a pagar. Si no coincide, MercadoPago rechaza el pago.";
    input.value = _loggedInUser?.email ?? "";
  } else {
    title.textContent = "Tu email para continuar";
    hint.textContent = "Usaremos este email para tu cuenta y recibos. Debe ser el de tu cuenta de MercadoPago.";
    input.value = "";
  }
  error.textContent = "";
  modal.dataset.mode = mode;
  modal.dataset.plan = plan;
  modal.dataset.billing = billing;
  modal._btn = btn;
  if (modal.classList.contains("hidden")) { modal.classList.remove("hidden"); lockBodyScroll(); }
  setTimeout(() => input.focus(), 100);
}

function hideEmailModal() {
  const el = document.getElementById("email-modal");
  if (el.classList.contains("hidden")) return;
  el.classList.add("hidden");
  unlockBodyScroll();
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("email-modal-close")?.addEventListener("click", hideEmailModal);
  document.getElementById("email-modal")?.addEventListener("click", (e) => {
    if (e.target === e.currentTarget) hideEmailModal();
  });
  document.getElementById("email-modal-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const modal = document.getElementById("email-modal");
    const input = document.getElementById("email-modal-input");
    const error = document.getElementById("email-modal-error");
    const email = input.value.trim();
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      error.textContent = "Ingresa un email válido";
      return;
    }
    error.textContent = "";
    const btn = modal._btn;
    hideEmailModal();
    if (modal.dataset.mode === "mp") {
      await doAuthCheckout(modal.dataset.plan, modal.dataset.billing, btn, email);
    } else {
      await doCheckout(modal.dataset.plan, modal.dataset.billing, btn, email);
    }
  });
});

async function startCheckout(plan, billing, btn) {
  if (_loggedInUser) {
    // Con sesión igual preguntamos el correo: el de MailMask no tiene por qué ser el de
    // su cuenta de MercadoPago, y MP rechaza el pago si no coinciden.
    showEmailModal(plan, billing, btn, "mp");
  } else {
    showEmailModal(plan, billing, btn);
  }
}

async function doAuthCheckout(plan, billing, btn, payerEmail) {
  btn.disabled = true;
  btn.textContent = "Redirigiendo...";
  try {
    const coupon = new URLSearchParams(location.search).get("coupon") || undefined;
    const res = await fetch("/api/billing/checkout", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ plan, billing: (loadedCoupon && plan === loadedCoupon.plan) ? "monthly" : billing, coupon, payerEmail }),
    });
    const data = await res.json();
    if (data.init_point) {
      location.href = data.init_point;
    } else {
      alert(data.error || "Error al iniciar el pago");
      btn.disabled = false;
      btn.textContent = "Empezar";
    }
  } catch {
    alert("Error de conexión");
    btn.disabled = false;
    btn.textContent = "Empezar";
  }
}

async function doCheckout(plan, billing, btn, email) {
  btn.disabled = true;
  btn.textContent = "Redirigiendo...";
  try {
    const coupon = new URLSearchParams(location.search).get("coupon") || undefined;
    const res = await fetch("/api/billing/guest-checkout", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ plan, billing: (loadedCoupon && plan === loadedCoupon.plan) ? "monthly" : billing, coupon, email }),
    });
    const data = await res.json();
    if (data.init_point) {
      location.href = data.init_point;
    } else {
      alert(data.error || "Error al iniciar el pago");
      btn.disabled = false;
      btn.textContent = "Empezar";
    }
  } catch {
    alert("Error de conexión");
    btn.disabled = false;
    btn.textContent = "Empezar";
  }
}

// --- Calculadora: la asimetría de precio ---
// Workspace escala con personas; MailMask con dominios. Antes cada slider alimentaba
// solo un lado, así que parecía una comparación y eran dos cálculos sueltos.
(function initCalc() {
  const usersSlider = document.getElementById("calc-users");
  const domainsSlider = document.getElementById("calc-domains");
  const chart = document.getElementById("calc-chart");
  if (!usersSlider || !domainsSlider || !chart) return;

  const $ = (id) => document.getElementById(id);
  const GW_POR_PERSONA = 108;
  const ENVIOS = 49;      // add-on de envíos, para comparar equivalente con Workspace
  const MAX_U = 20;

  // Geometría del SVG
  const W = 720, H = 300, L = 56, R = 24, T = 24, B = 44;
  const px = (u) => L + ((u - 1) / (MAX_U - 1)) * (W - L - R);
  const money = (n) => "$" + n.toLocaleString("es-MX");

  // `base` es lo que cuesta recibir y responder — el "desde $49" del encabezado.
  // `conEnvio` suma el add-on solo donde hace falta: Freelancer y Developer ya incluyen
  // iniciar correos, así que ahí las dos cifras coinciden.
  function precioMailMask(d) {
    if (d === 1) return { base: 49, conEnvio: 49 + ENVIOS, plan: "Básico · 1 dominio" };
    if (d <= 4) {
      const b = 49 + (d - 1) * 99;
      return { base: b, conEnvio: b + ENVIOS, plan: `Básico + ${d - 1} dominio${d - 1 > 1 ? "s" : ""} extra` };
    }
    if (d <= 15) return { base: 449, conEnvio: 449, plan: "Freelancer · hasta 15 dominios" };
    return { base: 999, conEnvio: 999, plan: "Developer · hasta 20 dominios" };
  }

  function dibujarGrid(maxY) {
    const g = $("chart-grid");
    let out = "";
    for (let i = 0; i <= 4; i++) {
      const val = (maxY / 4) * i;
      const y = H - B - (val / maxY) * (H - T - B);
      out += `<line x1="${L}" y1="${y}" x2="${W - R}" y2="${y}" stroke="#27272a" stroke-width="1" />`;
      out += `<text x="${L - 8}" y="${y + 4}" fill="#71717a" font-family="system-ui,sans-serif" font-size="11" text-anchor="end">${money(Math.round(val))}</text>`;
    }
    g.innerHTML = out;
  }

  function update() {
    const u = +usersSlider.value;
    const d = +domainsSlider.value;
    $("calc-users-val").textContent = u;
    $("calc-domains-val").textContent = d;

    const gw = u * GW_POR_PERSONA;
    const mm = precioMailMask(d);

    // La escala se fija al máximo del rango para que la línea de Workspace se vea
    // trepar de verdad en vez de reescalarse a cada movimiento.
    const maxY = Math.max(MAX_U * GW_POR_PERSONA, mm.conEnvio * 1.2);
    const py = (v) => H - B - (v / maxY) * (H - T - B);
    dibujarGrid(maxY);

    let gwPath = "", mmPath = "", envPath = "";
    for (let i = 1; i <= MAX_U; i++) {
      const cmd = i === 1 ? "M" : "L";
      gwPath += `${cmd} ${px(i)} ${py(i * GW_POR_PERSONA)} `;
      mmPath += `${cmd} ${px(i)} ${py(mm.base)} `;
      envPath += `${cmd} ${px(i)} ${py(mm.conEnvio)} `;
    }
    $("line-gw").setAttribute("d", gwPath);
    $("line-mm").setAttribute("d", mmPath);
    // La punteada solo se dibuja cuando el add-on cambia algo.
    const lineEnv = $("line-env");
    if (mm.conEnvio > mm.base) { lineEnv.setAttribute("d", envPath); lineEnv.style.display = ""; }
    else { lineEnv.style.display = "none"; }
    $("area-mm").setAttribute("d", `${mmPath} L ${px(MAX_U)} ${H - B} L ${px(1)} ${H - B} Z`);

    const xu = px(u);
    $("dot-gw").setAttribute("cx", xu); $("dot-gw").setAttribute("cy", py(gw));
    $("dot-mm").setAttribute("cx", xu); $("dot-mm").setAttribute("cy", py(mm.base));

    const lg = $("lbl-gw"), lm = $("lbl-mm");
    lg.textContent = money(gw); lm.textContent = money(mm.base);
    // Las etiquetas se apartan del borde para que no se corten.
    const clamp = (x) => Math.max(L + 34, Math.min(W - R - 34, x));
    lg.setAttribute("x", clamp(xu)); lg.setAttribute("y", Math.max(T + 12, py(gw) - 14));
    lm.setAttribute("x", clamp(xu)); lm.setAttribute("y", py(mm.base) + 24);
    const le = $("lbl-env");
    if (mm.conEnvio > mm.base) {
      le.style.display = ""; le.textContent = money(mm.conEnvio) + " con envío";
      le.setAttribute("x", clamp(xu)); le.setAttribute("y", py(mm.conEnvio) - 10);
    } else { le.style.display = "none"; }

    $("calc-gw-price").textContent = money(gw);
    $("calc-gw-users").textContent = u;
    $("calc-mm-price").textContent = money(mm.base);
    $("calc-mm-plan").textContent = mm.plan;
    $("calc-mm-envio").textContent = mm.conEnvio > mm.base
      ? `+$${ENVIOS} si además quieres iniciar correos`
      : "Incluye iniciar correos";

    const ahorro = Math.max(0, (gw - mm.base) * 12);
    $("calc-savings").textContent = money(ahorro);
    const pct = gw > 0 ? Math.round((1 - mm.base / gw) * 100) : 0;
    $("calc-badge").textContent = pct > 0 ? `${pct}% menos` : "Mismo precio";
  }

  usersSlider.addEventListener("input", update);
  domainsSlider.addEventListener("input", update);
  update(); // sin esto la página muestra los valores estáticos del HTML
})();

// Scroll-triggered animations using IntersectionObserver
document.addEventListener("DOMContentLoaded", () => {
  const animatedEls = document.querySelectorAll(".animate-on-scroll");
  if (!animatedEls.length) return;

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.style.animationPlayState = "running";
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.1 },
  );

  animatedEls.forEach((el) => {
    el.style.animationPlayState = "paused";
    observer.observe(el);
  });
});

// Bind billing toggle and checkout buttons
document.getElementById("billing-toggle")?.addEventListener("click", toggleBilling);
document.querySelectorAll(".checkout-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    const plan = btn.closest("[data-plan]").dataset.plan;
    startCheckout(plan, currentBilling, btn);
  });
});

// --- Coupon display ---
let loadedCoupon = null;

function applyCouponToCard() {
  if (!loadedCoupon) return;
  const card = document.querySelector(`.pricing-card[data-plan="${loadedCoupon.plan}"]`);
  if (!card) return;

  const priceEl = card.querySelector(".plan-price");
  const displayPrice = Math.round(loadedCoupon.fixedPrice / 100);
  if (priceEl) {
    const originalPrice = currentBilling === "yearly" ? card.dataset.yearly : card.dataset.monthly;
    priceEl.innerHTML = `<span class="line-through text-zinc-500 text-2xl mr-2">$${originalPrice}</span>$${displayPrice.toLocaleString("es-MX")}`;
  }

  // Lock period label to /mes since coupon is monthly
  const periodEl = card.querySelector(".plan-period");
  if (periodEl) periodEl.textContent = "/mes";
}

(async () => {
  const couponCode = new URLSearchParams(location.search).get("coupon");
  if (!couponCode) return;
  try {
    const res = await fetch(`/api/coupons/${encodeURIComponent(couponCode)}`);
    if (!res.ok) return;
    loadedCoupon = await res.json();
    const card = document.querySelector(`.pricing-card[data-plan="${loadedCoupon.plan}"]`);
    if (!card) return;

    applyCouponToCard();

    // Add coupon badge
    const badgeEl = document.createElement("div");
    badgeEl.className = "absolute -top-3 right-4 bg-green-600 text-white text-xs font-bold px-3 py-1 rounded-full";
    badgeEl.textContent = loadedCoupon.description;
    card.style.position = "relative";
    card.appendChild(badgeEl);

    // Highlight card border
    card.classList.remove("border-zinc-800");
    card.classList.add("border-green-600", "border-2");
  } catch { /* ignore */ }
})();
