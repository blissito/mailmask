// Capture referral slug from URL
const _refParam = new URLSearchParams(location.search).get("ref");
if (_refParam) localStorage.setItem("mailmask_ref", _refParam);

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

function showEmailModal(plan, billing, btn) {
  const modal = document.getElementById("email-modal");
  const input = document.getElementById("email-modal-input");
  const error = document.getElementById("email-modal-error");
  const form = document.getElementById("email-modal-form");
  input.value = "";
  error.textContent = "";
  modal.dataset.plan = plan;
  modal.dataset.billing = billing;
  modal._btn = btn;
  modal.classList.remove("hidden");
  setTimeout(() => input.focus(), 100);
}

function hideEmailModal() {
  document.getElementById("email-modal").classList.add("hidden");
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
    await doCheckout(modal.dataset.plan, modal.dataset.billing, btn, email);
  });
});

async function startCheckout(plan, billing, btn) {
  showEmailModal(plan, billing, btn);
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

// --- Calculator ---
(function initCalc() {
  const usersSlider = document.getElementById("calc-users");
  const domainsSlider = document.getElementById("calc-domains");
  if (!usersSlider || !domainsSlider) return;

  const usersVal = document.getElementById("calc-users-val");
  const domainsVal = document.getElementById("calc-domains-val");
  const gwPrice = document.getElementById("calc-gw-price");
  const gwUsers = document.getElementById("calc-gw-users");
  const mmPrice = document.getElementById("calc-mm-price");
  const mmPlan = document.getElementById("calc-mm-plan");
  const badge = document.getElementById("calc-badge");

  let prevGw = 324, prevMm = 49;

  function update() {
    const u = +usersSlider.value;
    const d = +domainsSlider.value;
    usersVal.textContent = u;
    domainsVal.textContent = d;

    const gw = u * 108;
    let mm, planName;
    if (d <= 1) { mm = 49; planName = "Plan Básico · 1 dominio"; }
    else if (d <= 3) { mm = 449; planName = "Plan Freelancer · hasta 15 dominios"; }
    else { mm = 999; planName = "Plan Developer · hasta 20 dominios"; }

    animatePrice(gwPrice, prevGw, gw, 400);
    animatePrice(mmPrice, prevMm, mm, 400);
    prevGw = gw;
    prevMm = mm;

    gwUsers.textContent = u;
    mmPlan.textContent = planName;

    const pct = Math.round((1 - mm / gw) * 100);
    badge.textContent = pct > 0 ? `Ahorras ${pct}%` : "Mismo precio";
  }

  usersSlider.addEventListener("input", update);
  domainsSlider.addEventListener("input", update);
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
