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
}

// Persist coupon from URL to localStorage
const _landingCoupon = new URLSearchParams(location.search).get("coupon");
if (_landingCoupon) localStorage.setItem("mailmask_coupon", _landingCoupon);

async function startCheckout(plan, billing, btn) {
  btn.disabled = true;
  btn.textContent = "Redirigiendo...";
  try {
    const coupon = localStorage.getItem("mailmask_coupon") || undefined;
    const res = await fetch("/api/billing/guest-checkout", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ plan, billing, coupon }),
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
document.getElementById("billing-toggle").addEventListener("click", toggleBilling);
document.querySelectorAll(".checkout-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    const plan = btn.closest("[data-plan]").dataset.plan;
    startCheckout(plan, currentBilling, btn);
  });
});
