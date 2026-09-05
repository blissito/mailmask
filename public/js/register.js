fetch("/api/auth/me").then(r => {
  if (r.ok) {
    const coupon = new URLSearchParams(location.search).get("coupon");
    window.location.href = "/app" + (coupon ? "?coupon=" + encodeURIComponent(coupon) : "");
  }
});

const _refParam = new URLSearchParams(location.search).get("ref");
if (_refParam) {
  localStorage.setItem("mailmask_ref", _refParam);
  fetch("/api/referrals/track", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ slug: _refParam }) }).catch(() => {});
}
const _hasRef = _refParam || localStorage.getItem("mailmask_ref");
if (_hasRef) {
  document.getElementById("referral-card")?.classList.remove("hidden");
  const inviterEl = document.getElementById("referral-inviter");
  if (inviterEl) {
    // Mientras llega el nombre real, el slug con mayúscula inicial ("brendi" → "Brendi").
    const pretty = _hasRef.split("-").map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
    inviterEl.textContent = pretty;
    fetch(`/api/referrals/lookup/${encodeURIComponent(_hasRef)}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => { if (d?.name) inviterEl.textContent = d.name; })
      .catch(() => {});
  }
}

document.getElementById("register-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const errEl = document.getElementById("error");
  errEl.classList.add("hidden");

  const ref = localStorage.getItem("mailmask_ref") || new URLSearchParams(location.search).get("ref") || undefined;
  const res = await fetch("/api/auth/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      email: form.email.value,
      password: form.password.value,
      ref,
    }),
  });

  if (res.ok) {
    localStorage.removeItem("mailmask_ref");
    const coupon = new URLSearchParams(location.search).get("coupon");
    window.location.href = "/app" + (coupon ? "?coupon=" + encodeURIComponent(coupon) : "");
  } else {
    const data = await res.json();
    errEl.textContent = data.error || "Error al crear cuenta";
    errEl.classList.remove("hidden");
  }
});

// Registro con Google: lleva el referido y el cupón en la URL; el servidor los guarda
// en el state y los aplica al crear la cuenta.
(() => {
  const a = document.getElementById("google-login");
  if (!a) return;
  const q = new URLSearchParams();
  const ref = localStorage.getItem("mailmask_ref") || new URLSearchParams(location.search).get("ref");
  const coupon = new URLSearchParams(location.search).get("coupon");
  if (ref) q.set("ref", ref);
  if (coupon) q.set("coupon", coupon);
  const qs = q.toString();
  if (qs) a.href = "/api/auth/google?" + qs;
})();

// Google es el camino principal; el formulario de contraseña se muestra a petición.
(() => {
  const btn = document.getElementById("show-password-form");
  const form = document.getElementById("register-form");
  if (!btn || !form) return;
  btn.addEventListener("click", () => {
    form.classList.remove("hidden");
    btn.classList.add("hidden");
    form.email.focus();
  });
})();
