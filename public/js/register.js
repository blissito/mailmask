fetch("/api/auth/me").then(r => {
  if (r.ok) {
    const coupon = new URLSearchParams(location.search).get("coupon");
    window.location.href = "/app" + (coupon ? "?coupon=" + encodeURIComponent(coupon) : "");
  }
});

// Campaña: lo que guardó analytics.js, o los utm_* de esta misma URL si cayó directo en /register.
function leerUtm() {
  try {
    const s = JSON.parse(localStorage.getItem("mailmask_utm") || "null");
    if (s && s.at && Date.now() - s.at < 30 * 864e5) return { source: s.source || undefined, medium: s.medium || undefined, campaign: s.campaign || undefined };
  } catch (e) {}
  const q = new URLSearchParams(location.search);
  const utm = { source: q.get("utm_source") || undefined, medium: q.get("utm_medium") || undefined, campaign: q.get("utm_campaign") || undefined };
  return utm.source || utm.medium || utm.campaign ? utm : undefined;
}

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

  // Turnstile deja el token en un input oculto que inyecta el widget. Si el reto
  // aún no terminó, el campo está vacío y el servidor lo rechaza: mejor decirlo
  // aquí que mandar una alta que va a fallar.
  const turnstileToken = form.querySelector('[name="cf-turnstile-response"]')?.value || "";
  if (window.turnstile && !turnstileToken) {
    errEl.textContent = "Espera a que termine la verificación de seguridad.";
    errEl.classList.remove("hidden");
    return;
  }
  const res = await fetch("/api/auth/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      email: form.email.value,
      password: form.password.value,
      ref,
      turnstileToken,
      utm: leerUtm(),
    }),
  });

  if (res.ok) {
    localStorage.removeItem("mailmask_ref");
    localStorage.removeItem("mailmask_utm");
    // beacon: sobrevive a la redirección que sigue.
    if (window.gtag) window.gtag("event", "sign_up", { method: "password", transport_type: "beacon" });
    const coupon = new URLSearchParams(location.search).get("coupon");
    window.location.href = "/app" + (coupon ? "?coupon=" + encodeURIComponent(coupon) : "");
  } else {
    const data = await res.json();
    errEl.textContent = data.error || "Error al crear cuenta";
    errEl.classList.remove("hidden");
    // Cada token de Turnstile sirve una sola vez: sin reiniciarlo, el segundo
    // intento fallaría siempre aunque el usuario corrija el correo.
    window.turnstile?.reset();
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
  const utm = leerUtm() || {};
  if (utm.source) q.set("utm_source", utm.source);
  if (utm.medium) q.set("utm_medium", utm.medium);
  if (utm.campaign) q.set("utm_campaign", utm.campaign);
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
