fetch("/api/auth/me").then(r => {
  if (r.ok) {
    const coupon = new URLSearchParams(location.search).get("coupon");
    window.location.href = "/app" + (coupon ? "?coupon=" + encodeURIComponent(coupon) : "");
  }
});

const _refParam = new URLSearchParams(location.search).get("ref");
if (_refParam) localStorage.setItem("mailmask_ref", _refParam);
const _hasRef = _refParam || localStorage.getItem("mailmask_ref");
if (_hasRef) {
  document.getElementById("referral-card")?.classList.remove("hidden");
  const inviterEl = document.getElementById("referral-inviter");
  if (inviterEl) inviterEl.textContent = _hasRef;
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
