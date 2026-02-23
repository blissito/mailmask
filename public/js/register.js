fetch("/api/auth/me").then(r => {
  if (r.ok) {
    const coupon = new URLSearchParams(location.search).get("coupon");
    window.location.href = "/app" + (coupon ? "?coupon=" + encodeURIComponent(coupon) : "");
  }
});

if (localStorage.getItem("mailmask_ref") || new URLSearchParams(location.search).get("ref")) {
  document.getElementById("referral-card")?.classList.remove("hidden");
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
