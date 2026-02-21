fetch("/api/auth/me").then(r => { if (r.ok) window.location.href = "/app"; });

// Persist coupon from URL to localStorage
const _couponParam = new URLSearchParams(location.search).get("coupon");
if (_couponParam) localStorage.setItem("mailmask_coupon", _couponParam);

document.getElementById("register-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const errEl = document.getElementById("error");
  errEl.classList.add("hidden");

  const res = await fetch("/api/auth/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      email: form.email.value,
      password: form.password.value,
    }),
  });

  if (res.ok) {
    window.location.href = "/app";
  } else {
    const data = await res.json();
    errEl.textContent = data.error || "Error al crear cuenta";
    errEl.classList.remove("hidden");
  }
});
