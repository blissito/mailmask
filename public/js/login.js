fetch("/api/auth/me").then(r => {
  if (r.ok) {
    const coupon = new URLSearchParams(location.search).get("coupon");
    window.location.href = "/app" + (coupon ? "?coupon=" + encodeURIComponent(coupon) : "");
  }
});

document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const btn = form.querySelector("button[type=submit]");
  const errEl = document.getElementById("error");
  errEl.classList.add("hidden");
  btn.disabled = true;
  btn.textContent = "Entrando...";

  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        email: form.email.value,
        password: form.password.value,
      }),
    });

    if (res.ok) {
      const coupon = new URLSearchParams(location.search).get("coupon");
      window.location.href = "/app" + (coupon ? "?coupon=" + encodeURIComponent(coupon) : "");
    } else {
      const data = await res.json();
      errEl.textContent = data.error || "Error al iniciar sesión";
      errEl.classList.remove("hidden");
      btn.disabled = false;
      btn.textContent = "Entrar";
    }
  } catch {
    errEl.textContent = "Error de conexión";
    errEl.classList.remove("hidden");
    btn.disabled = false;
    btn.textContent = "Entrar";
  }
});
