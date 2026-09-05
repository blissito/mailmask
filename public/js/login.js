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

// Login con Google: el callback vuelve a /login?error=... si algo falló.
(() => {
  const params = new URLSearchParams(location.search);
  const err = params.get("error");
  if (err && err.startsWith("google")) {
    const msgs = {
      "google-cancelado": "Cancelaste el acceso con Google.",
      "google-no-verificado": "Google no tiene verificado ese correo. Usa otro o crea cuenta con contraseña.",
      "google-state": "La sesión de Google caducó. Inténtalo de nuevo.",
    };
    const errEl = document.getElementById("error");
    errEl.textContent = msgs[err] || "No se pudo entrar con Google. Inténtalo de nuevo.";
    errEl.classList.remove("hidden");
  }
  const coupon = params.get("coupon");
  const a = document.getElementById("google-login");
  if (a && coupon) a.href = "/api/auth/google?coupon=" + encodeURIComponent(coupon);
})();

// El formulario de contraseña va escondido: Google es el camino principal.
(() => {
  const btn = document.getElementById("show-password-form");
  const form = document.getElementById("login-form");
  if (!btn || !form) return;
  const reveal = () => {
    form.classList.remove("hidden");
    btn.classList.add("hidden");
    form.email.focus();
  };
  btn.addEventListener("click", reveal);
  // Si Google falló o el navegador ya rellenó el correo, mostrarlo de una vez.
  const params = new URLSearchParams(location.search);
  if (params.get("password") === "1" || (params.get("error") || "").startsWith("google")) reveal();
})();
