document.getElementById("forgot-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const btn = form.querySelector("button[type=submit]");
  const errEl = document.getElementById("error");
  const successEl = document.getElementById("success");
  errEl.classList.add("hidden");
  successEl.classList.add("hidden");
  // Turnstile deja el token en un input oculto que inyecta el widget. Si el reto
  // aún no terminó, el campo está vacío y el servidor lo rechazaría.
  const turnstileToken = form.querySelector('[name="cf-turnstile-response"]')?.value || "";
  if (window.turnstile && !turnstileToken) {
    errEl.textContent = "Espera a que termine la verificación de seguridad.";
    errEl.classList.remove("hidden");
    return;
  }

  btn.disabled = true;
  btn.textContent = "Enviando...";

  try {
    const res = await fetch("/api/auth/forgot-password", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: form.email.value, turnstileToken }),
    });

    if (res.ok) {
      successEl.textContent = "Si el email existe en nuestro sistema, recibirás un enlace para restablecer tu contraseña.";
      successEl.classList.remove("hidden");
      btn.disabled = true;
      btn.textContent = "Enlace enviado";
    } else {
      const data = await res.json();
      errEl.textContent = data.error || "Error al enviar";
      errEl.classList.remove("hidden");
      btn.disabled = false;
      btn.textContent = "Enviar enlace";
      // Cada token de Turnstile sirve una sola vez.
      window.turnstile?.reset();
    }
  } catch {
    errEl.textContent = "Error de conexión";
    errEl.classList.remove("hidden");
    btn.disabled = false;
    btn.textContent = "Enviar enlace";
    window.turnstile?.reset();
  }
});
