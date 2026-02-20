document.getElementById("forgot-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const btn = form.querySelector("button[type=submit]");
  const errEl = document.getElementById("error");
  const successEl = document.getElementById("success");
  errEl.classList.add("hidden");
  successEl.classList.add("hidden");
  btn.disabled = true;
  btn.textContent = "Enviando...";

  try {
    const res = await fetch("/api/auth/forgot-password", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: form.email.value }),
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
    }
  } catch {
    errEl.textContent = "Error de conexión";
    errEl.classList.remove("hidden");
    btn.disabled = false;
    btn.textContent = "Enviar enlace";
  }
});
