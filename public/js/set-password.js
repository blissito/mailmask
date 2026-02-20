const token = new URLSearchParams(location.search).get("token");
if (!token) {
  document.getElementById("error").textContent = "Enlace inválido. Revisa tu correo.";
  document.getElementById("error").classList.remove("hidden");
  document.getElementById("btn").disabled = true;
}

document.getElementById("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const pw = document.getElementById("password").value;
  const confirm = document.getElementById("confirm").value;
  const err = document.getElementById("error");
  const btn = document.getElementById("btn");

  if (pw !== confirm) {
    err.textContent = "Las contraseñas no coinciden";
    err.classList.remove("hidden");
    return;
  }

  btn.disabled = true;
  btn.textContent = "Guardando...";
  err.classList.add("hidden");

  try {
    const res = await fetch("/api/auth/set-password", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token, password: pw }),
    });
    const data = await res.json();
    if (data.ok) {
      location.href = "/app";
    } else {
      err.textContent = data.error || "Error al guardar";
      err.classList.remove("hidden");
      btn.disabled = false;
      btn.textContent = "Guardar contraseña";
    }
  } catch {
    err.textContent = "Error de conexión";
    err.classList.remove("hidden");
    btn.disabled = false;
    btn.textContent = "Guardar contraseña";
  }
});
