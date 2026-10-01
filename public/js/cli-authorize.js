// Confirma el device-code de `mailmask login` (POST /api/cli/device/confirm,
// con sesión de cookie y el CSRF de siempre). El mismo patrón que docs-keys.js.
(async () => {
  const loading = document.getElementById("loading");
  const anon = document.getElementById("anon");
  const auth = document.getElementById("auth");
  const done = document.getElementById("done");
  const errEl = document.getElementById("error");
  const input = document.getElementById("user-code");
  const btn = document.getElementById("confirm-btn");

  const userCode = new URLSearchParams(location.search).get("user_code") || "";
  if (userCode) input.value = userCode.toUpperCase();

  let me = null;
  try {
    const res = await fetch("/api/auth/me");
    if (res.ok) me = await res.json();
  } catch {}

  loading.classList.add("hidden");
  if (!me) {
    anon.classList.remove("hidden");
    return;
  }
  auth.classList.remove("hidden");
  auth.querySelector("[data-email]").textContent = me.email;
  input.focus();

  btn.addEventListener("click", async () => {
    const code = input.value.trim().toUpperCase();
    if (!code) return;
    errEl.classList.add("hidden");
    btn.disabled = true;
    btn.textContent = "Autorizando…";
    const csrf = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]*)/)?.[1] ?? "";
    try {
      const res = await fetch("/api/cli/device/confirm", {
        method: "POST",
        headers: { "content-type": "application/json", "x-csrf-token": csrf },
        body: JSON.stringify({ userCode: code }),
      });
      if (res.ok) {
        auth.classList.add("hidden");
        done.classList.remove("hidden");
      } else {
        const data = await res.json().catch(() => ({}));
        errEl.textContent = data.error || "Código inválido o vencido";
        errEl.classList.remove("hidden");
        btn.disabled = false;
        btn.textContent = "Autorizar";
      }
    } catch {
      errEl.textContent = "Error de conexión";
      errEl.classList.remove("hidden");
      btn.disabled = false;
      btn.textContent = "Autorizar";
    }
  });
})();
