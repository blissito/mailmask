// Generador de API key dentro de /docs. Con sesión abierta crea la llave aquí mismo
// (POST /api/api-keys, con el CSRF de la cookie) y rellena el comando de `claude mcp add`;
// sin sesión deja el enlace al dashboard. La llave se muestra una sola vez, como en /app.
(async () => {
  const box = document.getElementById("docs-key");
  if (!box) return;
  const anon = box.querySelector("[data-anon]");
  const auth = box.querySelector("[data-auth]");
  const btn = box.querySelector("[data-generate]");
  const out = box.querySelector("[data-result]");

  let me = null;
  try {
    const res = await fetch("/api/auth/me");
    if (res.ok) me = await res.json();
  } catch {}
  if (!me) { anon.classList.remove("hidden"); return; }
  auth.classList.remove("hidden");
  auth.querySelector("[data-email]").textContent = me.email;

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.textContent = "Generando…";
    const csrf = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]*)/)?.[1] ?? "";
    let key = null, error = null;
    try {
      const res = await fetch("/api/api-keys", {
        method: "POST",
        headers: { "content-type": "application/json", "x-csrf-token": csrf },
        body: JSON.stringify({ name: "Agente (desde /docs)" }),
      });
      const data = await res.json();
      if (res.ok) key = data.key; else error = data.error || `Error ${res.status}`;
    } catch (e) { error = String(e); }
    btn.classList.add("hidden");
    if (!key) {
      out.innerHTML = `<p class="text-red-500 text-sm">${error}</p>`;
      out.classList.remove("hidden");
      return;
    }
    const esc = (t) => t.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
    out.innerHTML = `
      <p class="text-sm text-fg mb-2"><strong>Tu API key</strong> — cópiala ahora, no se vuelve a mostrar:</p>
      <pre class="bg-bg-elev border border-line rounded-lg p-4 overflow-x-auto text-sm font-mono mb-3"><code>${esc(key)}</code></pre>
      <p class="text-sm text-fg-muted mb-2">Y el MCP listo para pegar en Claude Code:</p>
      <pre class="bg-bg-elev border border-line rounded-lg p-4 overflow-x-auto text-sm font-mono mb-2"><code>claude mcp add --transport http mailmask https://www.mailmask.studio/mcp \\
  --header "Authorization: Bearer ${esc(key)}"</code></pre>`;
    out.classList.remove("hidden");
    // Botones de copiar, igual que en el resto de la página
    out.querySelectorAll("pre").forEach((pre) => {
      const b = document.createElement("button");
      b.className = "copy-btn";
      b.textContent = "Copiar";
      b.addEventListener("click", async () => {
        await navigator.clipboard.writeText(pre.querySelector("code").textContent);
        b.textContent = "Copiado!";
        setTimeout(() => (b.textContent = "Copiar"), 1500);
      });
      pre.appendChild(b);
    });
  });
})();
