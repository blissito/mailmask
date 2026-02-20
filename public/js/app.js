function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// --- State ---
let currentUser = null;
let domains = [];
let selectedDomain = null;

// --- Init ---
document.addEventListener("DOMContentLoaded", async () => {
  await checkAuth();
  await loadDomains();
  setupEventListeners();
});

async function checkAuth() {
  const res = await fetch("/api/auth/me");
  if (!res.ok) {
    window.location.href = "/login";
    return;
  }
  currentUser = await res.json();
  document.getElementById("user-email").textContent = currentUser.email;
  renderBillingBanner();

  // Handle query param redirects
  const params = new URLSearchParams(window.location.search);
  if (params.get("billing") === "success") {
    showToast("Plan activado exitosamente");
    window.history.replaceState({}, "", "/app");
  }
  if (params.get("verified") === "true") {
    showToast("Email verificado exitosamente");
    window.history.replaceState({}, "", "/app");
  }
}

function renderBillingBanner() {
  const container = document.getElementById("billing-banner");
  if (!container) return;

  const sub = currentUser.subscription;
  const planName = sub?.plan ? sub.plan.charAt(0).toUpperCase() + sub.plan.slice(1) : "Ninguno";
  const periodEnd = sub?.currentPeriodEnd ? new Date(sub.currentPeriodEnd) : null;
  const isExpired = periodEnd && periodEnd < new Date();
  const isActive = sub && sub.status === "active" && !isExpired;
  const isCancelledWithAccess = sub && sub.status === "cancelled" && periodEnd && !isExpired;

  if (isActive) {
    container.innerHTML = `
      <div class="bg-green-900/20 border border-green-800/50 rounded-lg px-4 py-3 flex items-center justify-between">
        <span class="text-sm text-green-400">Plan ${esc(planName)} — Activo</span>
        <div class="flex items-center gap-4">
          <span class="text-xs text-zinc-500">Hasta ${periodEnd ? periodEnd.toLocaleDateString("es-MX") : "—"}</span>
          <button id="btn-cancel-sub" class="text-xs text-zinc-500 hover:text-red-400 transition-colors underline">Cancelar suscripción</button>
        </div>
      </div>`;
    document.getElementById("btn-cancel-sub")?.addEventListener("click", cancelSubscription);
  } else if (isCancelledWithAccess) {
    container.innerHTML = `
      <div class="bg-yellow-900/20 border border-yellow-800/50 rounded-lg px-4 py-3 flex items-center justify-between">
        <span class="text-sm text-yellow-400">Plan ${esc(planName)} — Tu plan se cancela el ${periodEnd.toLocaleDateString("es-MX")}</span>
        <button id="btn-checkout" class="bg-mask-600 hover:bg-mask-700 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors">
          Reactivar Plan
        </button>
      </div>`;
    document.getElementById("btn-checkout")?.addEventListener("click", startCheckout);
  } else if (isExpired) {
    container.innerHTML = `
      <div class="bg-red-900/20 border border-red-800/50 rounded-lg px-4 py-3 flex items-center justify-between">
        <span class="text-sm text-red-400">Tu plan expiró — Reactiva para continuar</span>
        <button id="btn-checkout" class="bg-mask-600 hover:bg-mask-700 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors">
          Reactivar Plan
        </button>
      </div>`;
    document.getElementById("btn-checkout")?.addEventListener("click", startCheckout);
  } else {
    container.innerHTML = `
      <div class="bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-3 flex items-center justify-between">
        <span class="text-sm text-zinc-400">Sin plan activo — Activa tu plan para agregar dominios</span>
        <button id="btn-checkout" class="bg-mask-600 hover:bg-mask-700 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors">
          Activar Plan — $49/mes
        </button>
      </div>`;
    document.getElementById("btn-checkout")?.addEventListener("click", startCheckout);
  }

  // Disable add domain button if no active/grace-period plan
  const addDomainBtn = document.getElementById("btn-add-domain");
  if (addDomainBtn && !isActive && !isCancelledWithAccess) {
    addDomainBtn.disabled = true;
    addDomainBtn.classList.add("opacity-50", "cursor-not-allowed");
    addDomainBtn.title = "Necesitas un plan activo";
  }
}

async function startCheckout() {
  const btn = document.getElementById("btn-checkout");
  if (btn) { btn.textContent = "Redirigiendo..."; btn.disabled = true; }
  try {
    const res = await fetch("/api/billing/checkout", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ plan: "basico", billing: "monthly" }),
    });
    const data = await res.json();
    if (data.init_point) {
      window.location.href = data.init_point;
    } else {
      showToast(data.error || "Error al iniciar pago", true);
      if (btn) { btn.textContent = "Activar Plan — $49/mes"; btn.disabled = false; }
    }
  } catch {
    showToast("Error de conexión", true);
    if (btn) { btn.textContent = "Activar Plan — $49/mes"; btn.disabled = false; }
  }
}

async function cancelSubscription() {
  if (!confirm("¿Estás seguro de que quieres cancelar tu suscripción? Perderás acceso a las funciones de tu plan.")) return;
  try {
    const res = await fetch("/api/billing/cancel", { method: "POST" });
    const data = await res.json();
    if (data.ok) {
      showToast("Suscripción cancelada");
      setTimeout(() => window.location.reload(), 1000);
    } else {
      showToast(data.error || "Error al cancelar", true);
    }
  } catch {
    showToast("Error de conexión", true);
  }
}

function showToast(message, isError = false) {
  const toast = document.createElement("div");
  toast.className = `fixed top-4 right-4 z-50 px-4 py-3 rounded-lg text-sm font-medium transition-opacity ${isError ? 'bg-red-900/90 text-red-200' : 'bg-green-900/90 text-green-200'}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => { toast.style.opacity = "0"; setTimeout(() => toast.remove(), 300); }, 3000);
}

// --- Domains ---

async function loadDomains() {
  const res = await fetch("/api/domains");
  if (!res.ok) return;
  domains = await res.json();
  renderDomains();
}

function renderDomains() {
  const list = document.getElementById("domains-list");
  const empty = document.getElementById("empty-state");

  if (domains.length === 0) {
    list.innerHTML = "";
    empty.classList.remove("hidden");
    return;
  }

  empty.classList.add("hidden");
  list.innerHTML = domains.map(d => `
    <div class="bg-zinc-900 border border-zinc-800 rounded-xl p-4 flex items-center justify-between cursor-pointer hover:border-zinc-600 transition-colors"
         onclick="selectDomain('${esc(d.id)}')">
      <div>
        <span class="font-semibold text-lg">${esc(d.domain)}</span>
        <span class="ml-3 text-xs px-2 py-0.5 rounded-full ${d.verified ? 'bg-green-900/50 text-green-400' : 'bg-yellow-900/50 text-yellow-400'}">
          ${d.verified ? 'Verificado' : 'Pendiente DNS'}
        </span>
      </div>
      <svg class="w-5 h-5 text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
      </svg>
    </div>
  `).join("");
}

async function selectDomain(id) {
  selectedDomain = domains.find(d => d.id === id);
  if (!selectedDomain) return;

  document.getElementById("domains-list").classList.add("hidden");
  document.getElementById("empty-state").classList.add("hidden");
  document.getElementById("domain-detail").classList.remove("hidden");
  document.querySelector(".flex.items-center.justify-between.mb-6").classList.add("hidden");

  document.getElementById("detail-domain-name").textContent = selectedDomain.domain;
  const statusEl = document.getElementById("detail-status");
  statusEl.textContent = selectedDomain.verified ? "Verificado" : "Pendiente DNS";
  statusEl.className = `text-xs px-2 py-1 rounded-full ${selectedDomain.verified ? 'bg-green-900/50 text-green-400' : 'bg-yellow-900/50 text-yellow-400'}`;

  document.getElementById("alias-domain-suffix").textContent = `@${selectedDomain.domain}`;

  // Load default tab
  switchTab("aliases");
  await loadAliases();
}

function goBack() {
  selectedDomain = null;
  document.getElementById("domain-detail").classList.add("hidden");
  document.getElementById("domains-list").classList.remove("hidden");
  document.querySelector(".flex.items-center.justify-between.mb-6").classList.remove("hidden");
  renderDomains();
}

// --- Aliases ---

async function loadAliases() {
  if (!selectedDomain) return;
  const res = await fetch(`/api/domains/${selectedDomain.id}/aliases`);
  if (!res.ok) return;
  const aliases = await res.json();
  renderAliases(aliases);
}

function renderAliases(aliases) {
  const list = document.getElementById("aliases-list");
  const empty = document.getElementById("aliases-empty");

  if (aliases.length === 0) {
    list.innerHTML = "";
    empty.classList.remove("hidden");
    return;
  }

  empty.classList.add("hidden");
  list.innerHTML = aliases.map(a => `
    <div class="bg-zinc-800/50 border border-zinc-800 rounded-lg p-3 flex items-center justify-between">
      <div>
        <span class="font-mono text-sm ${a.enabled ? 'text-zinc-100' : 'text-zinc-500 line-through'}">
          ${a.alias === '*' ? '*' : esc(a.alias)}@${esc(selectedDomain.domain)}
        </span>
        <span class="text-zinc-500 mx-2">→</span>
        <span class="text-sm text-zinc-400">${esc(a.destinations.join(", "))}</span>
        ${a.forwardCount ? `<span class="text-xs text-zinc-500 ml-2">${a.forwardCount} reenviado${a.forwardCount === 1 ? '' : 's'}${a.lastFrom ? ` · último de ${esc(a.lastFrom)}` : ''}</span>` : ''}
      </div>
      <div class="flex items-center gap-2">
        <button onclick="toggleAlias('${esc(a.alias)}', ${!a.enabled})" class="text-xs px-2 py-1 rounded ${a.enabled ? 'bg-green-900/30 text-green-400' : 'bg-zinc-700 text-zinc-400'}">${a.enabled ? 'Activo' : 'Inactivo'}</button>
        <button onclick="removeAlias('${esc(a.alias)}')" class="text-xs text-zinc-500 hover:text-red-400 transition-colors">Eliminar</button>
      </div>
    </div>
  `).join("");
}

async function toggleAlias(alias, enabled) {
  await fetch(`/api/domains/${selectedDomain.id}/aliases/${alias}`, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ enabled }),
  });
  await loadAliases();
}

async function removeAlias(alias) {
  if (!confirm(`¿Eliminar alias ${alias}@${selectedDomain.domain}?`)) return;
  await fetch(`/api/domains/${selectedDomain.id}/aliases/${alias}`, { method: "DELETE" });
  await loadAliases();
}

// --- Rules ---

async function loadRules() {
  if (!selectedDomain) return;
  const res = await fetch(`/api/domains/${selectedDomain.id}/rules`);
  if (!res.ok) return;
  const rules = await res.json();
  renderRules(rules);
}

function renderRules(rules) {
  const list = document.getElementById("rules-list");
  const empty = document.getElementById("rules-empty");

  if (rules.length === 0) {
    list.innerHTML = "";
    empty.classList.remove("hidden");
    return;
  }

  empty.classList.add("hidden");
  const fieldLabels = { to: "Para", from: "De", subject: "Asunto" };
  const matchLabels = { contains: "contiene", equals: "es", regex: "regex" };
  const actionLabels = { forward: "→ Reenviar", webhook: "⚡ Webhook", discard: "🗑 Descartar" };

  list.innerHTML = rules.map(r => `
    <div class="bg-zinc-800/50 border border-zinc-800 rounded-lg p-3 flex items-center justify-between">
      <div class="text-sm">
        <span class="text-zinc-400">Si</span>
        <span class="text-zinc-200 font-semibold">${fieldLabels[r.field]}</span>
        <span class="text-zinc-400">${matchLabels[r.match]}</span>
        <span class="text-red-400 font-mono">"${esc(r.value)}"</span>
        <span class="text-zinc-400 mx-1">→</span>
        <span class="text-zinc-200">${actionLabels[r.action]}</span>
        ${r.target ? `<span class="text-zinc-400 ml-1">${esc(r.target)}</span>` : ''}
      </div>
      <button onclick="removeRule('${esc(r.id)}')" class="text-xs text-zinc-500 hover:text-red-400 transition-colors">Eliminar</button>
    </div>
  `).join("");
}

async function removeRule(ruleId) {
  if (!confirm("¿Eliminar esta regla?")) return;
  await fetch(`/api/domains/${selectedDomain.id}/rules/${ruleId}`, { method: "DELETE" });
  await loadRules();
}

// --- Logs ---

async function loadLogs() {
  if (!selectedDomain) return;
  const res = await fetch(`/api/domains/${selectedDomain.id}/logs?limit=50`);
  if (!res.ok) return;
  const logs = await res.json();
  renderLogs(logs);
}

function renderLogs(logs) {
  const list = document.getElementById("logs-list");
  const empty = document.getElementById("logs-empty");

  if (logs.length === 0) {
    list.innerHTML = "";
    empty.classList.remove("hidden");
    return;
  }

  empty.classList.add("hidden");
  const statusColors = {
    forwarded: "text-green-400",
    discarded: "text-zinc-500",
    failed: "text-red-400",
    rule_matched: "text-yellow-400",
  };
  const statusIcons = {
    forwarded: "✓",
    discarded: "—",
    failed: "✗",
    rule_matched: "⚡",
  };

  list.innerHTML = logs.map(l => {
    const date = new Date(l.timestamp);
    const time = date.toLocaleString("es-MX", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
    return `
      <div class="grid grid-cols-[80px_1fr_1fr_80px_24px] gap-2 text-xs py-2 border-b border-zinc-800/50 items-center">
        <span class="text-zinc-500">${time}</span>
        <span class="text-zinc-300 truncate" title="${esc(l.from)}">${esc(l.from)}</span>
        <span class="text-zinc-400 truncate" title="${esc(l.subject)}">${esc(l.subject)}</span>
        <span class="text-zinc-500 truncate">${l.forwardedTo ? esc(l.forwardedTo) : '—'}</span>
        <span class="${statusColors[l.status]}">${statusIcons[l.status]}</span>
      </div>
    `;
  }).join("");
}

// --- DNS ---

function renderDnsRecords() {
  if (!selectedDomain) return;
  const records = document.getElementById("dns-records");

  const dnsItems = [
    { type: "MX", name: selectedDomain.domain, value: "10 inbound-smtp.us-east-1.amazonaws.com" },
    { type: "TXT", name: `_amazonses.${selectedDomain.domain}`, value: selectedDomain.verificationToken },
    ...selectedDomain.dkimTokens.map(token => ({
      type: "CNAME",
      name: `${token}._domainkey.${selectedDomain.domain}`,
      value: `${token}.dkim.amazonses.com`,
    })),
  ];

  records.innerHTML = dnsItems.map(r => `
    <div class="bg-zinc-800/50 border border-zinc-800 rounded-lg p-3">
      <div class="flex items-center gap-2 mb-1">
        <span class="text-xs font-mono bg-zinc-700 px-2 py-0.5 rounded">${r.type}</span>
        <span class="text-sm text-zinc-300 font-mono truncate">${r.name}</span>
      </div>
      <div class="flex items-center gap-2">
        <code class="text-xs text-zinc-400 bg-zinc-900 px-2 py-1 rounded flex-1 truncate">${r.value}</code>
        <button onclick="navigator.clipboard.writeText('${esc(r.value)}')" class="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">Copiar</button>
      </div>
    </div>
  `).join("");
}

async function verifyDns() {
  const resultEl = document.getElementById("verify-result");
  resultEl.textContent = "Verificando...";
  resultEl.className = "ml-3 text-sm text-zinc-400";

  const res = await fetch(`/api/domains/${selectedDomain.id}/verify`, { method: "POST" });
  const data = await res.json();

  if (data.verified) {
    resultEl.textContent = "✓ Dominio verificado";
    resultEl.className = "ml-3 text-sm text-green-400";
    selectedDomain.verified = true;
    // Update status badge
    const statusEl = document.getElementById("detail-status");
    statusEl.textContent = "Verificado";
    statusEl.className = "text-xs px-2 py-1 rounded-full bg-green-900/50 text-green-400";
  } else {
    resultEl.textContent = "✗ DNS no configurado aún. Verifica los registros e intenta de nuevo.";
    resultEl.className = "ml-3 text-sm text-yellow-400";
  }
}

// --- Tabs ---

function switchTab(tab) {
  document.querySelectorAll(".tab-content").forEach(el => el.classList.add("hidden"));
  document.querySelectorAll(".tab-btn").forEach(el => {
    el.classList.remove("active-tab", "text-zinc-100");
    el.classList.add("text-zinc-500");
  });

  document.getElementById(`tab-${tab}`).classList.remove("hidden");
  const activeBtn = document.querySelector(`.tab-btn[data-tab="${tab}"]`);
  activeBtn.classList.add("active-tab", "text-zinc-100");
  activeBtn.classList.remove("text-zinc-500");

  // Load tab data
  if (tab === "aliases") loadAliases();
  else if (tab === "rules") loadRules();
  else if (tab === "logs") loadLogs();
  else if (tab === "dns") renderDnsRecords();
}

// --- Modals ---

function showModal(id) {
  document.getElementById(id).classList.remove("hidden");
}

function hideModal(id) {
  document.getElementById(id).classList.add("hidden");
}

function showAddDomainModal() {
  showModal("modal-add-domain");
}

// --- Event listeners ---

function setupEventListeners() {
  // Logout
  document.getElementById("btn-logout").addEventListener("click", async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    window.location.href = "/login";
  });

  // Add domain button
  document.getElementById("btn-add-domain").addEventListener("click", showAddDomainModal);

  // Back button
  document.getElementById("btn-back").addEventListener("click", goBack);

  // Tab buttons
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  // Add alias button
  document.getElementById("btn-add-alias").addEventListener("click", () => showModal("modal-add-alias"));

  // Add rule button
  document.getElementById("btn-add-rule").addEventListener("click", () => showModal("modal-add-rule"));

  // Verify DNS button
  document.getElementById("btn-verify-dns").addEventListener("click", verifyDns);

  // Form: Add domain
  document.getElementById("form-add-domain").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    const errEl = document.getElementById("add-domain-error");
    errEl.classList.add("hidden");

    const res = await fetch("/api/domains", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ domain: form.domain.value.trim().toLowerCase() }),
    });

    if (res.ok) {
      const data = await res.json();
      hideModal("modal-add-domain");
      form.reset();
      await loadDomains();
      // Auto-select the new domain and show DNS tab
      selectDomain(data.domain.id);
      switchTab("dns");
    } else {
      const data = await res.json();
      errEl.textContent = data.error || "Error al agregar dominio";
      errEl.classList.remove("hidden");
    }
  });

  // Form: Add alias
  document.getElementById("form-add-alias").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    const errEl = document.getElementById("add-alias-error");
    errEl.classList.add("hidden");

    const destinations = form.destinations.value.split(",").map(d => d.trim().toLowerCase()).filter(Boolean);
    if (destinations.length === 0) {
      errEl.textContent = "Agrega al menos un destino";
      errEl.classList.remove("hidden");
      return;
    }
    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const invalid = destinations.filter(d => !emailRe.test(d));
    if (invalid.length) {
      errEl.textContent = `Email(s) inválido(s): ${invalid.join(", ")}`;
      errEl.classList.remove("hidden");
      return;
    }

    const res = await fetch(`/api/domains/${selectedDomain.id}/aliases`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ alias: form.alias.value.trim().toLowerCase(), destinations }),
    });

    if (res.ok) {
      hideModal("modal-add-alias");
      form.reset();
      await loadAliases();
    } else {
      const data = await res.json();
      errEl.textContent = data.error || "Error al crear alias";
      errEl.classList.remove("hidden");
    }
  });

  // Form: Add rule
  document.getElementById("form-add-rule").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    const errEl = document.getElementById("add-rule-error");
    errEl.classList.add("hidden");

    const res = await fetch(`/api/domains/${selectedDomain.id}/rules`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        field: form.field.value,
        match: form.match.value,
        value: form.value.value,
        action: form.action.value,
        target: form.target.value || "",
      }),
    });

    if (res.ok) {
      hideModal("modal-add-rule");
      form.reset();
      await loadRules();
    } else {
      const data = await res.json();
      errEl.textContent = data.error || "Error al crear regla";
      errEl.classList.remove("hidden");
    }
  });

  // Close modals on backdrop click
  document.querySelectorAll("[id^='modal-']").forEach(modal => {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) hideModal(modal.id);
    });
  });

  // ESC to close modals
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      document.querySelectorAll("[id^='modal-']:not(.hidden)").forEach(m => hideModal(m.id));
    }
  });
}
