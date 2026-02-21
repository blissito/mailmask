function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// --- State ---
let currentUser = null;
let domains = [];
let selectedDomain = null;

async function refreshUsage() {
  const res = await fetch("/api/auth/me");
  if (!res.ok) return;
  currentUser = await res.json();
  renderUsage();
}

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
  renderVerifyBanner();
  renderBillingBanner();
  renderUsage();

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

function renderVerifyBanner() {
  const container = document.getElementById("verify-banner");
  if (!container || currentUser.emailVerified) return;
  container.innerHTML = `
    <div class="bg-yellow-900/20 border border-yellow-800/50 rounded-lg px-4 py-3 flex items-center justify-between">
      <span class="text-sm text-yellow-400">Verifica tu email para acceder a todas las funciones.</span>
      <button id="btn-resend-verify" class="text-xs text-yellow-400 hover:text-yellow-300 underline transition-colors">Reenviar email</button>
    </div>`;
  document.getElementById("btn-resend-verify").addEventListener("click", async () => {
    const btn = document.getElementById("btn-resend-verify");
    btn.textContent = "Enviando...";
    btn.disabled = true;
    try {
      const res = await fetch("/api/auth/resend-verification", { method: "POST" });
      const data = await res.json();
      if (res.ok) {
        showToast("Email de verificación enviado");
        btn.textContent = "Enviado ✓";
      } else {
        showToast(data.error || "Error enviando email", true);
        btn.textContent = "Reenviar email";
        btn.disabled = false;
      }
    } catch {
      showToast("Error de conexión", true);
      btn.textContent = "Reenviar email";
      btn.disabled = false;
    }
  });
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

  // Hide header add-domain button when no domains (empty state handles it)
  const addDomainBtn = document.getElementById("btn-add-domain");
  if (addDomainBtn) {
    addDomainBtn.classList.remove("hidden");
    if (!isActive && !isCancelledWithAccess) {
      addDomainBtn.disabled = true;
      addDomainBtn.classList.add("opacity-50", "cursor-not-allowed");
      addDomainBtn.title = "Necesitas un plan activo";
    } else {
      addDomainBtn.disabled = false;
      addDomainBtn.classList.remove("opacity-50", "cursor-not-allowed");
      addDomainBtn.title = "";
    }
  }
}

function renderUsage() {
  const container = document.getElementById("usage-banner");
  if (!container || !currentUser?.usage) return;

  const u = currentUser.usage;
  if (u.domains.limit === 0) { container.innerHTML = ""; return; }

  const items = [`Dominios ${u.domains.current}/${u.domains.limit}`];
  for (const a of u.aliasesPerDomain) {
    items.push(`Aliases — ${esc(a.domain)} ${a.current}/${a.limit}`);
  }

  container.innerHTML = `
    <div class="flex flex-wrap gap-3 text-xs text-zinc-400 px-1 py-2">
      ${items.map(i => `<span class="bg-zinc-800/60 border border-zinc-800 rounded px-2 py-1">${i}</span>`).join("")}
    </div>`;
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

    // Style empty-state CTA based on plan status
    const emptyBtn = document.getElementById("btn-add-domain-empty");
    if (emptyBtn) {
      const sub = currentUser?.subscription;
      const periodEnd = sub?.currentPeriodEnd ? new Date(sub.currentPeriodEnd) : null;
      const isExpired = periodEnd && periodEnd < new Date();
      const hasActivePlan = sub && (sub.status === "active" || sub.status === "cancelled") && !isExpired;

      if (hasActivePlan) {
        // Primary CTA: user has plan, needs to add domain
        emptyBtn.classList.remove("hidden");
        emptyBtn.className = "bg-mask-600 hover:bg-mask-700 text-white text-sm font-semibold px-6 py-3 rounded-lg transition-colors";
      } else {
        // No plan: hide entirely — billing banner is the sole CTA
        emptyBtn.classList.add("hidden");
      }
    }
    return;
  }

  empty.classList.add("hidden");
  list.innerHTML = domains.map(d => `
    <div class="bg-zinc-900 border border-zinc-800 rounded-xl px-6 py-5 flex items-center justify-between cursor-pointer hover:border-zinc-600 transition-colors"
         data-action="select-domain" data-domain-id="${esc(d.id)}">
      <div>
        <span class="font-semibold text-lg">${esc(d.domain)}</span>
        <span class="ml-3 text-xs px-2 py-0.5 rounded-full ${d.verified ? 'bg-green-900/50 text-green-400' : 'bg-yellow-900/50 text-yellow-400'}">
          ${d.verified ? 'Verificado' : 'Pendiente DNS'}
        </span>
        <div class="text-xs text-zinc-500 mt-1">${d.monthlyForwards ?? 0} reenvío${(d.monthlyForwards ?? 0) === 1 ? '' : 's'} este mes · límite ${d.forwardPerHour ?? 0}/hora</div>
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

async function deleteDomain() {
  if (!selectedDomain) return;
  if (!confirm(`¿Eliminar dominio ${selectedDomain.domain}? Se borrarán todos los aliases y reglas.`)) return;
  const res = await fetch(`/api/domains/${selectedDomain.id}`, { method: "DELETE" });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    alert(data.error || "Error al eliminar dominio");
    return;
  }
  goBack();
  await loadDomains();
  await refreshUsage();
}

// --- Aliases ---

async function loadAliases() {
  if (!selectedDomain) return;
  const res = await fetch(`/api/domains/${selectedDomain.id}/alias`);
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
    <div class="bg-zinc-800/50 border border-zinc-800 rounded-lg px-5 py-4 flex items-center justify-between">
      <div>
        <span class="font-mono text-sm ${a.enabled ? 'text-zinc-100' : 'text-zinc-500 line-through'}">
          ${a.alias === '*' ? '*' : esc(a.alias)}@${esc(selectedDomain.domain)}
        </span>
        <span class="text-zinc-500 mx-2">→</span>
        <span class="text-sm text-zinc-400">${esc(a.destinations.join(", "))}</span>
        ${a.forwardCount ? `<span class="text-xs text-zinc-500 ml-2">${a.forwardCount} reenviado${a.forwardCount === 1 ? '' : 's'}${a.lastFrom ? ` · último de ${esc(a.lastFrom)}` : ''}</span>` : ''}
      </div>
      <div class="flex items-center gap-2">
        <button data-action="toggle-alias" data-alias="${esc(a.alias)}" data-enabled="${!a.enabled}" class="text-xs px-2 py-1 rounded ${a.enabled ? 'bg-green-900/30 text-green-400' : 'bg-zinc-700 text-zinc-400'}">${a.enabled ? 'Activo' : 'Inactivo'}</button>
        <button data-action="remove-alias" data-alias="${esc(a.alias)}" class="text-xs text-zinc-500 hover:text-red-400 transition-colors">Eliminar</button>
      </div>
    </div>
  `).join("");
}

async function toggleAlias(alias, enabled) {
  await fetch(`/api/domains/${selectedDomain.id}/alias/${alias}`, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ enabled }),
  });
  await loadAliases();
}

async function removeAlias(alias) {
  if (!confirm(`¿Eliminar alias ${alias}@${selectedDomain.domain}?`)) return;
  await fetch(`/api/domains/${selectedDomain.id}/alias/${alias}`, { method: "DELETE" });
  await loadAliases();
  await refreshUsage();
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
    <div class="bg-zinc-800/50 border border-zinc-800 rounded-lg px-5 py-4 flex items-center justify-between">
      <div class="text-sm">
        <span class="text-zinc-400">Si</span>
        <span class="text-zinc-200 font-semibold">${fieldLabels[r.field]}</span>
        <span class="text-zinc-400">${matchLabels[r.match]}</span>
        <span class="text-red-400 font-mono">"${esc(r.value)}"</span>
        <span class="text-zinc-400 mx-1">→</span>
        <span class="text-zinc-200">${actionLabels[r.action]}</span>
        ${r.target ? `<span class="text-zinc-400 ml-1">${esc(r.target)}</span>` : ''}
      </div>
      <button data-action="remove-rule" data-rule-id="${esc(r.id)}" class="text-xs text-zinc-500 hover:text-red-400 transition-colors">Eliminar</button>
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

  const rows = logs.map(l => {
    const date = new Date(l.timestamp);
    const time = date.toLocaleString("es-MX", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
    return `
      <tr class="border-b border-zinc-800/50">
        <td class="py-2 pr-3 text-zinc-500 whitespace-nowrap">${time}</td>
        <td class="py-2 pr-3 text-zinc-300 truncate max-w-[200px]" title="${esc(l.from)}">${esc(l.from)}</td>
        <td class="py-2 pr-3 text-zinc-400 truncate max-w-[200px]" title="${esc(l.subject)}">${esc(l.subject)}</td>
        <td class="py-2 pr-3 text-zinc-500 truncate max-w-[120px]">${l.forwardedTo ? esc(l.forwardedTo) : '—'}</td>
        <td class="py-2 ${statusColors[l.status]}">${statusIcons[l.status]}</td>
      </tr>`;
  }).join("");

  list.innerHTML = `
    <thead>
      <tr class="border-b border-zinc-700 text-zinc-500">
        <th class="py-2 pr-3 font-medium text-left">Fecha</th>
        <th class="py-2 pr-3 font-medium text-left">De</th>
        <th class="py-2 pr-3 font-medium text-left">Asunto</th>
        <th class="py-2 pr-3 font-medium text-left">Destino</th>
        <th class="py-2 font-medium text-left">Estado</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>`;
}

// --- DNS ---

function renderDnsRecords() {
  if (!selectedDomain) return;
  const records = document.getElementById("dns-records");

  const d = selectedDomain.domain;
  const dnsItems = [
    {
      type: "MX",
      name: d,
      value: "10 inbound-smtp.us-east-1.amazonaws.com",
      hints: [
        `Algunos proveedores usan <strong>@</strong> en vez de <strong>${esc(d)}</strong> para el dominio raíz.`,
        `Si tu proveedor tiene un campo separado de <strong>Prioridad</strong>, pon <strong>10</strong> ahí y solo la dirección como valor.`,
      ],
    },
    {
      type: "TXT",
      name: `_amazonses.${d}`,
      value: selectedDomain.verificationToken,
      hints: [
        `Algunos proveedores agregan <strong>.${esc(d)}</strong> automáticamente al nombre — si es así, pon solo <strong>_amazonses</strong>.`,
        `Si tu proveedor pide comillas alrededor del valor, agrégalas: <strong>"${esc(selectedDomain.verificationToken)}"</strong>.`,
      ],
    },
    ...selectedDomain.dkimTokens.map(token => ({
      type: "CNAME",
      name: `${token}._domainkey.${d}`,
      value: `${token}.dkim.amazonses.com`,
      hints: [
        `Si tu proveedor agrega <strong>.${esc(d)}</strong> automáticamente, pon solo <strong>${esc(token)}._domainkey</strong>.`,
      ],
    })),
  ];

  // Only show DKIM hint once (on first CNAME)
  const sharedDkimHint = `Los 3 registros CNAME son para <strong>DKIM</strong> — la firma digital que evita que tus emails caigan en spam.`;
  if (dnsItems.length > 2) dnsItems[2].hints.unshift(sharedDkimHint);

  const copyBtn = (val) => `<button data-action="copy" data-copy-value="${esc(val)}" class="text-zinc-600 hover:text-white transition-colors shrink-0 p-1 rounded hover:bg-zinc-700" title="Copiar"><svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg></button>`;

  const hintIcon = `<svg class="w-3.5 h-3.5 text-zinc-600 shrink-0 mt-px" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`;

  const field = (label, val) => `
    <div class="mb-2">
      <div class="text-xs text-zinc-500 mb-1">${label}</div>
      <div class="flex items-center gap-2 bg-zinc-900 rounded-lg border border-zinc-800 px-3 py-2">
        <code class="text-xs text-zinc-300 font-mono break-all flex-1 select-all">${esc(val)}</code>
        ${copyBtn(val)}
      </div>
    </div>`;

  records.innerHTML = `
    <div class="divide-y divide-zinc-800/60">
      ${dnsItems.map(r => `
        <div class="px-4 py-4">
          <span class="inline-block font-mono font-bold text-xs text-zinc-100 bg-zinc-800 px-2 py-0.5 rounded mb-3">${r.type}</span>
          ${field("Nombre", r.name)}
          ${field("Valor", r.value)}
          ${r.hints.length ? `
            <div class="mt-3 space-y-1.5">
              ${r.hints.map(h => `
                <div class="flex items-start gap-2">
                  ${hintIcon}
                  <p class="text-xs text-zinc-500 leading-relaxed">${h}</p>
                </div>
              `).join("")}
            </div>
          ` : ""}
        </div>
      `).join("")}
    </div>`;
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
  document.getElementById("btn-delete-domain").addEventListener("click", deleteDomain);

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
      await refreshUsage();
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

    const res = await fetch(`/api/domains/${selectedDomain.id}/alias`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ alias: form.alias.value.trim().toLowerCase(), destinations }),
    });

    if (res.ok) {
      hideModal("modal-add-alias");
      form.reset();
      await loadAliases();
      await refreshUsage();
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

  // Empty state add domain button
  document.getElementById("btn-add-domain-empty")?.addEventListener("click", showAddDomainModal);

  // Cancel modal buttons
  document.querySelectorAll(".btn-cancel-modal").forEach(btn => {
    btn.addEventListener("click", () => hideModal(btn.dataset.modal));
  });

  // Event delegation: domains list
  document.getElementById("domains-list").addEventListener("click", (e) => {
    const el = e.target.closest("[data-action='select-domain']");
    if (el) selectDomain(el.dataset.domainId);
  });

  // Event delegation: aliases list
  document.getElementById("aliases-list").addEventListener("click", (e) => {
    const toggle = e.target.closest("[data-action='toggle-alias']");
    if (toggle) {
      toggleAlias(toggle.dataset.alias, toggle.dataset.enabled === "true");
      return;
    }
    const remove = e.target.closest("[data-action='remove-alias']");
    if (remove) removeAlias(remove.dataset.alias);
  });

  // Event delegation: rules list
  document.getElementById("rules-list").addEventListener("click", (e) => {
    const remove = e.target.closest("[data-action='remove-rule']");
    if (remove) removeRule(remove.dataset.ruleId);
  });

  // Event delegation: DNS copy buttons with feedback
  document.getElementById("dns-records").addEventListener("click", (e) => {
    const copy = e.target.closest("[data-action='copy']");
    if (!copy) return;
    navigator.clipboard.writeText(copy.dataset.copyValue);
    const checkIcon = `<svg class="w-3.5 h-3.5 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg>`;
    const original = copy.innerHTML;
    copy.innerHTML = checkIcon;
    setTimeout(() => { copy.innerHTML = original; }, 1500);
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
