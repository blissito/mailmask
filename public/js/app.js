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
  renderStats();
  renderReferrals();
  renderReferralBanner();
}

// --- Init ---
document.addEventListener("DOMContentLoaded", async () => {
  await loadCoupon();
  await checkAuth();
  await loadDomains();
  loadDomainRegistrations();
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
  if (currentUser.isAdmin) document.getElementById("admin-link")?.classList.remove("hidden");

  // Plan badge in nav
  const badge = document.getElementById("plan-badge");
  if (badge && currentUser.subscription?.plan) {
    badge.textContent = currentUser.subscription.plan;
    badge.classList.remove("hidden");
  }

  // Show API Keys tab for plans with API access
  const apiPlans = ["developer", "pro", "agencia"];
  const sub = currentUser.subscription;
  const periodEnd = sub?.currentPeriodEnd ? new Date(sub.currentPeriodEnd) : null;
  const isActive = sub && (sub.status === "active" || sub.status === "cancelled") && (!periodEnd || periodEnd >= new Date());
  if (isActive && apiPlans.includes(sub.plan)) {
    document.getElementById("tab-btn-apikeys")?.classList.remove("hidden");
  }

  renderVerifyBanner();
  renderBillingBanner();
  renderStats();
  renderReferralBanner();
  renderReferrals();

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
  if (!container || currentUser.emailVerified) { if (container) container.innerHTML = ""; return; }
  container.innerHTML = `
    <div class="bg-yellow-900/20 border border-yellow-800/50 rounded-xl px-4 py-3 flex items-center justify-between">
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
      <div class="bg-zinc-900/50 border border-zinc-800 rounded-xl px-4 py-3 flex items-center justify-between">
        <div class="flex items-center gap-3">
          <span class="w-2 h-2 rounded-full bg-green-400"></span>
          <span class="text-sm text-zinc-300">Plan ${esc(planName)}</span>
          <span class="text-xs text-zinc-500">hasta ${periodEnd ? periodEnd.toLocaleDateString("es-MX") : "—"}</span>
        </div>
        <div class="flex items-center gap-4">
          <a href="/pricing" class="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">Cambiar plan</a>
          <button id="btn-cancel-sub" class="text-xs text-zinc-500 hover:text-red-400 transition-colors">Cancelar</button>
        </div>
      </div>`;
    document.getElementById("btn-cancel-sub")?.addEventListener("click", cancelSubscription);
  } else if (isCancelledWithAccess) {
    container.innerHTML = `
      <div class="bg-yellow-900/20 border border-yellow-800/50 rounded-xl px-4 py-3 flex items-center justify-between">
        <span class="text-sm text-yellow-400">Plan ${esc(planName)} se cancela el ${periodEnd.toLocaleDateString("es-MX")}</span>
        <button id="btn-checkout" class="bg-mask-600 hover:bg-mask-700 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors">
          Reactivar
        </button>
      </div>`;
    document.getElementById("btn-checkout")?.addEventListener("click", startCheckout);
  } else if (isExpired) {
    container.innerHTML = `
      <div class="bg-red-900/20 border border-red-800/50 rounded-xl px-4 py-3 flex items-center justify-between">
        <span class="text-sm text-red-400">Tu plan expiró</span>
        <button id="btn-checkout" class="bg-mask-600 hover:bg-mask-700 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors">
          Reactivar
        </button>
      </div>`;
    document.getElementById("btn-checkout")?.addEventListener("click", startCheckout);
  } else {
    container.innerHTML = `
      <div class="bg-zinc-900/50 border border-zinc-800 rounded-xl px-4 py-3 flex items-center justify-between">
        <span class="text-sm text-zinc-400">Sin plan activo</span>
        <button id="btn-checkout" class="bg-mask-600 hover:bg-mask-700 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors">
          ${getCheckoutLabel()}
        </button>
      </div>`;
    document.getElementById("btn-checkout")?.addEventListener("click", startCheckout);
  }

  // Disable add-domain when no plan
  const addDomainBtn = document.getElementById("btn-add-domain");
  if (addDomainBtn) {
    if (!isActive && !isCancelledWithAccess) {
      addDomainBtn.classList.add("opacity-50", "pointer-events-none");
      addDomainBtn.title = "Necesitas un plan activo";
    } else {
      addDomainBtn.classList.remove("opacity-50", "pointer-events-none");
      addDomainBtn.title = "";
    }
  }
}

// --- Stats row (big numbers) ---
function renderStats() {
  const container = document.getElementById("stats-row");
  if (!container || !currentUser?.usage) return;

  const u = currentUser.usage;
  if (u.domains.limit === 0) { container.innerHTML = ""; return; }

  const totalAliases = u.aliasesPerDomain.reduce((s, a) => s + a.current, 0);
  const totalForwards = domains.reduce((s, d) => s + (d.monthlyForwards ?? 0), 0);

  container.innerHTML = `
    <div class="bg-zinc-900/50 border border-zinc-800 rounded-xl p-5">
      <div class="grid grid-cols-3 gap-6">
        <div>
          <span class="text-[11px] uppercase tracking-widest text-zinc-500 font-semibold">Dominios</span>
          <div class="text-3xl font-light text-zinc-100 mt-1">${u.domains.current}<span class="text-lg text-zinc-600">/${u.domains.limit}</span></div>
        </div>
        <div>
          <span class="text-[11px] uppercase tracking-widest text-zinc-500 font-semibold">Alias</span>
          <div class="text-3xl font-light text-zinc-100 mt-1">${totalAliases}</div>
        </div>
        <div>
          <span class="text-[11px] uppercase tracking-widest text-zinc-500 font-semibold">Forwards</span>
          <div class="text-3xl font-light text-zinc-100 mt-1">${totalForwards.toLocaleString("es-MX")}</div>
        </div>
      </div>
    </div>`;
}

// --- Referral credit banner ---
function renderReferralBanner() {
  const container = document.getElementById("referral-credit-banner");
  if (!container) return;
  const stats = currentUser?.referralStats;
  if (!stats || stats.creditsAvailable < 2) { container.innerHTML = ""; return; }

  // Celebration sound
  playCelebration();

  container.innerHTML = `
    <div class="border border-mask-500/30 bg-mask-950/20 rounded-xl px-5 py-4">
      <div class="flex items-center gap-3">
        <span class="text-2xl">🎉</span>
        <div>
          <p class="text-sm font-semibold text-mask-400">No pagas este mes — $5 MXN*</p>
          <p class="text-xs text-zinc-500 mt-0.5">*Mínimo requerido por procesador de pagos</p>
        </div>
      </div>
    </div>`;
}

function playCelebration() {
  if (!audioCtx || audioCtx.state !== "running") return;
  const t = audioCtx.currentTime;
  // Ascending celebration: C5 E5 G5 C6
  [523, 659, 784, 1047].forEach((freq, i) => {
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = "sine";
    osc.frequency.value = freq;
    gain.gain.value = 0.1;
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start(t + i * 0.15);
    gain.gain.exponentialRampToValueAtTime(0.001, t + i * 0.15 + 0.3);
    osc.stop(t + i * 0.15 + 0.3);
  });
}

// --- Referrals section ---
function buildSparklineSvg(byWeek) {
  if (!byWeek || !byWeek.length) return "";
  const max = Math.max(...byWeek.map(w => w.count), 1);
  const barW = 16, gap = 4, h = 40;
  const w = byWeek.length * (barW + gap) - gap;
  const bars = byWeek.map((wk, i) => {
    const barH = Math.max(2, (wk.count / max) * h);
    return `<rect x="${i * (barW + gap)}" y="${h - barH}" width="${barW}" height="${barH}" rx="2" fill="currentColor" opacity="0.7"><title>${wk.week}: ${wk.count}</title></rect>`;
  }).join("");
  return `<svg viewBox="0 0 ${w} ${h}" class="text-mask-400" style="width:${w}px;height:${h}px">${bars}</svg>`;
}

function renderReferrals() {
  const container = document.getElementById("referrals-section");
  if (!container) return;
  const stats = currentUser?.referralStats;
  if (!stats) { container.innerHTML = ""; return; }

  const slug = stats.slug || "";
  const link = slug ? `www.mailmask.studio/register?ref=${esc(slug)}` : "";
  const progressPct = Math.min(100, Math.round((stats.converted / 2) * 100));
  const clicks = stats.clicks || { total: 0, last30Days: 0, byWeek: [] };

  container.innerHTML = `
    <div class="bg-zinc-900/50 border border-zinc-800 rounded-xl p-5">
      <span class="text-[11px] uppercase tracking-widest text-zinc-500 font-semibold">Referidos</span>

      <div class="mt-3 space-y-3">
        ${slug ? `
          <div class="flex items-center gap-2">
            <code class="text-sm text-zinc-300 bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 flex-1 select-all">${link}</code>
            <button data-action="copy-referral" data-value="${esc(link)}" class="text-sm text-zinc-500 hover:text-zinc-300 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 px-3 py-2 rounded-lg transition-colors">Copiar</button>
            <button data-action="edit-slug" class="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">Editar</button>
          </div>
        ` : `
          <div class="flex items-center gap-2">
            <span class="text-sm text-zinc-500">Configura tu link de referido</span>
            <button data-action="edit-slug" class="text-sm text-mask-400 hover:text-mask-300 transition-colors">Crear slug</button>
          </div>
        `}

        <!-- Funnel cards -->
        <div class="grid grid-cols-3 gap-2 mt-2">
          <div class="bg-zinc-800/50 rounded-lg p-3 text-center">
            <div class="text-lg font-bold text-zinc-200">${clicks.last30Days}</div>
            <div class="text-[10px] text-zinc-500 uppercase tracking-wide">Clics</div>
          </div>
          <div class="bg-zinc-800/50 rounded-lg p-3 text-center">
            <div class="text-lg font-bold text-zinc-200">${stats.total}</div>
            <div class="text-[10px] text-zinc-500 uppercase tracking-wide">Registros</div>
          </div>
          <div class="bg-zinc-800/50 rounded-lg p-3 text-center">
            <div class="text-lg font-bold text-zinc-200">${stats.converted}</div>
            <div class="text-[10px] text-zinc-500 uppercase tracking-wide">Activos</div>
          </div>
        </div>

        <!-- Sparkline -->
        ${clicks.byWeek.length > 0 ? `
          <div class="mt-2">
            <div class="text-[10px] text-zinc-500 mb-1">Clics por semana</div>
            ${buildSparklineSvg(clicks.byWeek)}
          </div>
        ` : ""}

        ${stats.total > 0 ? `
          <div class="space-y-2 mt-2">
            ${currentUser._referralsList ? currentUser._referralsList.map(r => {
              const isConverted = r.status === "converted" || r.status === "credited";
              const masked = r.referredEmail.replace(/^(.{2}).*(@.*)$/, "$1***$2");
              return `
                <div class="flex items-center gap-3 text-sm">
                  <span class="w-2 h-2 rounded-full ${isConverted ? 'bg-green-400' : 'bg-zinc-600'}"></span>
                  <span class="text-zinc-400 font-mono text-xs">${esc(masked)}</span>
                  <span class="text-xs ${isConverted ? 'text-green-400' : 'text-zinc-500'}">${isConverted ? 'Activo' : 'Pendiente'}</span>
                  <span class="text-xs text-zinc-600 ml-auto">${relativeTime(r.createdAt)}</span>
                </div>`;
            }).join("") : ""}
          </div>
        ` : ""}

        <div class="mt-3">
          <div class="flex items-center justify-between text-xs text-zinc-500 mb-1">
            <span>${stats.converted}/2 referidos para mes gratis</span>
            <span>${progressPct}%</span>
          </div>
          <div class="h-1.5 bg-zinc-800 rounded-full overflow-hidden">
            <div class="h-full bg-mask-500 rounded-full transition-all duration-500" style="width: ${progressPct}%"></div>
          </div>
        </div>
      </div>
    </div>`;
}

let activeCoupon = null;

async function loadCoupon() {
  const code = new URLSearchParams(location.search).get("coupon");
  if (!code) return;
  try {
    const res = await fetch(`/api/coupons/${encodeURIComponent(code)}`);
    if (res.ok) activeCoupon = await res.json();
  } catch { /* ignore */ }
}

function getCheckoutLabel() {
  if (activeCoupon) {
    const name = activeCoupon.plan.charAt(0).toUpperCase() + activeCoupon.plan.slice(1);
    const price = Math.round(activeCoupon.fixedPrice / 100);
    return `Activar Plan ${name} — $${price}/mes`;
  }
  return "Activar Plan — $49/mes";
}

async function startCheckout() {
  const btn = document.getElementById("btn-checkout");
  if (btn) { btn.textContent = "Redirigiendo..."; btn.disabled = true; }
  try {
    const coupon = new URLSearchParams(location.search).get("coupon") || undefined;
    const plan = activeCoupon ? activeCoupon.plan : "basico";
    const res = await fetch("/api/billing/checkout", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ plan, billing: "monthly", coupon }),
    });
    const data = await res.json();
    if (data.init_point) {
      window.location.href = data.init_point;
    } else {
      showToast(data.error || "Error al iniciar pago", true);
      if (btn) { btn.textContent = getCheckoutLabel(); btn.disabled = false; }
    }
  } catch {
    showToast("Error de conexión", true);
    if (btn) { btn.textContent = getCheckoutLabel(); btn.disabled = false; }
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

// --- Sounds (Web Audio API) ---
let audioCtx = null;
document.addEventListener("click", () => {
  if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  if (audioCtx.state === "suspended") audioCtx.resume();
});

function playSound(type) {
  if (!audioCtx || audioCtx.state !== "running") return;
  const t = audioCtx.currentTime;
  if (type === "success") {
    [520, 660, 840].forEach((freq, i) => {
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.type = "sine";
      osc.frequency.value = freq;
      gain.gain.value = 0.12;
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      osc.start(t + i * 0.12);
      gain.gain.exponentialRampToValueAtTime(0.001, t + i * 0.12 + 0.2);
      osc.stop(t + i * 0.12 + 0.2);
    });
  } else if (type === "pop") {
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = "sine";
    osc.frequency.setValueAtTime(400, t);
    osc.frequency.exponentialRampToValueAtTime(600, t + 0.05);
    gain.gain.value = 0.13;
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start(t);
    gain.gain.exponentialRampToValueAtTime(0.001, t + 0.08);
    osc.stop(t + 0.08);
  } else if (type === "whoosh") {
    const dur = 0.3;
    const bs = audioCtx.sampleRate * dur;
    const buf = audioCtx.createBuffer(1, bs, audioCtx.sampleRate);
    const d = buf.getChannelData(0);
    for (let i = 0; i < bs; i++) d[i] = Math.random() * 2 - 1;
    const src = audioCtx.createBufferSource();
    src.buffer = buf;
    const filter = audioCtx.createBiquadFilter();
    filter.type = "bandpass";
    filter.frequency.setValueAtTime(600, t);
    filter.frequency.exponentialRampToValueAtTime(2400, t + dur);
    filter.Q.value = 1.2;
    const gain = audioCtx.createGain();
    gain.gain.setValueAtTime(0.001, t);
    gain.gain.linearRampToValueAtTime(0.12, t + 0.05);
    gain.gain.exponentialRampToValueAtTime(0.001, t + dur);
    src.connect(filter);
    filter.connect(gain);
    gain.connect(audioCtx.destination);
    src.start(t);
    src.stop(t + dur);
  } else if (type === "error") {
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = "sine";
    osc.frequency.value = 200;
    gain.gain.value = 0.15;
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start(t);
    gain.gain.exponentialRampToValueAtTime(0.001, t + 0.1);
    osc.stop(t + 0.1);
  }
}

function showToast(message, isError = false) {
  if (isError) playSound("error");
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
  renderStats(); // update after domains loaded (for forward counts)

  // Load referrals list
  try {
    const rRes = await fetch("/api/referrals");
    if (rRes.ok) {
      const data = await rRes.json();
      currentUser._referralsList = data.referrals;
      renderReferrals();
    }
  } catch { /* ignore */ }
}

function renderDomains() {
  const list = document.getElementById("domains-list");
  const empty = document.getElementById("empty-state");
  const header = document.getElementById("domains-header");

  if (domains.length === 0) {
    list.innerHTML = "";
    empty.classList.remove("hidden");
    if (header) header.classList.add("hidden");

    const emptyBtn = document.getElementById("btn-add-domain-empty");
    if (emptyBtn) {
      const sub = currentUser?.subscription;
      const periodEnd = sub?.currentPeriodEnd ? new Date(sub.currentPeriodEnd) : null;
      const isExpired = periodEnd && periodEnd < new Date();
      const hasActivePlan = sub && (sub.status === "active" || sub.status === "cancelled") && !isExpired;
      emptyBtn.classList.toggle("hidden", !hasActivePlan);
    }
    return;
  }

  empty.classList.add("hidden");
  if (header) header.classList.remove("hidden");

  list.innerHTML = domains.map(d => {
    const verified = d.verified;
    const dotClass = verified ? 'bg-green-400' : 'bg-yellow-400';
    const statusText = verified ? 'Verificado' : 'Pendiente';
    const fwds = d.monthlyForwards ?? 0;
    return `
    <div class="bg-zinc-900/50 border border-zinc-800 rounded-xl px-5 py-4 cursor-pointer hover:border-zinc-700 transition-all"
         data-action="select-domain" data-domain-id="${esc(d.id)}">
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-3">
          <span class="w-2 h-2 rounded-full ${dotClass}"></span>
          <span class="font-semibold">${esc(d.domain)}</span>
          <span class="text-xs text-zinc-500">${statusText}</span>
          ${d.registeredViaMailmask ? '<span class="text-[10px] bg-mask-600/20 text-mask-400 px-1.5 py-0.5 rounded-full">MailMask</span>' : ''}
        </div>
        <div class="flex items-center gap-4 text-xs text-zinc-500">
          <span>${fwds} fwd${fwds === 1 ? '' : 's'}</span>
          <svg class="w-4 h-4 text-zinc-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
          </svg>
        </div>
      </div>
    </div>`;
  }).join("");
}

async function selectDomain(id) {
  selectedDomain = domains.find(d => d.id === id);
  if (!selectedDomain) return;

  document.getElementById("domains-list").classList.add("hidden");
  document.getElementById("empty-state").classList.add("hidden");
  document.getElementById("domain-detail").classList.remove("hidden");
  document.getElementById("domains-header")?.classList.add("hidden");
  document.getElementById("stats-row")?.classList.add("hidden");
  document.getElementById("referrals-section")?.classList.add("hidden");
  document.getElementById("referral-credit-banner")?.classList.add("hidden");

  document.getElementById("detail-domain-name").textContent = selectedDomain.domain;
  const statusEl = document.getElementById("detail-status");
  statusEl.textContent = selectedDomain.verified ? "Verificado" : "Pendiente DNS";
  statusEl.className = `text-xs px-2 py-1 rounded-full ${selectedDomain.verified ? 'bg-green-900/50 text-green-400' : 'bg-yellow-900/50 text-yellow-400'}`;

  document.getElementById("alias-domain-suffix").textContent = `@${selectedDomain.domain}`;

  // Hide DNS tab for domains registered via MailMask (DNS is automatic)
  const dnsBtn = document.querySelector('.tab-btn[data-tab="dns"]');
  if (dnsBtn) {
    if (selectedDomain.registeredViaMailmask) {
      dnsBtn.classList.add("hidden");
    } else {
      dnsBtn.classList.remove("hidden");
    }
  }

  switchTab("aliases");
  await loadAliases();
  loadDomainHealth();
}

function goBack() {
  selectedDomain = null;
  document.getElementById("domain-detail").classList.add("hidden");
  document.getElementById("domains-list").classList.remove("hidden");
  document.getElementById("domains-header")?.classList.remove("hidden");
  document.getElementById("stats-row")?.classList.remove("hidden");
  document.getElementById("referrals-section")?.classList.remove("hidden");
  document.getElementById("referral-credit-banner")?.classList.remove("hidden");
  renderDomains();
}

async function deleteDomain() {
  if (!selectedDomain) return;
  if (!confirm(`¿Eliminar dominio ${selectedDomain.domain}? Se borrarán todos los alias y reglas.`)) return;
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

// --- Domain Registration (Route 53) ---

async function searchDomainAvailability() {
  const input = document.getElementById("add-domain-input");
  const errEl = document.getElementById("add-domain-error");
  const resultEl = document.getElementById("add-domain-step-result");
  const q = input.value.trim().toLowerCase();

  errEl.classList.add("hidden");
  resultEl.classList.add("hidden");
  resultEl.innerHTML = "";

  if (!q) { renderTldGrid(""); return; }

  // If no TLD or just a trailing dot, update TLD grid with the name
  const base = q.replace(/\.$/, "");
  if (!q.includes(".") || q.endsWith(".")) {
    renderTldGrid(base);
    return;
  }

  // Hide TLD grid, show result area
  document.getElementById("add-domain-tld-grid")?.classList.add("hidden");

  resultEl.innerHTML = `<p class="text-sm text-zinc-400">Buscando disponibilidad...</p>`;
  resultEl.classList.remove("hidden");

  try {
    const res = await fetch(`/api/domains/search?q=${encodeURIComponent(q)}`);
    const data = await res.json();

    if (!res.ok) {
      // API error — could be unsupported TLD or other
      resultEl.innerHTML = `
        <div class="bg-zinc-800/50 border border-zinc-700 rounded-lg p-4">
          <p class="text-sm text-zinc-300 mb-3">${esc(data.error || `Extensión no disponible para compra`)}</p>
          <button type="button" id="btn-connect-existing" class="w-full bg-mask-600 hover:bg-mask-700 text-white text-sm font-semibold px-4 py-2.5 rounded-lg transition-colors">
            Ya tengo este dominio, conectarlo →
          </button>
        </div>`;
      resultEl.querySelector("#btn-connect-existing").addEventListener("click", () => connectExistingDomain(q));
      playSound("pop");
      return;
    }

    if (data.available) {
      const priceStr = (data.price / 100).toLocaleString("es-MX", { style: "currency", currency: "MXN", currencyDisplay: "narrowSymbol" });
      resultEl.innerHTML = `
        <div class="bg-green-900/20 border border-green-800/50 rounded-lg p-4">
          <div class="flex items-center justify-between mb-3">
            <div>
              <span class="font-semibold text-green-400">${esc(data.domain)}</span>
              <span class="text-xs text-green-500 ml-2">Disponible</span>
              <div class="text-xs text-zinc-400 mt-0.5">${priceStr} MXN/año</div>
            </div>
          </div>
          <button type="button" id="btn-buy-domain" class="w-full bg-green-600 hover:bg-green-700 text-white text-sm font-semibold px-4 py-2.5 rounded-lg transition-colors mb-2">
            Comprar dominio
          </button>
          <div class="flex items-center gap-3 my-3">
            <div class="flex-1 border-t border-zinc-700"></div>
            <span class="text-xs text-zinc-500">o</span>
            <div class="flex-1 border-t border-zinc-700"></div>
          </div>
          <button type="button" id="btn-connect-existing" class="w-full bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-sm font-semibold px-4 py-2.5 rounded-lg transition-colors">
            Ya tengo este dominio →
          </button>
        </div>`;
      resultEl.querySelector("#btn-buy-domain").addEventListener("click", () => registerDomainAction(data.domain));
      resultEl.querySelector("#btn-connect-existing").addEventListener("click", () => connectExistingDomain(q));
    } else {
      resultEl.innerHTML = `
        <div class="bg-zinc-800/50 border border-zinc-700 rounded-lg px-4 py-4">
          <p class="text-sm text-zinc-300 mb-1"><span class="font-semibold">${esc(data.domain)}</span> ya está registrado</p>
          <p class="text-xs text-zinc-500 mb-4">Si es tuyo, conéctalo para usarlo con MailMask.</p>
          <button type="button" id="btn-connect-existing" class="w-full bg-mask-600 hover:bg-mask-700 text-white text-sm font-semibold px-4 py-2.5 rounded-lg transition-colors mb-2">
            Ya es mío, conectarlo →
          </button>
          <button type="button" id="btn-search-another" class="w-full bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-sm font-semibold px-4 py-2.5 rounded-lg transition-colors mb-2">
            Buscar otro dominio
          </button>
          <div class="relative group">
            <button type="button" disabled class="w-full bg-zinc-800/40 text-zinc-600 text-sm font-semibold px-4 py-2.5 rounded-lg cursor-not-allowed">
              Transferir dominio a MailMask
            </button>
            <div class="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-3 py-1.5 bg-zinc-700 text-zinc-200 text-xs rounded-lg opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap">
              Próximamente
            </div>
          </div>
        </div>`;
      resultEl.querySelector("#btn-connect-existing").addEventListener("click", () => connectExistingDomain(q));
      resultEl.querySelector("#btn-search-another").addEventListener("click", () => {
        resultEl.classList.add("hidden");
        input.value = "";
        input.focus();
        renderTldGrid("");
      });
    }
    playSound("pop");
  } catch {
    resultEl.innerHTML = `<p class="text-sm text-red-400">Error de conexión</p>`;
  }
}

async function connectExistingDomain(domain) {
  const resultEl = document.getElementById("add-domain-step-result");
  resultEl.innerHTML = `<p class="text-sm text-zinc-400">Agregando dominio...</p>`;

  try {
    const res = await fetch("/api/domains", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ domain }),
    });
    const data = await res.json();
    if (res.ok) {
      hideModal("modal-add-domain");
      await loadDomains();
      await refreshUsage();
      selectDomain(data.domain.id);
      switchTab("dns");
    } else {
      resultEl.innerHTML = `<p class="text-sm text-red-400">${esc(data.error || "Error al agregar dominio")}</p>`;
    }
  } catch {
    resultEl.innerHTML = `<p class="text-sm text-red-400">Error de conexión</p>`;
  }
}

async function registerDomainAction(domain) {
  const resultEl = document.getElementById("add-domain-step-result");
  resultEl.innerHTML = `<p class="text-sm text-zinc-400">Creando pago...</p>`;

  try {
    const res = await fetch("/api/domains/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ domain }),
    });
    const data = await res.json();
    if (!res.ok) {
      resultEl.innerHTML = `<p class="text-sm text-red-400">${esc(data.error)}</p>`;
      return;
    }
    // Redirect to MercadoPago
    window.location.href = data.initPoint;
  } catch {
    resultEl.innerHTML = `<p class="text-sm text-red-400">Error de conexión</p>`;
  }
}

async function loadDomainRegistrations() {
  try {
    const res = await fetch("/api/domains/registrations");
    if (!res.ok) return;
    const regs = await res.json();
    const container = document.getElementById("domain-registrations-list");
    if (!container) return;

    const active = regs.filter(r => r.status !== "registered" && r.status !== "pending_payment");
    if (!active.length) { container.innerHTML = ""; return; }

    container.innerHTML = active.map(r => {
      const statusMap = {
        paid: { label: "Pagado — esperando registro", color: "text-yellow-400", dot: "bg-yellow-400", animate: true },
        registering: { label: "Registrando dominio...", color: "text-blue-400", dot: "bg-blue-400", animate: true },
        failed: { label: "Error: " + (r.lastError || "fallo desconocido"), color: "text-red-400", dot: "bg-red-400", animate: false },
      };
      const s = statusMap[r.status] || { label: r.status, color: "text-zinc-400", dot: "bg-zinc-400", animate: false };
      return `
      <div class="bg-zinc-900/50 border border-zinc-800 rounded-xl px-5 py-3">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <span class="w-2 h-2 rounded-full ${s.dot} ${s.animate ? 'animate-pulse' : ''}"></span>
            <span class="font-semibold text-sm">${esc(r.domainName)}</span>
          </div>
          <span class="text-xs ${s.color}">${s.label}</span>
        </div>
      </div>`;
    }).join("");

    // Poll while there are registering domains
    if (active.some(r => r.status === "registering" || r.status === "paid")) {
      setTimeout(loadDomainRegistrations, 5000);
      // Also reload domains in case one just finished
      setTimeout(loadDomains, 6000);
    }
  } catch { /* ignore */ }
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
        <button data-action="edit-alias" data-alias="${esc(a.alias)}" data-destinations="${esc(a.destinations.join(', '))}" class="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">Editar</button>
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

// --- Members ---

async function loadMembers() {
  if (!selectedDomain) return;
  const list = document.getElementById("members-list");
  const empty = document.getElementById("members-empty");
  const upgrade = document.getElementById("members-upgrade");
  const inviteBtn = document.getElementById("btn-invite-member");

  const sub = currentUser?.subscription;
  const plan = sub?.plan ?? "basico";
  const agentLimits = { basico: 0, freelancer: 3, developer: 10 };
  const limit = agentLimits[plan] ?? 0;

  if (limit === 0) {
    list.innerHTML = "";
    empty.classList.add("hidden");
    upgrade.classList.remove("hidden");
    if (inviteBtn) inviteBtn.classList.add("hidden");
    return;
  }

  upgrade.classList.add("hidden");
  if (inviteBtn) inviteBtn.classList.remove("hidden");

  const res = await fetch(`/api/domains/${selectedDomain.id}/agents`);
  if (!res.ok) return;
  const members = await res.json();
  renderMembers(members, limit);
}

function renderMembers(members, limit) {
  const list = document.getElementById("members-list");
  const empty = document.getElementById("members-empty");

  if (members.length === 0) {
    list.innerHTML = "";
    empty.classList.remove("hidden");
    return;
  }

  empty.classList.add("hidden");
  const roleLabels = { admin: "Admin", agent: "Miembro" };
  list.innerHTML = `
    <p class="text-xs text-zinc-500 mb-2">${members.length}/${limit} miembros</p>
    ${members.map(m => `
      <div class="bg-zinc-800/50 border border-zinc-800 rounded-lg px-5 py-4 flex items-center justify-between">
        <div>
          <span class="text-sm text-zinc-100">${esc(m.name)}</span>
          <span class="text-sm text-zinc-500 ml-2">${esc(m.email)}</span>
          <span class="text-xs ml-2 px-2 py-0.5 rounded ${m.role === 'admin' ? 'bg-mask-600/15 text-mask-400' : 'bg-zinc-700 text-zinc-400'}">${roleLabels[m.role] ?? m.role}</span>
        </div>
        <button data-action="remove-member" data-agent-id="${esc(m.id)}" data-agent-name="${esc(m.name)}" class="text-xs text-zinc-500 hover:text-red-400 transition-colors">Eliminar</button>
      </div>
    `).join("")}`;
}

async function inviteMember(name, email, role) {
  const errEl = document.getElementById("invite-member-error");
  errEl.classList.add("hidden");

  const res = await fetch(`/api/domains/${selectedDomain.id}/agents/invite`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name, email, role }),
  });

  if (res.ok) {
    hideModal("modal-invite-member");
    document.getElementById("form-invite-member").reset();
    showToast("Invitación enviada");
    await loadMembers();
  } else {
    const data = await res.json();
    errEl.textContent = data.error || "Error al invitar miembro";
    errEl.classList.remove("hidden");
  }
}

async function removeMember(agentId, name) {
  if (!confirm(`¿Eliminar a ${name} de este dominio?`)) return;
  const res = await fetch(`/api/domains/${selectedDomain.id}/agents/${agentId}`, { method: "DELETE" });
  if (res.ok) {
    showToast("Miembro eliminado");
    await loadMembers();
  } else {
    const data = await res.json().catch(() => ({}));
    showToast(data.error || "Error al eliminar", true);
  }
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

// --- Domain Health ---

async function loadDomainHealth() {
  if (!selectedDomain) return;
  const statusEl = document.getElementById("detail-status");

  statusEl.textContent = "Verificando...";
  statusEl.className = "text-xs px-2 py-1 rounded-full bg-zinc-800 text-zinc-400 animate-pulse";

  try {
    const res = await fetch(`/api/domains/${selectedDomain.id}/health`);
    if (!res.ok) return;
    const health = await res.json();
    selectedDomain._health = health;

    const badgeStyles = {
      ok: "bg-green-900/50 text-green-400",
      warning: "bg-yellow-900/50 text-yellow-400",
      error: "bg-red-900/50 text-red-400",
    };
    const badgeLabels = { ok: "Saludable", warning: "Atención", error: "Error" };
    statusEl.textContent = badgeLabels[health.status] || health.status;
    statusEl.className = `text-xs px-2 py-1 rounded-full ${badgeStyles[health.status] || badgeStyles.error}`;

    renderHealthPanel();
  } catch {
    statusEl.textContent = selectedDomain.verified ? "Verificado" : "Pendiente DNS";
    statusEl.className = `text-xs px-2 py-1 rounded-full ${selectedDomain.verified ? 'bg-green-900/50 text-green-400' : 'bg-yellow-900/50 text-yellow-400'}`;
  }
}

function renderHealthPanel() {
  const health = selectedDomain?._health;
  if (!health) return;

  let panel = document.getElementById("health-panel");
  if (!panel) {
    panel = document.createElement("div");
    panel.id = "health-panel";
    const dnsTab = document.getElementById("tab-dns");
    if (dnsTab) dnsTab.prepend(panel);
    else return;
  }

  const iconOk = `<svg class="w-4 h-4 text-green-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>`;
  const iconWarn = `<svg class="w-4 h-4 text-yellow-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`;
  const iconErr = `<svg class="w-4 h-4 text-red-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>`;

  const summaryBg = { ok: "border-green-800/50 bg-green-900/20", warning: "border-yellow-800/50 bg-yellow-900/20", error: "border-red-800/50 bg-red-900/20" };
  const summaryText = { ok: "text-green-400", warning: "text-yellow-400", error: "text-red-400" };

  const checkOrder = ["verified", "mx", "spf", "dkim", "aliases", "plan"];
  const checkLabels = { verified: "Verificación", mx: "MX (recepción)", spf: "SPF", dkim: "DKIM", aliases: "Aliases", plan: "Plan" };

  panel.innerHTML = `
    <div class="mb-6 border ${summaryBg[health.status]} rounded-xl p-5">
      <p class="text-sm font-medium ${summaryText[health.status]} mb-3">${esc(health.summary)}</p>
      <div class="space-y-2">
        ${checkOrder.map(key => {
          const c = health.checks[key];
          if (!c) return "";
          const icon = c.ok ? iconOk : (health.status === "error" && !c.ok ? iconErr : iconWarn);
          return `<div class="flex items-start gap-2">
            ${icon}
            <div>
              <span class="text-xs font-medium text-zinc-300">${checkLabels[key]}</span>
              <span class="text-xs text-zinc-500 ml-1">— ${esc(c.detail)}</span>
            </div>
          </div>`;
        }).join("")}
      </div>
      <button onclick="loadDomainHealth()" class="mt-3 text-xs text-zinc-500 hover:text-zinc-300 transition-colors">Actualizar diagnóstico</button>
    </div>`;
}

// --- DNS ---

function renderDnsRecords() {
  if (!selectedDomain) return;
  const records = document.getElementById("dns-records");

  if (selectedDomain.registeredViaMailmask) {
    records.innerHTML = `
      <div class="flex items-center gap-2 bg-green-900/20 border border-green-800/50 rounded-lg px-4 py-3">
        <svg class="w-5 h-5 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
        <span class="text-sm text-green-400 font-medium">DNS configurado automáticamente por MailMask</span>
      </div>`;
    return;
  }

  const d = selectedDomain.domain;
  const dnsItems = [
    {
      type: "MX",
      name: "@",
      value: "10 inbound-smtp.us-east-1.amazonaws.com",
      hints: [
        `<strong>@</strong> significa el dominio raíz (<strong>${esc(d)}</strong>). La mayoría de proveedores usan <strong>@</strong>.`,
        `Si tu proveedor tiene un campo separado de <strong>Prioridad</strong>, pon <strong>10</strong> ahí y solo la dirección como valor.`,
      ],
    },
    {
      type: "TXT",
      name: "_amazonses",
      value: selectedDomain.verificationToken,
      hints: [
        `Pon solo <strong>_amazonses</strong> como nombre — tu proveedor agrega <strong>.${esc(d)}</strong> automáticamente.`,
        `Si tu proveedor pide comillas alrededor del valor, agrégalas: <strong>"${esc(selectedDomain.verificationToken)}"</strong>.`,
      ],
    },
    ...selectedDomain.dkimTokens.map(token => ({
      type: "CNAME",
      name: `${token}._domainkey`,
      value: `${token}.dkim.amazonses.com`,
      hints: [
        `Pon solo <strong>${esc(token)}._domainkey</strong> como nombre — tu proveedor agrega <strong>.${esc(d)}</strong> automáticamente.`,
      ],
    })),
    {
      type: "TXT",
      name: "@",
      value: "v=spf1 include:amazonses.com ~all",
      hints: [
        `Este registro <strong>SPF</strong> autoriza a Amazon SES a enviar emails en nombre de tu dominio.`,
        `Si ya tienes un registro SPF, agrega <strong>include:amazonses.com</strong> antes del <strong>~all</strong> existente en vez de crear uno nuevo.`,
      ],
    },
  ];

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
    playSound("success");
    selectedDomain.verified = true;
    const statusEl = document.getElementById("detail-status");
    statusEl.textContent = "Verificado";
    statusEl.className = "text-xs px-2 py-1 rounded-full bg-green-900/50 text-green-400";
    loadDomainHealth();
  } else {
    resultEl.textContent = "✗ DNS no configurado aún. Verifica los registros e intenta de nuevo.";
    resultEl.className = "ml-3 text-sm text-yellow-400";
  }
}

// --- SMTP helpers ---

const _smtpCopied = new Set();

function copySmtp(btn, text, key) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.innerHTML;
    btn.innerHTML = `<svg class="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>`;
    btn.classList.add("border-green-700");
    setTimeout(() => { btn.innerHTML = orig; btn.classList.remove("border-green-700"); }, 1500);
    if (key) {
      _smtpCopied.add(key);
      if (_smtpCopied.has("username") && _smtpCopied.has("password") && _smtpCopied.has("server")) {
        const closeBtn = document.getElementById("btn-smtp-close");
        if (closeBtn) {
          closeBtn.disabled = false;
          closeBtn.classList.remove("opacity-50", "cursor-not-allowed");
        }
      }
    }
  });
}

function relativeTime(dateStr) {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "hace un momento";
  if (mins < 60) return `hace ${mins} min`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `hace ${hrs}h`;
  const days = Math.floor(hrs / 24);
  if (days === 1) return "hace 1 día";
  if (days < 7) return `hace ${days} días`;
  const weeks = Math.floor(days / 7);
  if (weeks === 1) return "hace 1 sem";
  if (weeks < 5) return `hace ${weeks} sem`;
  const months = Math.floor(days / 30);
  if (months === 1) return "hace 1 mes";
  return `hace ${months} meses`;
}

// --- SMTP Credentials ---

async function loadSmtpCredentials() {
  if (!selectedDomain) return;
  const list = document.getElementById("smtp-list");
  const empty = document.getElementById("smtp-empty");
  const upgrade = document.getElementById("smtp-upgrade");

  const sub = currentUser?.subscription;
  const periodEnd = sub?.currentPeriodEnd ? new Date(sub.currentPeriodEnd) : null;
  const isExpired = periodEnd && periodEnd < new Date();
  const plan = sub && (sub.status === "active" || sub.status === "cancelled") && !isExpired ? sub.plan : null;
  const smtpAllowed = plan && ["developer", "pro", "agencia"].includes(plan);

  if (!smtpAllowed) {
    list.innerHTML = "";
    empty.classList.add("hidden");
    upgrade.classList.remove("hidden");
    return;
  }
  upgrade.classList.add("hidden");

  const res = await fetch(`/api/domains/${selectedDomain.id}/smtp-credentials`);
  if (!res.ok) return;
  const creds = await res.json();
  renderSmtpCredentials(creds);
}

function renderSmtpCredentials(creds) {
  const list = document.getElementById("smtp-list");
  const empty = document.getElementById("smtp-empty");

  if (creds.length === 0) {
    list.innerHTML = "";
    empty.classList.remove("hidden");
    return;
  }
  empty.classList.add("hidden");
  const cpIcon = `<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>`;
  list.innerHTML = creds.map(c => `
    <div class="bg-zinc-800/50 border border-zinc-800 rounded-lg px-5 py-4">
      <div class="flex items-center justify-between mb-2">
        <span class="font-semibold text-sm">${esc(c.label)}</span>
        <button data-revoke="${esc(c.id)}" class="text-xs text-red-400 hover:text-red-300 transition-colors flex items-center gap-1" title="Revocar credencial">
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
          Revocar
        </button>
      </div>
      <div class="flex items-center gap-2 text-xs text-zinc-400">
        <span>Usuario SMTP:</span>
        <code class="bg-zinc-800 border border-zinc-700 rounded px-2 py-0.5 font-mono text-zinc-300 select-all">${esc(c.accessKeyId)}</code>
        <button data-copy="${esc(c.accessKeyId)}" class="text-zinc-500 hover:text-zinc-300 transition-colors" title="Copiar usuario">${cpIcon}</button>
      </div>
      <div class="flex items-center gap-2 mt-2 text-xs text-zinc-500">
        <span>${relativeTime(c.createdAt)}</span>
        <span class="inline-flex items-center gap-1 bg-green-900/30 text-green-400 border border-green-800/40 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide">
          <span class="w-1.5 h-1.5 bg-green-400 rounded-full"></span>Activa
        </span>
      </div>
    </div>
  `).join("");
}

async function createSmtpCredentialUI(label) {
  if (!selectedDomain) return;
  const res = await fetch(`/api/domains/${selectedDomain.id}/smtp-credentials`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ label }),
  });
  const data = await res.json();
  if (!res.ok) {
    const errEl = document.getElementById("smtp-label-error");
    errEl.textContent = data.error || "Error al generar credenciales";
    errEl.classList.remove("hidden");
    return;
  }

  hideModal("modal-smtp-label");

  _smtpCopied.clear();
  const closeBtn = document.getElementById("btn-smtp-close");
  if (closeBtn) {
    closeBtn.disabled = true;
    closeBtn.classList.add("opacity-50", "cursor-not-allowed");
  }

  const info = document.getElementById("smtp-creds-info");
  const domain = selectedDomain.domain;
  const copyIcon = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>`;

  info.innerHTML = `
    <p class="text-sm text-zinc-400 mb-4">Usa estas credenciales en tu aplicación para enviar emails desde <strong class="text-zinc-200">${esc(domain)}</strong>.</p>

    <div class="space-y-3">
      <div class="smtp-field">
        <div class="flex items-center justify-between mb-1">
          <span class="text-xs font-semibold text-zinc-400 uppercase tracking-wide">Servidor SMTP</span>
        </div>
        <div class="flex items-center gap-2">
          <code class="flex-1 bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2.5 text-sm text-zinc-100 font-mono select-all">${esc(data.server)}</code>
          <button data-copy="${esc(data.server)}" data-copy-key="server" class="smtp-copy shrink-0 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg p-2.5 text-zinc-400 hover:text-zinc-200 transition-colors" title="Copiar">${copyIcon}</button>
        </div>
        <div class="flex gap-3 mt-2">
          <div class="flex items-center gap-2">
            <code class="bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-xs text-zinc-300 font-mono">587</code>
            <button data-copy="587" class="text-zinc-500 hover:text-zinc-300 transition-colors" title="Copiar puerto"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg></button>
            <span class="text-xs text-zinc-500">Puerto</span>
          </div>
          <div class="flex items-center gap-2">
            <code class="bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-xs text-zinc-300 font-mono">STARTTLS</code>
            <button data-copy="STARTTLS" class="text-zinc-500 hover:text-zinc-300 transition-colors" title="Copiar seguridad"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg></button>
            <span class="text-xs text-zinc-500">Seguridad</span>
          </div>
        </div>
      </div>

      <div class="smtp-field">
        <div class="flex items-center justify-between mb-1">
          <span class="text-xs font-semibold text-zinc-400 uppercase tracking-wide">Usuario</span>
        </div>
        <div class="flex items-center gap-2">
          <code class="flex-1 bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2.5 text-sm text-zinc-100 font-mono select-all truncate">${esc(data.username)}</code>
          <button data-copy="${esc(data.username)}" data-copy-key="username" class="smtp-copy shrink-0 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg p-2.5 text-zinc-400 hover:text-zinc-200 transition-colors" title="Copiar">${copyIcon}</button>
        </div>
      </div>

      <div class="smtp-field">
        <div class="flex items-center justify-between mb-1">
          <span class="text-xs font-semibold text-yellow-400 uppercase tracking-wide">Contraseña</span>
        </div>
        <p class="text-xs text-yellow-400/70 mb-1.5">Copia esta contraseña ahora — no podrás verla de nuevo.</p>
        <div class="flex items-center gap-2">
          <code class="flex-1 bg-zinc-800 border border-yellow-800/50 rounded-lg px-3 py-2.5 text-sm text-zinc-100 font-mono select-all break-all">${esc(data.password)}</code>
          <button data-copy="${esc(data.password)}" data-copy-key="password" class="smtp-copy shrink-0 bg-zinc-800 hover:bg-zinc-700 border border-yellow-800/50 rounded-lg p-2.5 text-yellow-400 hover:text-yellow-300 transition-colors" title="Copiar">${copyIcon}</button>
        </div>
      </div>
    </div>
  `;
  showModal("modal-smtp-creds");
  await loadSmtpCredentials();
}

async function revokeSmtpCredentialUI(credId) {
  if (!selectedDomain) return;
  if (!confirm("¿Revocar esta credencial SMTP? Tu aplicación dejará de poder enviar emails.")) return;
  const res = await fetch(`/api/domains/${selectedDomain.id}/smtp-credentials/${credId}`, { method: "DELETE" });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    alert(data.error || "Error al revocar credencial");
    return;
  }
  await loadSmtpCredentials();
}

// --- Referral slug ---

async function saveSlug(slug) {
  const errEl = document.getElementById("edit-slug-error");
  errEl.classList.add("hidden");

  const res = await fetch("/api/referrals/slug", {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ slug }),
  });

  if (res.ok) {
    hideModal("modal-edit-slug");
    playSound("pop");
    showToast("Slug guardado");
    await refreshUsage();
  } else {
    const data = await res.json();
    errEl.textContent = data.error || "Error al guardar slug";
    errEl.classList.remove("hidden");
  }
}

// --- API Keys ---

async function loadApiKeys() {
  const list = document.getElementById("apikeys-list");
  const empty = document.getElementById("apikeys-empty");
  if (!list) return;

  const res = await fetch("/api/api-keys");
  if (!res.ok) { list.innerHTML = ""; empty.classList.remove("hidden"); return; }
  const keys = await res.json();
  renderApiKeys(keys);
}

function renderApiKeys(keys) {
  const list = document.getElementById("apikeys-list");
  const empty = document.getElementById("apikeys-empty");
  if (!keys.length) { list.innerHTML = ""; empty.classList.remove("hidden"); return; }
  empty.classList.add("hidden");
  list.innerHTML = keys.map(k => `
    <div class="flex items-center justify-between bg-zinc-800/50 border border-zinc-700 rounded-lg px-4 py-3">
      <div>
        <span class="text-sm font-medium">${k.name}</span>
        <span class="text-xs text-zinc-500 ml-2">mk_...${k.id.slice(-6)}</span>
        ${k.lastUsedAt ? `<span class="text-xs text-zinc-500 ml-2">Último uso: ${new Date(k.lastUsedAt).toLocaleDateString()}</span>` : ""}
      </div>
      <button onclick="revokeApiKeyUI('${k.id}')" class="text-xs text-red-400 hover:text-red-300 transition-colors">Revocar</button>
    </div>
  `).join("");
}

async function revokeApiKeyUI(id) {
  if (!confirm("¿Revocar esta API key?")) return;
  const res = await fetch(`/api/api-keys/${id}`, { method: "DELETE" });
  if (res.ok) {
    playSound("delete");
    loadApiKeys();
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

  if (tab === "aliases") loadAliases();
  else if (tab === "rules") loadRules();
  else if (tab === "logs") loadLogs();
  else if (tab === "dns") { renderDnsRecords(); renderHealthPanel(); }
  else if (tab === "members") loadMembers();
  else if (tab === "smtp") loadSmtpCredentials();
  else if (tab === "apikeys") loadApiKeys();
}

// --- Modals ---

function showModal(id) {
  document.getElementById(id).classList.remove("hidden");
}

function hideModal(id) {
  document.getElementById(id).classList.add("hidden");
}

const AVAILABLE_TLDS = [
  { tld: ".com", price: 59900, popular: true },
  { tld: ".mx", price: 159900 },
  { tld: ".com.mx", price: 159900 },
  { tld: ".net", price: 49900 },
  { tld: ".org", price: 54900 },
  { tld: ".io", price: 179900, popular: true },
  { tld: ".co", price: 114900 },
  { tld: ".click", price: 13900 },
  { tld: ".link", price: 22900 },
  { tld: ".xyz", price: 54900 },
  { tld: ".info", price: 54900 },
  { tld: ".me", price: 86900 },
];

function renderTldGrid(base) {
  const container = document.getElementById("add-domain-tld-list");
  const gridEl = document.getElementById("add-domain-tld-grid");
  if (!container || !gridEl) return;

  const name = base || "tudominio";
  container.innerHTML = AVAILABLE_TLDS.map(t => {
    const p = (t.price / 100).toLocaleString("es-MX", { minimumFractionDigits: 0, maximumFractionDigits: 0 });
    return `<button type="button" class="tld-suggestion group text-left bg-zinc-800/40 hover:bg-zinc-800 border border-zinc-700/30 hover:border-mask-500/40 rounded-xl px-5 py-4 transition-all" data-domain="${esc(name + t.tld)}">
      <span class="block text-base font-bold text-mask-400 group-hover:text-mask-300">${t.tld}</span>
      <span class="block text-xs text-zinc-500 mt-1.5">$${p} MXN/año</span>
      ${t.popular ? '<span class="inline-block text-[9px] bg-mask-600/25 text-mask-400 px-1.5 py-0.5 rounded mt-1.5 leading-none">Popular</span>' : ''}
    </button>`;
  }).join("");
  gridEl.classList.remove("hidden");
  container.querySelectorAll(".tld-suggestion").forEach(btn => {
    btn.addEventListener("click", () => {
      document.getElementById("add-domain-input").value = btn.dataset.domain;
      searchDomainAvailability();
    });
  });
}

function showAddDomainModal() {
  const input = document.getElementById("add-domain-input");
  const errEl = document.getElementById("add-domain-error");
  const resultEl = document.getElementById("add-domain-step-result");
  if (input) input.value = "";
  if (errEl) errEl.classList.add("hidden");
  if (resultEl) { resultEl.classList.add("hidden"); resultEl.innerHTML = ""; }
  renderTldGrid("");
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

  // Domain search in modal
  document.getElementById("btn-add-domain-search")?.addEventListener("click", searchDomainAvailability);
  document.getElementById("add-domain-input")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); searchDomainAvailability(); }
  });
  document.getElementById("add-domain-input")?.addEventListener("input", (e) => {
    const v = e.target.value.trim().toLowerCase().replace(/\.$/, "");
    if (!v || !v.includes(".")) {
      document.getElementById("add-domain-step-result")?.classList.add("hidden");
      renderTldGrid(v);
    }
  });

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

  // SMTP
  document.getElementById("btn-add-smtp").addEventListener("click", () => {
    const title = document.getElementById("smtp-label-title");
    if (title && selectedDomain) title.textContent = `Generar credenciales SMTP — ${selectedDomain.domain}`;
    showModal("modal-smtp-label");
  });
  document.getElementById("form-smtp-label").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    const errEl = document.getElementById("smtp-label-error");
    errEl.classList.add("hidden");
    await createSmtpCredentialUI(form.label.value.trim());
    form.reset();
  });

  // API Keys
  document.getElementById("btn-add-apikey").addEventListener("click", () => showModal("modal-apikey-name"));
  document.getElementById("form-apikey-name").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    const errEl = document.getElementById("apikey-name-error");
    errEl.classList.add("hidden");
    const res = await fetch("/api/api-keys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: form.name.value.trim() }),
    });
    if (res.ok) {
      const data = await res.json();
      hideModal("modal-apikey-name");
      form.reset();
      document.getElementById("apikey-value").textContent = data.key;
      showModal("modal-apikey-show");
      playSound("success");
      loadApiKeys();
    } else {
      const data = await res.json();
      errEl.textContent = data.error || "Error al crear key";
      errEl.classList.remove("hidden");
    }
  });
  document.getElementById("btn-copy-apikey").addEventListener("click", () => {
    const key = document.getElementById("apikey-value").textContent;
    navigator.clipboard.writeText(key);
    playSound("copy");
    showToast("API Key copiada");
  });

  // Delegated click handlers
  document.addEventListener("click", (e) => {
    const copyBtn = e.target.closest("[data-copy]");
    if (copyBtn) {
      copySmtp(copyBtn, copyBtn.dataset.copy, copyBtn.dataset.copyKey);
      return;
    }
    const revokeBtn = e.target.closest("[data-revoke]");
    if (revokeBtn) {
      revokeSmtpCredentialUI(revokeBtn.dataset.revoke);
      return;
    }
    // Copy referral link
    const copyRef = e.target.closest("[data-action='copy-referral']");
    if (copyRef) {
      navigator.clipboard.writeText(copyRef.dataset.value);
      playSound("pop");
      showToast("Link copiado");
      return;
    }
    // Edit slug
    const editSlug = e.target.closest("[data-action='edit-slug']");
    if (editSlug) {
      const form = document.getElementById("form-edit-slug");
      if (form && currentUser?.referralSlug) form.slug.value = currentUser.referralSlug;
      showModal("modal-edit-slug");
      return;
    }
  });

  // Form: Edit slug
  document.getElementById("form-edit-slug")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    await saveSlug(e.target.slug.value.trim().toLowerCase());
  });

  // (Add domain form replaced by unified search modal — handled via btn-add-domain-search)

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
      playSound("pop");
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

  // Form: Edit alias
  document.getElementById("form-edit-alias").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    const errEl = document.getElementById("edit-alias-error");
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

    const res = await fetch(`/api/domains/${selectedDomain.id}/alias/${form.alias.value}`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ destinations }),
    });

    if (res.ok) {
      hideModal("modal-edit-alias");
      await loadAliases();
    } else {
      const data = await res.json();
      errEl.textContent = data.error || "Error al editar alias";
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
    const edit = e.target.closest("[data-action='edit-alias']");
    if (edit) {
      const alias = edit.dataset.alias;
      document.getElementById("edit-alias-name").textContent = `${alias}@${selectedDomain.domain}`;
      const form = document.getElementById("form-edit-alias");
      form.alias.value = alias;
      form.destinations.value = edit.dataset.destinations;
      document.getElementById("edit-alias-error").classList.add("hidden");
      showModal("modal-edit-alias");
    }
  });

  // Event delegation: rules list
  document.getElementById("rules-list").addEventListener("click", (e) => {
    const remove = e.target.closest("[data-action='remove-rule']");
    if (remove) removeRule(remove.dataset.ruleId);
  });

  // Invite member button
  document.getElementById("btn-invite-member")?.addEventListener("click", () => showModal("modal-invite-member"));

  // Form: Invite member
  document.getElementById("form-invite-member")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    await inviteMember(form.name.value.trim(), form.email.value.trim().toLowerCase(), form.role.value);
  });

  // Event delegation: members list
  document.getElementById("members-list")?.addEventListener("click", (e) => {
    const remove = e.target.closest("[data-action='remove-member']");
    if (remove) removeMember(remove.dataset.agentId, remove.dataset.agentName);
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
