// Con un modal abierto, el fondo no debe desplazarse.
let openModals = 0;
function lockBodyScroll() {
  if (openModals === 0) {
    const gap = window.innerWidth - document.documentElement.clientWidth;
    document.body.dataset.prevOverflow = document.body.style.overflow || "";
    document.body.style.overflow = "hidden";
    if (gap > 0) document.body.style.paddingRight = `${gap}px`;
  }
  openModals++;
}
function unlockBodyScroll() {
  openModals = Math.max(0, openModals - 1);
  if (openModals === 0) {
    document.body.style.overflow = document.body.dataset.prevOverflow ?? "";
    document.body.style.paddingRight = "";
    delete document.body.dataset.prevOverflow;
  }
}

// --- CSRF: inject X-CSRF-Token header on mutating requests ---
{
  const _fetch = window.fetch;
  window.fetch = function(url, opts) {
    opts = opts || {};
    const method = (opts.method || "GET").toUpperCase();
    if (method !== "GET" && method !== "HEAD") {
      const csrfToken = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]*)/)?.[1];
      if (csrfToken) {
        opts.headers = opts.headers instanceof Headers
          ? opts.headers
          : new Headers(opts.headers || {});
        if (!opts.headers.has("x-csrf-token")) {
          opts.headers.set("x-csrf-token", csrfToken);
        }
      }
    }
    return _fetch.call(this, url, opts);
  };
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// --- Tab switching ---

function switchTab(tab) {
  document.querySelectorAll(".admin-tab").forEach(btn => {
    const active = btn.dataset.tab === tab;
    btn.classList.toggle("border-red-500", active);
    btn.classList.toggle("text-zinc-100", active);
    btn.classList.toggle("border-transparent", !active);
    btn.classList.toggle("text-zinc-500", !active);
  });
  document.getElementById("tab-backups").classList.toggle("hidden", tab !== "backups");
  document.getElementById("tab-users").classList.toggle("hidden", tab !== "users");
  document.getElementById("tab-coupons").classList.toggle("hidden", tab !== "coupons");
  document.getElementById("tab-campaigns").classList.toggle("hidden", tab !== "campaigns");
  if (tab === "users" && !usersLoaded) loadUsers();
  if (tab === "coupons" && !couponsLoaded) loadCoupons();
  if (tab === "campaigns" && !campaignsLoaded) loadCampaigns();
}

// --- Init ---

async function init() {
  document.querySelectorAll(".admin-tab").forEach(btn =>
    btn.addEventListener("click", () => switchTab(btn.dataset.tab))
  );
  switchTab("backups");

  const res = await fetch("/api/admin/backups");
  if (res.status === 401 || res.status === 403) { window.location.href = "/app"; return; }

  const me = await fetch("/api/auth/me");
  if (me.ok) {
    const u = await me.json();
    document.getElementById("user-email").textContent = u.email;
  }

  const backupsData = await res.json();
  renderBackups(Array.isArray(backupsData) ? backupsData : []);

  document.getElementById("backups-list").addEventListener("click", async (e) => {
    const btn = e.target.closest(".btn-delete-backup");
    if (!btn) return;
    if (!confirm(`¿Eliminar backup "${btn.dataset.key}"?`)) return;
    btn.disabled = true; btn.textContent = "Eliminando...";
    const r = await fetch(`/api/admin/backups/${encodeURIComponent(btn.dataset.key)}`, { method: "DELETE" });
    if (r.ok) { const lr = await fetch("/api/admin/backups"); if (lr.ok) renderBackups(await lr.json()); }
    else { const d = await r.json(); alert(d.error || "Error"); }
  });

  document.getElementById("btn-trigger").addEventListener("click", triggerBackup);
  document.getElementById("btn-logout").addEventListener("click", async () => {
    await fetch("/api/auth/logout", { method: "POST" }); window.location.href = "/login";
  });

  // Users
  document.getElementById("user-search").addEventListener("input", filterUsers);
  document.getElementById("users-list").addEventListener("click", (e) => {
    const row = e.target.closest(".user-row");
    if (row) openUserDetail(row.dataset.email);
  });
  document.getElementById("btn-close-detail").addEventListener("click", closeDetail);
  document.getElementById("btn-save-user").addEventListener("click", saveUser);
  document.getElementById("btn-delete-user").addEventListener("click", deleteUserHandler);
  initCoupons();
}

// --- Backups ---

function renderBackups(backups) {
  document.getElementById("loading").classList.add("hidden");
  if (backups.length === 0) {
    document.getElementById("backups-empty").classList.remove("hidden");
    document.getElementById("backups-list").classList.add("hidden");
    return;
  }
  document.getElementById("backups-empty").classList.add("hidden");
  const list = document.getElementById("backups-list");
  list.classList.remove("hidden");
  list.innerHTML = backups.map(b => `
    <div class="flex items-center justify-between bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-3">
      <div>
        <span class="font-mono text-sm">${esc(b.key)}</span>
        <span class="text-zinc-500 text-xs ml-3">${new Date(b.date).toLocaleString("es-MX")}</span>
        <span class="text-zinc-600 text-xs ml-2">${formatBytes(b.sizeBytes)}</span>
      </div>
      <div class="flex items-center gap-3">
        <a href="/api/admin/backups/${encodeURIComponent(b.key)}" class="text-sm text-red-400 hover:text-red-300 transition-colors">Descargar</a>
        <button data-key="${esc(b.key)}" class="btn-delete-backup text-sm text-zinc-500 hover:text-red-400 transition-colors">Eliminar</button>
      </div>
    </div>
  `).join("");
}

async function triggerBackup() {
  const btn = document.getElementById("btn-trigger");
  const st = document.getElementById("trigger-status");
  btn.disabled = true; btn.textContent = "Creando..."; st.classList.add("hidden");
  try {
    const res = await fetch("/api/admin/backups/trigger", { method: "POST" });
    const data = await res.json();
    if (res.ok) {
      st.className = "mt-4 p-3 rounded-lg text-sm bg-green-900/50 border border-green-800 text-green-300";
      st.textContent = "Backup creado: " + data.key + " (" + data.users + " usuarios)";
      const lr = await fetch("/api/admin/backups"); if (lr.ok) renderBackups(await lr.json());
    } else {
      st.className = "mt-4 p-3 rounded-lg text-sm bg-red-900/50 border border-red-800 text-red-300";
      st.textContent = data.error || "Error al crear backup";
    }
  } catch {
    st.className = "mt-4 p-3 rounded-lg text-sm bg-red-900/50 border border-red-800 text-red-300";
    st.textContent = "Error de conexion";
  }
  st.classList.remove("hidden"); btn.disabled = false; btn.textContent = "Crear backup ahora";
}

// --- Users ---

let usersLoaded = false;

// --- Campaigns ---

let campaignsLoaded = false;

async function loadCampaigns() {
  const res = await fetch("/api/admin/campaigns");
  if (!res.ok) return;
  const rows = await res.json();
  campaignsLoaded = true;
  document.getElementById("campaigns-loading").classList.add("hidden");
  const list = document.getElementById("campaigns-list");
  list.classList.remove("hidden");
  if (rows.length === 0) {
    list.innerHTML = '<p class="text-zinc-500 text-sm py-4">Todavía no llega nadie con utm.</p>';
    return;
  }
  const fecha = (iso) => iso ? new Date(iso).toLocaleDateString("es-MX", { day: "numeric", month: "short" }) : "—";
  const pct = (n, d) => d ? Math.round((n / d) * 100) + "%" : "—";
  list.innerHTML = `
    <table class="w-full text-sm">
      <thead class="text-xs text-zinc-500 uppercase tracking-wide">
        <tr class="border-b border-zinc-800 text-left">
          <th class="py-2 pr-4">Campaña</th><th class="py-2 pr-4">Fuente / medio</th>
          <th class="py-2 pr-4 text-right">Registros</th><th class="py-2 pr-4 text-right">Verificados</th>
          <th class="py-2 pr-4 text-right">Con dominio</th><th class="py-2 pr-4">Primero</th><th class="py-2">Último</th>
        </tr>
      </thead>
      <tbody>
        ${rows.map(r => `
          <tr class="border-b border-zinc-900">
            <td class="py-2 pr-4 font-medium">${esc(r.campaign || "—")}</td>
            <td class="py-2 pr-4 text-zinc-400">${esc(r.source || "—")} / ${esc(r.medium || "—")}</td>
            <td class="py-2 pr-4 text-right">${r.registros}</td>
            <td class="py-2 pr-4 text-right">${r.verificados} <span class="text-zinc-600">${pct(r.verificados, r.registros)}</span></td>
            <td class="py-2 pr-4 text-right">${r.conDominio} <span class="text-zinc-600">${pct(r.conDominio, r.registros)}</span></td>
            <td class="py-2 pr-4 text-zinc-400">${fecha(r.primero)}</td>
            <td class="py-2 text-zinc-400">${fecha(r.ultimo)}</td>
          </tr>`).join("")}
      </tbody>
    </table>`;
}
let allUsers = [];
let selectedEmail = null;

async function loadUsers() {
  const res = await fetch("/api/admin/users");
  if (!res.ok) return;
  allUsers = await res.json();
  usersLoaded = true;
  document.getElementById("users-loading").classList.add("hidden");
  renderUsers(allUsers);
}

function filterUsers() {
  const q = document.getElementById("user-search").value.toLowerCase();
  renderUsers(q ? allUsers.filter(u => u.email.toLowerCase().includes(q)) : allUsers);
}

function renderUsers(users) {
  const list = document.getElementById("users-list");
  list.classList.remove("hidden");
  if (users.length === 0) {
    list.innerHTML = '<p class="text-zinc-500 text-sm py-4">Sin resultados.</p>';
    return;
  }
  list.innerHTML = users.map(u => `
    <div class="user-row flex items-center justify-between rounded-lg px-3 py-2 cursor-pointer transition-colors
                ${u.email === selectedEmail ? 'bg-zinc-800 border border-zinc-700' : 'hover:bg-zinc-900 border border-transparent'}"
         data-email="${esc(u.email)}">
      <div class="flex items-center gap-2 min-w-0">
        <span class="text-sm font-medium truncate">${esc(u.email)}</span>
        ${u.emailVerified ? '<span class="text-green-500 text-xs shrink-0">✓</span>' : '<span class="text-zinc-600 text-xs shrink-0">✗</span>'}
      </div>
      <div class="flex items-center gap-3 text-xs text-zinc-500 shrink-0 ml-2">
        <span>${u.plan || '—'}</span>
        <span class="${u.status === 'active' ? 'text-green-500' : u.status === 'cancelled' ? 'text-red-400' : ''}">${esc(u.status)}</span>
        ${u.paying
          ? '<span class="text-green-500" title="Suscripción real en MercadoPago">$ pagado</span>'
          : '<span class="text-amber-500" title="Plan puesto a mano, sin suscripción en MercadoPago">cortesía</span>'}
        <span>${u.domainsCount}d</span>
        ${u.utmCampaign ? `<span class="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400" title="utm_source: ${esc(u.utmSource || "")}">${esc(u.utmCampaign)}</span>` : ""}
      </div>
    </div>
  `).join("");
}

async function openUserDetail(email) {
  selectedEmail = email;
  renderUsers(document.getElementById("user-search").value.toLowerCase()
    ? allUsers.filter(u => u.email.toLowerCase().includes(document.getElementById("user-search").value.toLowerCase()))
    : allUsers);

  const res = await fetch(`/api/admin/users/${encodeURIComponent(email)}`);
  if (!res.ok) return;
  const user = await res.json();

  document.getElementById("detail-email").textContent = user.email;
  document.getElementById("detail-plan").value = user.subscription?.plan ?? "basico";
  document.getElementById("detail-status").value = user.subscription?.status ?? "none";
  document.getElementById("detail-verified").checked = user.emailVerified ?? false;
  const pe = user.subscription?.currentPeriodEnd;
  document.getElementById("detail-period-end").value = pe ? pe.split("T")[0] : "";

  const dd = document.getElementById("detail-domains");
  dd.innerHTML = user.domains?.length
    ? user.domains.map(d => `
        <div class="flex items-center justify-between bg-zinc-800 rounded px-3 py-1.5">
          <span>${esc(d.domain)} ${d.verified ? '<span class="text-green-500">✓</span>' : '<span class="text-zinc-600">✗</span>'}</span>
          <span class="text-zinc-500">${d.aliasCount} alias</span>
        </div>`).join("")
    : '<p class="text-zinc-600">Sin dominios</p>';

  document.getElementById("detail-save-status").classList.add("hidden");
  document.getElementById("user-detail").classList.remove("hidden");
}

function closeDetail() {
  document.getElementById("user-detail").classList.add("hidden");
  selectedEmail = null;
  filterUsers();
}

async function saveUser() {
  if (!selectedEmail) return;
  const btn = document.getElementById("btn-save-user");
  btn.disabled = true; btn.textContent = "Guardando...";

  const status = document.getElementById("detail-status").value;
  const periodEnd = document.getElementById("detail-period-end").value || null;

  // Un status "active" con la fecha vencida NO da plan: getUserPlanLimits mira
  // primero si el periodo ya pasó y devuelve cero de todo. Es la trampa entera de
  // esta pantalla, porque el formulario conserva la fecha anterior aunque cambies
  // el plan, y el usuario se queda sin reenvío creyendo que lo activó.
  if ((status === "active" || status === "cancelled") && periodEnd && new Date(periodEnd) < new Date()) {
    if (!confirm(`La fecha de fin de periodo (${periodEnd}) ya pasó, así que el plan seguirá contando como inactivo y el correo no se reenviará.\n\n¿Guardar de todos modos?`)) {
      btn.disabled = false; btn.textContent = "Guardar";
      return;
    }
  }

  const body = {
    plan: document.getElementById("detail-plan").value,
    status,
    currentPeriodEnd: periodEnd,
    emailVerified: document.getElementById("detail-verified").checked,
  };

  try {
    const res = await fetch(`/api/admin/users/${encodeURIComponent(selectedEmail)}`, {
      method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    });
    const st = document.getElementById("detail-save-status");
    if (res.ok) {
      st.className = "mb-3 p-2 rounded text-sm bg-green-900/50 border border-green-800 text-green-300";
      st.textContent = "Guardado";
      usersLoaded = false; loadUsers();
    } else {
      const d = await res.json();
      st.className = "mb-3 p-2 rounded text-sm bg-red-900/50 border border-red-800 text-red-300";
      st.textContent = d.error || "Error al guardar";
    }
    st.classList.remove("hidden");
  } catch { alert("Error de conexión"); }

  btn.disabled = false; btn.textContent = "Guardar";
}

async function deleteUserHandler() {
  if (!selectedEmail) return;
  if (!confirm(`¿Eliminar "${selectedEmail}" y todos sus datos?`)) return;
  const btn = document.getElementById("btn-delete-user");
  btn.disabled = true; btn.textContent = "Eliminando...";
  try {
    const res = await fetch(`/api/admin/users/${encodeURIComponent(selectedEmail)}`, { method: "DELETE" });
    if (res.ok) { closeDetail(); usersLoaded = false; loadUsers(); }
    else { const d = await res.json(); alert(d.error || "Error"); }
  } catch { alert("Error de conexión"); }
  btn.disabled = false; btn.textContent = "Eliminar";
}

// --- Coupons ---

let couponsLoaded = false;
let allCoupons = [];

async function loadCoupons() {
  const res = await fetch("/api/admin/coupons");
  if (!res.ok) return;
  allCoupons = await res.json();
  couponsLoaded = true;
  document.getElementById("coupons-loading").classList.add("hidden");
  renderCoupons();
}

function renderCoupons() {
  if (allCoupons.length === 0) {
    document.getElementById("coupons-empty").classList.remove("hidden");
    document.getElementById("coupons-list").classList.add("hidden");
    return;
  }
  document.getElementById("coupons-empty").classList.add("hidden");
  const list = document.getElementById("coupons-list");
  list.classList.remove("hidden");
  const baseUrl = window.location.origin;
  list.innerHTML = allCoupons.map(c => {
    const link = `${baseUrl}/pricing?coupon=${encodeURIComponent(c.code)}`;
    const expired = c.expiresAt && new Date(c.expiresAt) < new Date();
    const statusBadge = c.used
      ? '<span class="text-xs bg-zinc-700 text-zinc-400 px-2 py-0.5 rounded">Usado</span>'
      : expired
        ? '<span class="text-xs bg-red-900/50 text-red-400 px-2 py-0.5 rounded">Expirado</span>'
        : '<span class="text-xs bg-green-900/50 text-green-400 px-2 py-0.5 rounded">Activo</span>';
    return `
      <div class="flex items-center justify-between bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-3">
        <div class="flex items-center gap-3 min-w-0">
          <span class="font-mono text-sm font-bold">${esc(c.code)}</span>
          ${statusBadge}
          <span class="text-zinc-400 text-sm">${esc(c.plan)}</span>
          <span class="text-zinc-500 text-sm">$${(c.fixedPrice / 100).toFixed(0)} MXN</span>
          ${c.singleUse ? '<span class="text-xs text-zinc-600">1 uso</span>' : ''}
          ${c.expiresAt ? '<span class="text-xs text-zinc-600">exp ' + new Date(c.expiresAt).toLocaleDateString("es-MX") + '</span>' : ''}
        </div>
        <div class="flex items-center gap-3 shrink-0">
          <button data-link="${esc(link)}" class="btn-copy-link text-sm text-mask-400 hover:text-mask-300 transition-colors">Copiar link</button>
          <button data-code="${esc(c.code)}" class="btn-delete-coupon text-sm text-zinc-500 hover:text-red-400 transition-colors">Eliminar</button>
        </div>
      </div>`;
  }).join("");
}

function initCoupons() {
  document.getElementById("btn-create-coupon").addEventListener("click", () => {
    const cm = document.getElementById("coupon-modal");
    if (cm.classList.contains("hidden")) { cm.classList.remove("hidden"); lockBodyScroll(); }
    document.getElementById("coupon-modal-error").classList.add("hidden");
    document.getElementById("coupon-code").value = "";
    document.getElementById("coupon-desc").value = "";
    document.getElementById("coupon-price").value = "5000";
    document.getElementById("coupon-plan").value = "freelancer";
    document.getElementById("coupon-single").checked = false;
    document.getElementById("coupon-expires").value = "";
  });

  document.getElementById("btn-cancel-coupon").addEventListener("click", () => {
    const cmc = document.getElementById("coupon-modal");
        if (!cmc.classList.contains("hidden")) { cmc.classList.add("hidden"); unlockBodyScroll(); }
  });

  document.getElementById("coupon-price").addEventListener("input", (e) => {
    const v = Number(e.target.value);
    const preview = document.getElementById("coupon-price-preview");
    if (v < 100) {
      preview.textContent = "⚠ Mínimo 100 centavos ($1 MXN)";
      preview.className = "text-xs text-red-400 mt-1 block";
    } else {
      preview.textContent = `= $${(v / 100).toLocaleString("es-MX", { minimumFractionDigits: 0 })} MXN/mes`;
      preview.className = "text-xs text-green-400 mt-1 block";
    }
  });

  document.getElementById("btn-gen-code").addEventListener("click", () => {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let code = "";
    for (let i = 0; i < 8; i++) code += chars[Math.floor(Math.random() * chars.length)];
    document.getElementById("coupon-code").value = code;
  });

  document.getElementById("btn-save-coupon").addEventListener("click", async () => {
    const btn = document.getElementById("btn-save-coupon");
    const errEl = document.getElementById("coupon-modal-error");
    btn.disabled = true; btn.textContent = "Creando...";
    errEl.classList.add("hidden");

    const body = {
      code: document.getElementById("coupon-code").value,
      plan: document.getElementById("coupon-plan").value,
      fixedPrice: Number(document.getElementById("coupon-price").value),
      description: document.getElementById("coupon-desc").value,
      singleUse: document.getElementById("coupon-single").checked,
      expiresAt: document.getElementById("coupon-expires").value || undefined,
    };

    if (!body.code || !body.fixedPrice || !body.description) {
      errEl.textContent = "Completa todos los campos requeridos";
      errEl.classList.remove("hidden");
      btn.disabled = false; btn.textContent = "Crear";
      return;
    }

    try {
      const res = await fetch("/api/admin/coupons", {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      if (res.ok) {
        const cmc = document.getElementById("coupon-modal");
        if (!cmc.classList.contains("hidden")) { cmc.classList.add("hidden"); unlockBodyScroll(); }
        couponsLoaded = false; loadCoupons();
      } else {
        const d = await res.json();
        errEl.textContent = d.error || "Error al crear";
        errEl.classList.remove("hidden");
      }
    } catch { errEl.textContent = "Error de conexion"; errEl.classList.remove("hidden"); }
    btn.disabled = false; btn.textContent = "Crear";
  });

  document.getElementById("coupons-list").addEventListener("click", async (e) => {
    const copyBtn = e.target.closest(".btn-copy-link");
    if (copyBtn) {
      await navigator.clipboard.writeText(copyBtn.dataset.link);
      copyBtn.textContent = "Copiado!";
      setTimeout(() => copyBtn.textContent = "Copiar link", 1500);
      return;
    }
    const delBtn = e.target.closest(".btn-delete-coupon");
    if (delBtn) {
      if (!confirm(`Eliminar cupon "${delBtn.dataset.code}"?`)) return;
      delBtn.disabled = true; delBtn.textContent = "...";
      const res = await fetch(`/api/admin/coupons/${encodeURIComponent(delBtn.dataset.code)}`, { method: "DELETE" });
      if (res.ok) { couponsLoaded = false; loadCoupons(); }
      else { const d = await res.json(); alert(d.error || "Error"); }
    }
  });
}

document.addEventListener("DOMContentLoaded", init);
