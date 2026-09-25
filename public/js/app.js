function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
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
    const p = _fetch.call(this, url, opts);
    // Sesión caducada: al login, no un error a media pantalla.
    if (String(url).startsWith("/api/") && !String(url).startsWith("/api/auth/")) {
      p.then((res) => { if (res.status === 401) window.location.href = "/login"; }).catch(() => {});
    }
    return p;
  };
}

// --- State ---
let currentUser = null;
let domains = [];
let selectedDomain = null;

// Todo es POR DOMINIO desde el 7-sep-2026: derechos, add-ons y uso vienen en
// currentUser.porDominio. Ya no existe "el plan de la cuenta".
function porDominio(id) {
  return (currentUser?.porDominio ?? []).find(d => d.id === id) ?? null;
}
function derechosDe(id) {
  return porDominio(id)?.derechos ?? { activado: false, esGratis: true, bloqueado: false, aliases: 5, agentes: 0, sends: 0, sendsUnlocked: false, mailboxes: false, mailboxBytes: 0, rules: false, webhooks: false, smtpRelay: false };
}
function estadoDominio(id) {
  const r = derechosDe(id);
  return r.activado ? "activado" : r.bloqueado ? "bloqueado" : "gratis";
}
const money = (c) => `$${(c / 100).toLocaleString("es-MX")}`;
const GB = 1024 * 1024 * 1024;

// Todo lo que depende de /api/auth/me se pinta desde aquí. Antes `refreshUsage` no
// llamaba a `renderBillingBanner`, así que cancelar un add-on dejaba el estado de
// facturación viejo en pantalla — con el resumen de cobro eso ya no es cosmético: el
// total se quedaría en un número que no es.
function renderAccountUI() {
  renderHello();
  renderBillingBanner();
  renderPlanCard();
  renderReferralBanner();
  renderReferrals();
}

// --- Saludo y estado ---
function renderHello() {
  const el = document.getElementById("home-hello");
  if (!el || !currentUser) return;
  const h = new Date().getHours();
  const saludo = h < 12 ? "Buenos días" : h < 19 ? "Buenas tardes" : "Buenas noches";
  const nombre = (currentUser.email || "").split("@")[0].split(/[._+-]/)[0];
  const quien = nombre ? nombre.charAt(0).toUpperCase() + nombre.slice(1) : "";
  const pendientes = domains.filter(d => !d.verified).length;
  const bloqueados = domains.filter(d => estadoDominio(d.id) === "bloqueado").length;
  let estado;
  if (domains.length === 0) estado = "Agrega tu dominio para empezar a recibir correo. El primero es gratis.";
  else if (bloqueados > 0) estado = `${bloqueados === 1 ? "Un dominio guarda correo pero no reenvía" : `${bloqueados} dominios guardan correo pero no reenvían`}: actívalo por $99 al mes.`;
  else if (pendientes > 0) estado = `${pendientes === 1 ? "Un dominio espera" : `${pendientes} dominios esperan`} configuración DNS.`;
  else estado = `${domains.length === 1 ? "Tu dominio recibe" : "Tus dominios reciben"} con normalidad. Nada pendiente.`;
  const hoy = new Date().toLocaleDateString("es-MX", { weekday: "short", day: "numeric", month: "short" });
  el.innerHTML = `
    <div>
      <h1>${esc(saludo)}${quien ? `, ${esc(quien)}` : ""}</h1>
      <p>${esc(estado)}</p>
    </div>
    <span class="today num">${esc(hoy)}</span>`;
}

// --- Tarjeta de cuenta: qué dominio está en qué estado, y cuánto se cobra al mes ---
//
// Ya no hay "plan". Cada dominio es gratis o está activado ($99/mes), y sobre el activado
// se suman bloques de +50 GB y +100 envíos, a $99 cada uno. La tarjeta lo dice por dominio.
function renderPlanCard() {
  const el = document.getElementById("plan-card");
  if (!el || !currentUser) return;
  const lista = currentUser.porDominio ?? [];
  const sub = currentUser.subscription;
  const periodEnd = sub?.currentPeriodEnd ? new Date(sub.currentPeriodEnd) : null;
  const legadoVigente = sub && (sub.status === "active" || sub.status === "cancelled") && periodEnd && periodEnd >= new Date();
  const fecha = (d) => d.toLocaleDateString("es-MX", { day: "numeric", month: "long" });

  const efectivo = (a) => a.status === "active" || (a.status === "cancelled" && a.currentPeriodEnd && new Date(a.currentPeriodEnd) >= new Date());
  let total = legadoVigente ? (currentUser.planPriceCents ?? 0) : 0;
  for (const a of (currentUser.addons ?? []).filter(efectivo)) total += a.isCourtesy ? 0 : (a.priceCents ?? 0);

  const filas = lista.map(d => {
    const r = d.derechos;
    const estado = r.activado ? (r.legado ? "activado · plan anterior" : "activado") : r.bloqueado ? "sin activar" : "gratis";
    const extras = (d.addons ?? []).filter(a => a.kind !== "domain");
    const cortesia = (d.addons ?? []).some(a => a.kind === "domain" && a.isCourtesy);
    const detalle = r.activado
      ? [cortesia ? "cortesía" : null, extras.length ? `${extras.length} bloque${extras.length === 1 ? "" : "s"}` : null].filter(Boolean).join(" · ")
      : r.bloqueado ? "guarda, no reenvía" : `${r.aliases} máscaras · 7 días de Bandeja`;
    return `
      <div class="meter">
        <div class="l"><span>${esc(d.domain)}</span><span class="num">${esc(estado)}</span></div>
        ${detalle ? `<div class="note">${esc(detalle)}</div>` : ""}
      </div>`;
  }).join("");

  el.innerHTML = `
    <div class="app-card plan-card">
      <div class="plan-h">
        <h3>Tu cuenta</h3>
        <span class="price num">${money(total)} <small>MXN / mes</small></span>
      </div>
      <div class="next">${lista.length === 0
        ? "Tu primer dominio es gratis. Actívalo cuando quieras al equipo entero: $99 al mes."
        : legadoVigente
          ? `Plan anterior <b>${esc(sub.planLabel ?? sub.plan)}</b> ${sub.status === "cancelled" ? "termina" : "cubierto hasta"} el <b>${fecha(periodEnd)}</b> — mientras dure, todos tus dominios cuentan como activados.`
          : "Cada dominio activado: $99 al mes, todo incluido, personas ilimitadas."}</div>
      <div class="meters">${filas}</div>
      <div class="foot">
        <button data-action="show-orders" class="app-link">Historial de pagos</button>
        <a href="/pricing" class="app-link">Qué incluye</a>
        ${legadoVigente && sub.status === "active" ? `<button id="btn-cancel-sub" class="danger">Cancelar plan anterior</button>` : ""}
      </div>
    </div>`;
  document.getElementById("btn-cancel-sub")?.addEventListener("click", cancelSubscription);
}

async function refreshUsage() {
  const res = await fetch("/api/auth/me");
  if (!res.ok) return;
  currentUser = await res.json();
  renderAccountUI();
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
  // Ya no hay plan: la píldora sólo aparece mientras viva una suscripción anterior,
  // porque explica por qué todos los dominios cuentan como activados.
  const subBadge = currentUser.subscription;
  const finBadge = subBadge?.currentPeriodEnd ? new Date(subBadge.currentPeriodEnd) : null;
  if (badge && subBadge?.plan && (!finBadge || finBadge >= new Date())) {
    badge.textContent = `plan anterior · ${subBadge.planLabel ?? subBadge.plan}`;
    badge.classList.remove("hidden");
  }

  // La API (y el MCP y las skills) va con todas las cuentas, gratis incluidas: la pestaña
  // se ocultaba a quien no tuviera una suscripción legado y nadie nuevo podía crear su llave.
  document.getElementById("tab-btn-apikeys")?.classList.remove("hidden");

  renderVerifyBanner();
  renderAccountUI();

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
    <div class="bg-amber-500/15 border border-amber-500/30 rounded-xl px-4 py-3 flex items-center justify-between">
      <span class="text-sm text-amber-600">Verifica tu email para acceder a todas las funciones.</span>
      <button id="btn-resend-verify" class="text-xs text-amber-600 hover:text-yellow-300 underline transition-colors">Reenviar email</button>
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
  // Sin plan no hay nada que atender: el primer dominio es gratis. Sólo avisa cuando
  // una suscripción ANTERIOR está por terminar, porque sus dominios volverán a la
  // regla normal (el primero gratis, los demás requieren activación).
  const sub = currentUser.subscription;
  const periodEnd = sub?.currentPeriodEnd ? new Date(sub.currentPeriodEnd) : null;
  const isExpired = periodEnd && periodEnd < new Date();
  const isCancelledWithAccess = sub && sub.status === "cancelled" && periodEnd && !isExpired;
  if (isCancelledWithAccess && domains.length > 1) {
    container.innerHTML = `
      <div class="bg-amber-500/15 border border-amber-500/30 rounded-xl px-4 py-3 text-sm text-amber-600">
        Tu plan anterior termina el ${periodEnd.toLocaleDateString("es-MX")}. Después, tu primer dominio sigue gratis y los demás necesitan activarse ($99/mes cada uno).
      </div>`;
  } else {
    container.innerHTML = "";
  }
  const addDomainBtn = document.getElementById("btn-add-domain");
  if (addDomainBtn) { addDomainBtn.classList.remove("opacity-50", "pointer-events-none"); addDomainBtn.title = ""; }
}

// --- Resumen de cobro ---

// Sección siempre visible, no un modal. La queja de fondo es que la app nunca decía lo
// que cobraba: esconder la respuesta detrás de un clic repetiría el error de los
// add-ons. Y va aparte de renderBillingBanner, que ya tiene cuatro ramas.
function renderBillingSummary() {
  const el = document.getElementById("billing-summary");
  if (!el) return;
  const catalog = currentUser?.addonCatalog ?? {};
  const now = new Date();
  const efectivo = (a) => a.status === "active" || (a.status === "cancelled" && a.currentPeriodEnd && new Date(a.currentPeriodEnd) >= now);
  const sub = currentUser?.subscription;
  const periodEnd = sub?.currentPeriodEnd ? new Date(sub.currentPeriodEnd) : null;
  const legadoVigente = sub && (sub.status === "active" || sub.status === "cancelled") && periodEnd && periodEnd >= now;

  const lines = [];
  if (legadoVigente) lines.push({ label: `Plan anterior · ${sub.planLabel ?? sub.plan}`, cents: currentUser.planPriceCents ?? 0, gift: false });
  for (const a of (currentUser?.addons ?? []).filter(efectivo)) {
    const dom = domains.find(d => d.id === a.domainId)?.domain;
    const label = `${catalog[a.kind]?.label ?? a.kind}${dom ? ` · ${dom}` : ""}`;
    lines.push({ label: a.isCourtesy ? `${label} (cortesía)` : label, cents: a.isCourtesy ? 0 : (a.priceCents ?? 0), gift: !!a.isCourtesy });
  }
  if (!lines.length) { el.innerHTML = ""; return; }
  const total = lines.reduce((sum, l) => sum + l.cents, 0);
  const aviso = renderLastOrderStrip();

  el.innerHTML = `
    <div class="bg-bg-elev border border-line rounded-xl px-4 py-3">
      ${aviso}
      <div class="flex items-center justify-between mb-2">
        <span class="text-[11px] uppercase tracking-widest text-fg-muted font-semibold">Tu cobro mensual</span>
        <button data-action="show-orders" class="text-xs text-accent-text hover:text-accent transition-colors">Historial de pagos</button>
      </div>
      <div class="space-y-1">
        ${lines.map(l => `
          <div class="flex items-center justify-between gap-3 text-sm">
            <span class="${l.gift ? "text-accent-text" : "text-fg"}">${esc(l.label)}</span>
            <span class="${l.gift ? "text-accent-text" : "text-fg"}">${money(l.cents)}</span>
          </div>`).join("")}
      </div>
      <div class="flex items-center justify-between border-t border-line mt-2 pt-2">
        <span class="text-sm font-semibold text-fg">Total</span>
        <span class="text-sm font-semibold text-fg">${money(total)} MXN/mes</span>
      </div>
    </div>`;
}

// Aviso de que sí pasó algo con tu dinero. No hay tabla de notificaciones a propósito:
// el libro mayor ya es el almacén, y el descarte es preferencia de vista, no dato —
// por eso vive en localStorage. En el peor caso reaparece en otro dispositivo.
function renderLastOrderStrip() {
  const lo = currentUser?.lastOrder;
  if (!lo) return "";

  const dias = (Date.now() - new Date(lo.createdAt).getTime()) / 864e5;
  if (dias > 14) return "";

  const fallo = lo.kind === "failed_charge";
  // El fallido no se puede descartar: es una tarea pendiente, no una noticia.
  if (!fallo && localStorage.getItem("mm:seen-order") === lo.id) return "";

  const fecha = new Date(lo.occurredAt).toLocaleDateString("es-MX");
  const monto = `$${((fallo ? (lo.listPriceCents ?? 0) : lo.amountCents) / 100).toLocaleString("es-MX")}`;

  if (fallo) {
    return `
      <div class="flex flex-wrap items-center justify-between gap-2 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2 mb-3">
        <span class="text-sm text-red-500">No pudimos cobrar ${monto} MXN el ${fecha}</span>
        <button data-action="show-orders" class="text-xs text-red-300 hover:text-red-200">Ver detalle</button>
      </div>`;
  }
  return `
    <div class="flex flex-wrap items-center justify-between gap-2 bg-accent/10 border border-accent/30 rounded-lg px-3 py-2 mb-3">
      <span class="text-sm text-accent-text">Cobramos ${monto} MXN el ${fecha}</span>
      <div class="flex items-center gap-3">
        <button data-action="show-orders" class="text-xs text-accent-text hover:text-accent">Ver recibo</button>
        <button data-action="dismiss-order" data-order-id="${esc(lo.id)}" class="text-fg-muted hover:text-fg text-lg leading-none">&times;</button>
      </div>
    </div>`;
}

// --- Historial de pagos ---

const ORDER_TONE = {
  charge:       { dot: "bg-green-400", label: "Pagado" },
  courtesy:     { dot: "bg-mask-400",  label: "Cortesía" },
  cancellation: { dot: "bg-fg-muted",  label: "Cancelado" },
  failed_charge:{ dot: "bg-red-400",   label: "Rechazado" },
};

async function showOrdersModal() {
  const list = document.getElementById("orders-list");
  const err = document.getElementById("orders-error");
  if (!list) return;
  err.classList.add("hidden");
  list.innerHTML = `<div class="text-fg-muted text-sm">Cargando…</div>`;
  showModal("modal-orders");

  const res = await fetch("/api/billing/orders");
  if (!res.ok) {
    list.innerHTML = "";
    err.textContent = "No se pudo cargar el historial.";
    err.classList.remove("hidden");
    return;
  }
  const { orders } = await res.json();
  if (!orders.length) {
    list.innerHTML = `<div class="text-fg-muted text-sm">Todavía no hay movimientos. Aquí van a aparecer tus cargos, cortesías y cancelaciones.</div>`;
    return;
  }

  // Dos líneas por fila: cinco campos no caben en un teléfono en una sola.
  list.innerHTML = orders.map(o => {
    const tone = ORDER_TONE[o.kind] ?? ORDER_TONE.charge;
    const gratis = o.kind === "courtesy" || o.amountCents === 0;
    const monto = o.kind === "failed_charge" && o.listPriceCents
      ? `$${(o.listPriceCents / 100).toLocaleString("es-MX")}`
      : gratis ? "$0" : `$${(o.amountCents / 100).toLocaleString("es-MX")}`;
    const periodo = o.periodStart && o.periodEnd
      ? ` · ${new Date(o.periodStart).toLocaleDateString("es-MX")} – ${new Date(o.periodEnd).toLocaleDateString("es-MX")}`
      : o.periodEnd ? ` · hasta ${new Date(o.periodEnd).toLocaleDateString("es-MX")}` : "";

    return `
      <div class="border border-line rounded-lg px-4 py-3">
        <div class="flex items-start justify-between gap-4">
          <div class="min-w-0">
            <div class="text-sm text-fg truncate">${esc(o.concept)}</div>
            <div class="text-xs text-fg-muted mt-0.5">${new Date(o.date).toLocaleDateString("es-MX")}${periodo}</div>
            ${o.failureReason ? `<div class="text-xs text-red-500 mt-0.5">${esc(o.failureReason)}</div>` : ""}
            ${o.note ? `<div class="text-xs text-fg-muted mt-0.5">${esc(o.note)}</div>` : ""}
          </div>
          <div class="text-right shrink-0">
            <div class="text-sm font-semibold ${gratis ? "text-accent-text" : "text-fg"}">
              ${monto} <span class="text-xs font-normal text-fg-muted">${esc(o.currency)}</span>
            </div>
            <div class="flex items-center justify-end gap-1.5 mt-0.5">
              <span class="w-1.5 h-1.5 rounded-full ${tone.dot}"></span>
              <span class="text-xs text-fg-muted">${tone.label}</span>
            </div>
          </div>
        </div>
        <div class="flex flex-wrap items-center gap-3 mt-2 pt-2 border-t border-line text-[11px] text-fg-muted">
          <span class="font-mono">${esc(o.number)}</span>
          ${o.reference ? `<span class="font-mono">MP ${esc(o.reference)}</span>` : ""}
          <button data-action="copy-order" data-order-number="${esc(o.number)}" class="text-accent-text hover:text-accent ml-auto">Copiar folio</button>
        </div>
      </div>`;
  }).join("");
}

// --- Stats row (big numbers) ---
function renderStats() {
  const container = document.getElementById("stats-row");
  if (!container || !currentUser?.usage) return;

  const u = currentUser.usage;
  if (u.domains.limit === 0) { container.innerHTML = ""; return; }

  const totalAliases = u.aliasesPerDomain.reduce((s, a) => s + a.current, 0);
  const totalForwards = domains.reduce((s, d) => s + (d.monthlyForwards ?? 0), 0);
  const sendsToday = (u.sendsPerDomain ?? []).reduce((s, d) => s + d.current, 0);
  // Ya no hay `limits` global: cada dominio trae sus derechos en `porDominio`.
  const rights = (currentUser?.porDominio ?? []).map((d) => d.derechos ?? {});
  const sendsLimit = rights.reduce((s, d) => s + (d.sendsUnlocked ? d.sends ?? 0 : 0), 0);
  const sendsUnlocked = rights.some((d) => d.sendsUnlocked);
  const fwdPerHour = Math.max(0, ...rights.map((d) => d.forwardPerHour ?? 0));
  // Tope mensual por cuenta: es el que protege el margen (SES cobra por correo).
  const fwdMes = currentUser?.forwards?.current ?? 0;
  const fwdCap = currentUser?.forwards?.limit ?? 0;

  // Los envíos son el límite chico y el que se agota; el reenvío de entrada es un orden
  // de magnitud mayor y es lo que de verdad usa quien solo redirige correo. Se muestran
  // juntos para que nadie confunda uno con el otro.
  // 2 columnas en móvil y 4 desde sm: cuatro cifras de 3xl no caben en un teléfono.
  container.innerHTML = `
    <div class="bg-bg-elev border border-line rounded-xl p-5">
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-6">
        <div>
          <span class="text-[11px] uppercase tracking-widest text-fg-subtle font-semibold">Dominios</span>
          <div class="text-3xl font-light text-fg mt-1">${u.domains.current}${u.domains.limit == null ? "" : `<span class="text-lg text-fg-subtle">/${u.domains.limit}</span>`}</div>
        </div>
        <div>
          <span class="text-[11px] uppercase tracking-widest text-fg-subtle font-semibold">Alias</span>
          <div class="text-3xl font-light text-fg mt-1">${totalAliases}</div>
        </div>
        <div>
          <span class="text-[11px] uppercase tracking-widest text-fg-subtle font-semibold">Envíos hoy</span>
          ${sendsUnlocked
            ? `<div class="text-3xl font-light text-fg mt-1">${sendsToday.toLocaleString("es-MX")}<span class="text-lg text-fg-subtle">/${sendsLimit.toLocaleString("es-MX")}</span></div>
               <div class="text-[11px] text-fg-subtle mt-0.5">por dominio, al día</div>`
            : `<div class="text-3xl font-light text-fg-subtle mt-1">—</div>
               <button id="usage-addon-cta" class="text-[11px] text-accent-text hover:underline mt-0.5">Activar envíos →</button>`}
        </div>
        <div>
          <span class="text-[11px] uppercase tracking-widest text-fg-subtle font-semibold">Reenvíos</span>
          <div class="text-3xl font-light text-fg mt-1">${fwdMes.toLocaleString("es-MX")}<span class="text-lg text-fg-subtle">/${fwdCap.toLocaleString("es-MX")}</span></div>
          <div class="text-[11px] ${fwdMes >= fwdCap * 0.8 ? "text-amber-600" : "text-fg-subtle"} mt-0.5">este mes · ${totalForwards.toLocaleString("es-MX")} en total · ${fwdPerHour.toLocaleString("es-MX")}/hora por dominio</div>
        </div>
      </div>
    </div>`;

  document.getElementById("usage-addon-cta")?.addEventListener("click", showAddonsModal);
}

// --- Add-ons ---

const ADDON_COPY = {
  domain:    { desc: "Todo para este dominio: equipo ilimitado en la Bandeja, buzones IMAP, 50 correos nuevos al día, 10 GB, reglas, webhooks y SMTP." },
  storage50: { desc: "50 GB más para los buzones de este dominio. Cuantas veces quieras." },
  sends100:  { desc: "100 correos nuevos más al día en este dominio. Cuantas veces quieras." },
};

// Los add-ons son POR DOMINIO. El modal siempre se abre para uno concreto.
async function showAddonsModal(domainId) {
  domainId = domainId || selectedDomain?.id || domains[0]?.id;
  const dom = domains.find(d => d.id === domainId);
  const list = document.getElementById("addons-list");
  const err = document.getElementById("addons-error");
  const titulo = document.getElementById("addons-domain");
  if (titulo) titulo.textContent = dom?.domain ?? "";
  err.classList.add("hidden");
  list.innerHTML = `<div class="text-fg-subtle text-sm">Cargando…</div>`;
  showModal("modal-addons");

  const res = await fetch("/api/addons");
  if (!res.ok) {
    list.innerHTML = "";
    err.textContent = "No se pudieron cargar los add-ons.";
    err.classList.remove("hidden");
    return;
  }
  const { catalog, forSale, mine } = await res.json();
  const now = new Date();
  const propios = (mine ?? []).filter(a => a.domainId === domainId);
  const effective = propios.filter(a => a.status === "active" || (a.status === "cancelled" && a.currentPeriodEnd && new Date(a.currentPeriodEnd) >= now));
  const r = derechosDe(domainId);

  list.innerHTML = (forSale ?? Object.keys(catalog)).map((kind) => {
    const info = catalog[kind];
    const owned = effective.filter(a => a.kind === kind);
    // Un pago recién hecho vive en `pending` hasta que MercadoPago avisa (o hasta que el
    // cron de reconciliación lo alcanza). Sin esto el usuario volvía del checkout y veía
    // el botón intacto, como si su pago no hubiera existido.
    const pending = propios.filter(a => a.kind === kind && a.status === "pending" && Date.now() - new Date(a.createdAt).getTime() < 30 * 60_000);
    const esDominio = kind === "domain";
    const bloqueado = !esDominio && !r.activado;

    const ownedRows = owned.map(a => {
      if (a.isCourtesy) {
        return `
          <div class="flex flex-wrap items-center gap-2 text-xs mt-2">
            <span class="inline-flex items-center gap-1 bg-accent/10 border border-accent/30 text-accent-text rounded-full px-2 py-0.5">Cortesía</span>
            <span class="text-fg-muted">sin costo${a.currentPeriodEnd ? ` · hasta ${new Date(a.currentPeriodEnd).toLocaleDateString("es-MX")}` : ""}</span>
          </div>`;
      }
      const cancelled = a.status === "cancelled";
      const precio = `$${((a.priceCents ?? info.price) / 100).toLocaleString("es-MX")} MXN/mes`;
      return `
        <div class="flex flex-wrap items-center gap-2 text-xs mt-2">
          <span class="${cancelled ? "text-amber-600" : "text-accent-text"}">${cancelled ? `Termina el ${new Date(a.currentPeriodEnd).toLocaleDateString("es-MX")}` : "Activo"}</span>
          <span class="text-fg-muted">· ${precio}</span>
          ${cancelled ? "" : `<button data-action="cancel-addon" data-addon-id="${esc(a.id)}" class="text-fg-muted hover:text-red-500 transition-colors">Cancelar</button>`}
        </div>`;
    }).join("");
    const pendingRows = pending.map(() => `
      <div class="flex flex-wrap items-center gap-2 text-xs mt-2">
        <span class="inline-flex items-center gap-1 bg-amber-500/15 border border-amber-500/30 text-amber-600 rounded-full px-2 py-0.5">Procesando tu pago…</span>
        <span class="text-fg-muted">se activa en unos minutos</span>
      </div>`).join("");

    let accion;
    if (pending.length) accion = `<div class="text-[11px] text-fg-muted max-w-[8rem]">Pago en proceso</div>`;
    else if (esDominio && r.activado) accion = `<div class="text-[11px] text-accent-text max-w-[8rem]">${r.legado ? "Incluido en tu plan anterior" : "Activado"}</div>`;
    else if (bloqueado) accion = `<div class="text-[11px] text-fg-muted max-w-[8rem]">Primero activa el dominio</div>`;
    else accion = `<button data-action="buy-addon" data-kind="${esc(kind)}" data-domain-id="${esc(domainId)}"
                 class="bg-accent hover:bg-accent/90 text-white text-sm font-semibold px-3 py-1.5 rounded-lg transition-colors">
                 ${esDominio ? "Activar" : owned.length ? "Agregar otro" : "Agregar"}
               </button>`;

    return `
      <div class="border ${esDominio ? "border-accent/30" : "border-line"} rounded-lg p-4 flex items-start justify-between gap-4">
        <div class="flex-1 min-w-0">
          <div class="font-semibold text-fg">${esc(info.label)}</div>
          <div class="text-sm text-fg-muted mt-1">${esc(ADDON_COPY[kind]?.desc ?? "")}</div>
          ${ownedRows}${pendingRows}
        </div>
        <div class="text-right shrink-0">
          <div class="text-xl font-bold">${esDominio ? "" : "+"}$${(info.price / 100).toLocaleString("es-MX")}</div>
          <div class="text-[11px] text-fg-muted mb-2">MXN/mes</div>
          ${accion}
        </div>
      </div>`;
  }).join("");
}

async function buyAddon(kind, domainId) {
  const payerEmail = await askMpEmail();
  if (!payerEmail) return;
  const err = document.getElementById("addons-error");
  err.classList.add("hidden");
  const res = await fetch("/api/addons/checkout", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ kind, domainId, payerEmail }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.init_point) {
    err.textContent = data.error ?? "No se pudo iniciar la compra.";
    err.classList.remove("hidden");
    return;
  }
  window.location.href = data.init_point;
}

async function cancelAddon(id) {
  if (!confirm("¿Cancelar este add-on? Lo conservas hasta que termine el periodo que ya pagaste.")) return;
  const err = document.getElementById("addons-error");
  err.classList.add("hidden");
  const res = await fetch(`/api/addons/${id}/cancel`, { method: "POST" });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    err.textContent = data.error ?? "No se pudo cancelar.";
    err.classList.remove("hidden");
    return;
  }
  await refreshUsage();
  const addon = (currentUser?.addons ?? []).find(a => a.id === id);
  await showAddonsModal(addon?.domainId);
}

// Cualquier botón "Activar" / "+50 GB" de la app abre el modal del dominio que toca.
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-action='open-addons']");
  if (b) showAddonsModal(b.dataset.domainId);
});

// --- Referral credit banner ---
function renderReferralBanner() {
  const container = document.getElementById("referral-credit-banner");
  if (!container) return;
  const stats = currentUser?.referralStats;
  if (!stats || stats.creditsAvailable < 2) { container.innerHTML = ""; return; }

  // Celebration sound
  playCelebration();

  container.innerHTML = `
    <div class="border border-accent/30 bg-accent/10 rounded-xl px-5 py-4">
      <div class="flex items-center gap-3">
        <span class="text-2xl">🎉</span>
        <div>
          <p class="text-sm font-semibold text-accent-text">No pagas este mes — $5 MXN*</p>
          <p class="text-xs text-fg-subtle mt-0.5">*Mínimo requerido por procesador de pagos</p>
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
  return `<svg viewBox="0 0 ${w} ${h}" class="text-accent-text" style="width:${w}px;height:${h}px">${bars}</svg>`;
}

function renderReferrals() {
  const container = document.getElementById("referrals-section");
  if (!container) return;
  const stats = currentUser?.referralStats;
  if (!stats) { container.innerHTML = ""; return; }

  const slug = stats.slug || "";
  const link = slug ? `www.mailmask.studio/register?ref=${esc(slug)}` : "";
  const clicks = stats.clicks || { total: 0, last30Days: 0, byWeek: [] };
  const goal = 2;
  const done = Math.min(goal, stats.converted);
  // Dos puntos en vez de una barra al 0%: una barra vacía sólo dice "no has hecho nada".
  const dots = Array.from({ length: goal }, (_, i) =>
    `<span class="w-2.5 h-2.5 rounded-full ${i < done ? "bg-mask-400" : "bg-line"}"></span>`).join("");
  const hasActivity = clicks.last30Days > 0 || stats.total > 0;

  container.innerHTML = `
    <div class="border border-line rounded-xl px-5 py-4">
      <div class="flex flex-col sm:flex-row sm:items-center gap-4">
        <div class="min-w-0 sm:w-64 shrink-0">
          <div class="flex items-center gap-2">
            <span class="text-sm font-semibold text-fg">Invita y gana un mes gratis</span>
            <span class="flex items-center gap-1" title="${done} de ${goal} referidos activos">${dots}</span>
          </div>
          <p class="text-xs text-fg-subtle mt-0.5">${done}/${goal} referidos activos${hasActivity ? ` · ${clicks.last30Days} clics · ${stats.total} registros` : ""}</p>
        </div>
        ${slug ? `
          <div class="flex items-center gap-2 flex-1 min-w-0">
            <code class="text-xs sm:text-sm text-fg bg-bg-elev border border-line rounded-lg px-3 py-2 flex-1 min-w-0 truncate select-all">${link}</code>
            <button data-action="copy-referral" data-value="${esc(link)}" class="text-sm text-fg hover:text-white bg-bg-inset hover:bg-line border border-line px-3 py-2 rounded-lg transition-colors shrink-0">Copiar</button>
            <button data-action="edit-slug" class="text-xs text-fg-subtle hover:text-fg transition-colors shrink-0" title="Cambiar el nombre del enlace">Editar</button>
          </div>
        ` : `
          <div class="flex items-center gap-3 flex-1">
            <span class="text-sm text-fg-subtle">Aún no tienes enlace de referido.</span>
            <button data-action="edit-slug" class="text-sm text-accent-text hover:text-accent transition-colors">Crear enlace</button>
          </div>
        `}
      </div>

      ${clicks.byWeek.length > 0 && clicks.total > 0 ? `
        <div class="mt-3 flex items-center gap-3">
          <span class="text-[10px] uppercase tracking-widest text-fg-subtle">Clics por semana</span>
          ${buildSparklineSvg(clicks.byWeek)}
        </div>
      ` : ""}

      ${stats.total > 0 && currentUser._referralsList ? `
        <div class="mt-3 pt-3 border-t border-line space-y-1.5">
          ${currentUser._referralsList.map(r => {
            const isConverted = r.status === "converted" || r.status === "credited";
            const masked = r.referredEmail.replace(/^(.{2}).*(@.*)$/, "$1***$2");
            return `
              <div class="flex items-center gap-3 text-sm">
                <span class="w-2 h-2 rounded-full ${isConverted ? 'bg-mask-400' : 'bg-line'}"></span>
                <span class="text-fg-muted font-mono text-xs">${esc(masked)}</span>
                <span class="text-xs ${isConverted ? 'text-accent-text' : 'text-fg-subtle'}">${isConverted ? 'Activo' : 'Pendiente'}</span>
                <span class="text-xs text-fg-subtle ml-auto">${relativeTime(r.createdAt)}</span>
              </div>`;
          }).join("")}
        </div>
      ` : ""}
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

// Ya no hay checkout de plan: lo que se compra son add-ons por dominio (buyAddon).

// Pide el correo de la cuenta de MercadoPago y resuelve con él (o con null si cancelan).
// Existe porque MP exige que `payer_email` sea el correo de la cuenta con la que se paga
// —si no coincide, el checkout muere con "Tu e-mail no coincide con el de la
// suscripción"— y el campo es obligatorio en su API, así que no se puede omitir.
function askMpEmail() {
  return new Promise((resolve) => {
    const form = document.getElementById("form-mp-email");
    const errEl = document.getElementById("mp-email-error");
    errEl.classList.add("hidden");
    form.payerEmail.value = currentUser?.email ?? "";
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      form.removeEventListener("submit", onSubmit);
      cancelBtn?.removeEventListener("click", onCancel);
      hideModal("modal-mp-email");
      resolve(value);
    };
    const onSubmit = (e) => {
      e.preventDefault();
      const email = form.payerEmail.value.trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        errEl.textContent = "Ingresa un correo válido";
        errEl.classList.remove("hidden");
        return;
      }
      finish(email);
    };
    const onCancel = () => finish(null);
    const cancelBtn = document.querySelector('#modal-mp-email [data-modal="modal-mp-email"]');
    form.addEventListener("submit", onSubmit);
    cancelBtn?.addEventListener("click", onCancel);
    showModal("modal-mp-email");
    setTimeout(() => form.payerEmail.focus(), 100);
  });
}

async function cancelSubscription() {
  if (!confirm("¿Cancelar tu plan anterior? Al terminar el periodo pagado, tu primer dominio sigue gratis y los demás necesitarán activarse ($99/mes cada uno).")) return;
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
  toast.className = `fixed top-4 right-4 z-50 px-4 py-3 rounded-lg text-sm font-medium transition-opacity ${isError ? 'bg-red-900/90 text-red-100' : 'bg-mask-800 text-mask-50'}`;
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
  renderHello();
  renderPlanCard(); // los reenvíos del mes salen de los dominios

  // `/app#apikeys` (desde /docs): abre el primer dominio en la pestaña de API Keys.
  if (window.location.hash === "#apikeys" && domains[0]) {
    await selectDomain(domains[0].id);
    switchTab("apikeys");
  }

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

    document.getElementById("btn-add-domain-empty")?.classList.remove("hidden");
    return;
  }

  empty.classList.add("hidden");
  if (header) header.classList.remove("hidden");

  const aliasCount = (id) => (currentUser?.usage?.aliasesPerDomain ?? []).find(a => a.domainId === id)?.current;
  list.innerHTML = `<div class="dom-list">${domains.map(d => {
    const verified = d.verified;
    const fwds = d.monthlyForwards ?? 0;
    const n = aliasCount(d.id);
    const estado = estadoDominio(d.id);
    const chip = estado === "activado" ? `<span class="tag">Activado</span>` : estado === "bloqueado" ? `<span class="tag !bg-amber-500/15 !text-amber-600">Sin activar</span>` : `<span class="tag">Gratis</span>`;
    const detalle = verified
      ? `${n != null ? `<em>${n} alias</em> · ` : ""}${estado === "bloqueado" ? "guarda, no reenvía" : "verificado"}`
      : `<em>Falta configurar DNS</em>`;
    return `
    <div class="dom" data-action="select-domain" data-domain-id="${esc(d.id)}">
      <span class="st ${verified ? "" : "pend"}"></span>
      <div class="min-w-0">
        <div class="name">${esc(d.domain)}${chip}${d.registeredViaMailmask ? '<span class="tag">MailMask</span>' : ''}</div>
        <div class="sub">${detalle}</div>
      </div>
      <div class="k num">${verified
        ? `<b>${fwds.toLocaleString("es-MX")}</b><span>este mes</span>`
        : `<span class="app-link" style="font-size:13px;text-transform:none;letter-spacing:0">Ver DNS</span>`}</div>
      <span class="chev">›</span>
    </div>`;
  }).join("")}</div>`;
}

async function selectDomain(id) {
  selectedDomain = domains.find(d => d.id === id);
  if (!selectedDomain) return;

  document.getElementById("domains-list").classList.add("hidden");
  document.getElementById("empty-state").classList.add("hidden");
  document.getElementById("domain-detail").classList.remove("hidden");
  document.getElementById("domains-header")?.classList.add("hidden");
  document.getElementById("home-aside")?.classList.add("hidden");
  document.getElementById("home-hello")?.classList.add("hidden");
  document.getElementById("referrals-section")?.classList.add("hidden");
  document.getElementById("referral-credit-banner")?.classList.add("hidden");

  document.getElementById("detail-domain-name").textContent = selectedDomain.domain;
  const statusEl = document.getElementById("detail-status");
  statusEl.textContent = selectedDomain.verified ? "Verificado" : "Pendiente DNS";
  statusEl.className = `text-xs px-2 py-1 rounded-full ${selectedDomain.verified ? 'bg-mask-500/15 text-accent-text' : 'bg-amber-500/15 text-amber-600'}`;
  renderActivacion();

  document.getElementById("alias-domain-suffix").textContent = `@${selectedDomain.domain}`;

  // La pestaña DNS está siempre: desde que hay editor, el dominio comprado con nosotros es
  // justamente el que más tiene que editar. Antes se ocultaba porque "el DNS es automático".
  document.querySelector('.tab-btn[data-tab="dns"]')?.classList.remove("hidden");

  switchTab("aliases");
  await loadAliases();
  loadDomainHealth();
}

// Cuánto llevan usado los buzones del dominio. El almacenamiento crece solo y no
// baja al borrar en la Bandeja (son almacenes distintos: la Bandeja va a S3, el
// buzón a Stalwart), así que la barra es el único aviso antes de toparse.
// El dato viene de `mailbox_used_bytes`, que es una CACHÉ reconciliada a diario:
// por eso se dice desde cuándo y no se usa para cobrar.
function barraAlmacenamiento(r) {
  const total = r.mailboxBytes ?? 0;
  if (!total) return "";
  const usado = porDominio(selectedDomain.id)?.uso?.mailboxBytes?.current ?? 0;
  const pct = Math.min(100, Math.round((usado / total) * 1000) / 10);
  const apretado = pct >= 80;
  const color = pct >= 95 ? "bg-red-500" : apretado ? "bg-amber-500" : "bg-accent";
  const gb = (b) => {
    const n = b / GB;
    return n >= 10 ? Math.round(n) + " GB" : n >= 0.1 ? n.toFixed(1) + " GB" : Math.max(1, Math.round(b / (1024 * 1024))) + " MB";
  };
  return `
    <div class="bg-bg-elev border border-line rounded-xl px-4 py-3 mt-2">
      <div class="flex items-baseline gap-2 mb-2">
        <span class="text-sm font-semibold text-fg">Almacenamiento de buzones</span>
        <span class="text-xs text-fg-muted">${gb(usado)} de ${gb(total)}</span>
        <span class="ml-auto text-xs ${apretado ? "text-amber-600 font-semibold" : "text-fg-muted"}">${pct}%</span>
      </div>
      <div class="h-2 rounded-full bg-bg-inset overflow-hidden">
        <div class="h-full ${color} rounded-full transition-all" style="width:${Math.max(pct, 1)}%"></div>
      </div>
      <p class="text-xs text-fg-muted mt-2">
        ${apretado
          ? "Te queda poco espacio. Agrega un bloque de +50 GB por $99 al mes para no dejar de recibir."
          : "Lo comparten todos los buzones del dominio. Borrar en la Bandeja no lo libera: para que baje hay que borrar en el buzón y vaciar su Papelera."}
      </p>
    </div>`;
}

// Banda de activación bajo la cabecera del dominio: gratis, sin activar, o activado.
function renderActivacion() {
  const el = document.getElementById("detail-activation");
  if (!el || !selectedDomain) return;
  const r = derechosDe(selectedDomain.id);
  const btn = (label, primario = true) => `<button data-action="open-addons" data-domain-id="${esc(selectedDomain.id)}" class="${primario ? "bg-accent hover:bg-accent/90 text-white" : "bg-bg-inset hover:bg-line text-fg"} text-sm font-semibold px-4 py-2 rounded-lg transition-colors whitespace-nowrap">${label}</button>`;
  if (r.activado) {
    el.innerHTML = `
      <div class="flex flex-wrap items-center gap-3 bg-bg-elev border border-line rounded-xl px-4 py-3">
        <span class="text-sm text-accent-text font-semibold">Dominio activado</span>
        <span class="text-xs text-fg-muted">personas ilimitadas · buzones IMAP · ${r.sends} correos nuevos al día · ${Math.round((r.mailboxBytes ?? 0) / GB)} GB</span>
        <span class="ml-auto">${btn("+50 GB · +100 envíos", false)}</span>
      </div>
      ${barraAlmacenamiento(r)}`;
  } else if (r.bloqueado) {
    el.innerHTML = `
      <div class="flex flex-wrap items-center gap-3 bg-amber-500/15 border border-amber-500/30 rounded-xl px-4 py-3">
        <span class="text-sm text-amber-600 font-semibold">Este dominio guarda el correo pero no lo reenvía</span>
        <span class="text-xs text-fg-muted">Tu primer dominio es gratis; los demás se activan por $99 al mes.</span>
        <span class="ml-auto">${btn("Activar dominio · $99/mes")}</span>
      </div>`;
  } else {
    el.innerHTML = `
      <div class="flex flex-wrap items-center gap-3 bg-bg-elev border border-line rounded-xl px-4 py-3">
        <span class="text-sm text-fg font-semibold">Dominio gratis</span>
        <span class="text-xs text-fg-muted">${r.aliases} máscaras · la Bandeja muestra 7 días · sin correo nuevo ni equipo</span>
        <span class="ml-auto">${btn("Activar · $99/mes")}</span>
      </div>`;
  }
}

function goBack() {
  selectedDomain = null;
  document.getElementById("domain-detail").classList.add("hidden");
  document.getElementById("domains-list").classList.remove("hidden");
  document.getElementById("domains-header")?.classList.remove("hidden");
  document.getElementById("home-aside")?.classList.remove("hidden");
  document.getElementById("home-hello")?.classList.remove("hidden");
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

  resultEl.innerHTML = `<p class="text-sm text-fg-muted">Buscando disponibilidad...</p>`;
  resultEl.classList.remove("hidden");

  try {
    const res = await fetch(`/api/domains/search?q=${encodeURIComponent(q)}`);
    const data = await res.json();

    if (!res.ok) {
      // API error — could be unsupported TLD or other
      resultEl.innerHTML = `
        <div class="bg-bg-inset border border-line rounded-lg p-4">
          <p class="text-sm text-fg mb-3">${esc(data.error || `Extensión no disponible para compra`)}</p>
          <button type="button" id="btn-connect-existing" class="w-full bg-accent hover:bg-accent/90 text-white text-sm font-semibold px-4 py-2.5 rounded-lg transition-colors">
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
        <div class="bg-mask-500/10 border border-accent/30 rounded-lg p-4">
          <div class="flex items-center justify-between mb-3">
            <div>
              <span class="font-semibold text-accent-text">${esc(data.domain)}</span>
              <span class="text-xs text-green-500 ml-2">Disponible</span>
              <div class="text-xs text-fg-muted mt-0.5">${priceStr} MXN/año</div>
            </div>
          </div>
          <button type="button" id="btn-buy-domain" class="w-full bg-green-600 hover:bg-green-700 text-white text-sm font-semibold px-4 py-2.5 rounded-lg transition-colors mb-2">
            Comprar dominio
          </button>
          <div class="flex items-center gap-3 my-3">
            <div class="flex-1 border-t border-line"></div>
            <span class="text-xs text-fg-subtle">o</span>
            <div class="flex-1 border-t border-line"></div>
          </div>
          <button type="button" id="btn-connect-existing" class="w-full bg-bg-inset hover:bg-line text-fg text-sm font-semibold px-4 py-2.5 rounded-lg transition-colors">
            Ya tengo este dominio →
          </button>
        </div>`;
      resultEl.querySelector("#btn-buy-domain").addEventListener("click", () => registerDomainAction(data.domain));
      resultEl.querySelector("#btn-connect-existing").addEventListener("click", () => connectExistingDomain(q));
    } else {
      resultEl.innerHTML = `
        <div class="bg-bg-inset border border-line rounded-lg px-4 py-4">
          <p class="text-sm text-fg mb-1"><span class="font-semibold">${esc(data.domain)}</span> ya está registrado</p>
          <p class="text-xs text-fg-subtle mb-4">Si es tuyo, conéctalo para usarlo con MailMask.</p>
          <button type="button" id="btn-connect-existing" class="w-full bg-accent hover:bg-accent/90 text-white text-sm font-semibold px-4 py-2.5 rounded-lg transition-colors mb-2">
            Ya es mío, conectarlo →
          </button>
          <button type="button" id="btn-search-another" class="w-full bg-bg-inset hover:bg-line text-fg text-sm font-semibold px-4 py-2.5 rounded-lg transition-colors mb-2">
            Buscar otro dominio
          </button>
          <button type="button" id="btn-transferir" class="w-full bg-bg-inset hover:bg-line text-fg text-sm font-semibold px-4 py-2.5 rounded-lg transition-colors">
            Transferir dominio a MailMask
          </button>
        </div>`;
      resultEl.querySelector("#btn-connect-existing").addEventListener("click", () => connectExistingDomain(q));
      resultEl.querySelector("#btn-transferir").addEventListener("click", () => iniciarTransferencia(q));
      resultEl.querySelector("#btn-search-another").addEventListener("click", () => {
        resultEl.classList.add("hidden");
        input.value = "";
        input.focus();
        renderTldGrid("");
      });
    }
    playSound("pop");
  } catch {
    resultEl.innerHTML = `<p class="text-sm text-red-500">Error de conexión</p>`;
  }
}

// --- Transferencia entrante ---
//
// Cuatro pasos: requisitos, código y pago, espera, y revisión del DNS. El orden importa:
// los requisitos se comprueban ANTES de cobrar, y nada se mueve hasta que el cliente
// aprueba el inventario de su DNS actual.

async function iniciarTransferencia(dominio) {
  const dlg = document.createElement("div");
  dlg.className = "fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 overflow-y-auto";
  dlg.innerHTML = `
    <div class="bg-bg-elev border border-line rounded-xl w-full max-w-lg p-5 my-8">
      <h3 class="font-semibold text-fg mb-1">Transferir ${esc(dominio)}</h3>
      <p class="text-sm text-fg-muted mb-4">Comprobando si tu registrador lo permite…</p>
      <div id="transf-cuerpo"></div>
      <div class="flex justify-end gap-2 mt-5">
        <button type="button" data-action="cerrar" class="text-sm text-fg-muted hover:text-fg px-3 py-2">Cerrar</button>
      </div>
    </div>`;
  document.body.appendChild(dlg);
  dlg.querySelector('[data-action="cerrar"]').addEventListener("click", () => dlg.remove());
  dlg.addEventListener("click", (e) => { if (e.target === dlg) dlg.remove(); });

  const cuerpo = dlg.querySelector("#transf-cuerpo");
  const res = await fetch("/api/domains/transfer/check", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ domain: dominio }),
  });
  const data = await res.json();
  if (!res.ok) {
    cuerpo.innerHTML = `<p class="text-sm text-red-500">${esc(data.error || "No pudimos comprobarlo.")}</p>`;
    return;
  }

  const marca = (ok) => ok === true
    ? `<span class="text-accent-text">✓</span>`
    : ok === false
      ? `<span class="text-red-500">✗</span>`
      : `<span class="text-amber-600">?</span>`;

  const bloqueado = data.requisitos.some(r => r.ok === false);

  cuerpo.innerHTML = `
    <ul class="space-y-2 mb-4">
      ${data.requisitos.map(r => `
        <li class="text-sm">
          <div class="flex gap-2"><span class="w-4 shrink-0">${marca(r.ok)}</span><span class="text-fg">${esc(r.texto)}</span></div>
          ${r.ayuda ? `<p class="text-xs text-fg-subtle ml-6 mt-0.5">${esc(r.ayuda)}</p>` : ""}
        </li>`).join("")}
    </ul>
    <div class="border border-line rounded-lg p-3 mb-4">
      <p class="text-sm text-fg mb-1">Encontramos <strong>${data.dns.found.length}</strong> registro(s) en tu DNS actual.</p>
      <p class="text-xs text-fg-subtle">Los copiamos para que tu sitio no se caiga. Podrás revisarlos y corregirlos antes de que el dominio se mueva.</p>
    </div>
    ${bloqueado ? `<p class="text-sm text-amber-600 mb-3">Arregla lo marcado con ✗ en tu registrador actual y vuelve a intentarlo.</p>` : `
      <label class="block text-xs text-fg-muted mb-1">Código de autorización (EPP)</label>
      <input id="transf-code" placeholder="Lo pides en tu registrador actual" class="w-full bg-bg-inset border border-line rounded-lg px-3 py-2 text-sm text-fg font-mono mb-4">
      <p class="text-xs text-fg-muted mb-2">Tus datos para el WHOIS. El dominio queda <strong>a tu nombre</strong>, no al nuestro, y el registro exige que sean reales.</p>
      <div class="grid grid-cols-2 gap-2 mb-3">
        ${[
          ["firstName", "Nombre", "text"],
          ["lastName", "Apellido", "text"],
          ["email", "Correo", "email"],
          ["phone", "Teléfono (+52 55 1234 5678)", "tel"],
          ["address", "Calle y número", "text"],
          ["city", "Ciudad", "text"],
          ["state", "Estado (ej. Ciudad de México)", "text"],
          ["zip", "Código postal", "text"],
          ["country", "País (MX)", "text"],
          ["organization", "Empresa (opcional)", "text"],
        ].map(([campo, etiqueta, tipo]) => `
          <input data-whois="${campo}" type="${tipo}" placeholder="${etiqueta}" class="bg-bg-inset border border-line rounded-lg px-3 py-2 text-sm text-fg">`).join("")}
      </div>
      <p id="transf-error" class="text-sm text-red-500 mb-2 hidden"></p>
      <button type="button" id="transf-pagar" class="w-full bg-accent hover:bg-accent/90 text-white text-sm font-semibold px-4 py-2.5 rounded-lg transition-colors">
        Transferir por $${(data.price / 100).toFixed(0)} MXN · incluye 1 año
      </button>
      <p class="text-xs text-fg-subtle mt-2">Tarda de 5 a 7 días. Tu registrador te mandará un correo de aprobación que tienes que contestar.</p>`}`;

  if (bloqueado) return;

  dlg.querySelector("#transf-pagar").addEventListener("click", async () => {
    const code = dlg.querySelector("#transf-code").value.trim();
    const err = dlg.querySelector("#transf-error");
    if (!code) {
      err.textContent = "Falta el código de autorización.";
      err.classList.remove("hidden");
      return;
    }
    const whois = {};
    dlg.querySelectorAll("[data-whois]").forEach((i) => { whois[i.dataset.whois] = i.value.trim(); });

    const r = await fetch("/api/domains/transfer/start", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ domain: dominio, authCode: code, dnsRecords: data.dns.found, whois }),
    });
    const j = await r.json();
    if (!r.ok) {
      err.textContent = j.error || "No se pudo iniciar la transferencia.";
      err.classList.remove("hidden");
      return;
    }
    window.location.href = j.initPoint;
  });
}

async function connectExistingDomain(domain) {
  const resultEl = document.getElementById("add-domain-step-result");
  resultEl.innerHTML = `<p class="text-sm text-fg-muted">Agregando dominio...</p>`;

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
      resultEl.innerHTML = `<p class="text-sm text-red-500">${esc(data.error || "Error al agregar dominio")}</p>`;
    }
  } catch {
    resultEl.innerHTML = `<p class="text-sm text-red-500">Error de conexión</p>`;
  }
}

async function registerDomainAction(domain) {
  const resultEl = document.getElementById("add-domain-step-result");
  resultEl.innerHTML = `<p class="text-sm text-fg-muted">Creando pago...</p>`;

  try {
    const res = await fetch("/api/domains/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ domain }),
    });
    const data = await res.json();
    if (!res.ok) {
      resultEl.innerHTML = `<p class="text-sm text-red-500">${esc(data.error)}</p>`;
      return;
    }
    // Redirect to MercadoPago
    window.location.href = data.initPoint;
  } catch {
    resultEl.innerHTML = `<p class="text-sm text-red-500">Error de conexión</p>`;
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
        paid: { label: "Pagado — esperando registro", color: "text-amber-600", dot: "bg-yellow-400", animate: true },
        registering: { label: "Registrando dominio...", color: "text-blue-400", dot: "bg-blue-400", animate: true },
        failed: { label: "Error: " + (r.lastError || "fallo desconocido"), color: "text-red-500", dot: "bg-red-400", animate: false },
        transfer_pending_payment: { label: "Transferencia: esperando pago", color: "text-fg-muted", dot: "bg-fg-muted", animate: false },
        transfer_paid: { label: "Pagada — falta tu código EPP", color: "text-amber-600", dot: "bg-yellow-400", animate: false },
        transfer_submitted: { label: "Transferencia enviada — revisa tu correo", color: "text-blue-400", dot: "bg-blue-400", animate: true },
        transfer_awaiting_approval: { label: "Esperando que apruebes en tu registrador", color: "text-blue-400", dot: "bg-blue-400", animate: true },
        transfer_failed: { label: "La transferencia falló", color: "text-red-500", dot: "bg-red-400", animate: false },
        transfer_cancelled: { label: "Transferencia cancelada", color: "text-fg-muted", dot: "bg-fg-muted", animate: false },
      };
      const s = statusMap[r.status] || { label: r.status, color: "text-fg-muted", dot: "bg-fg-muted", animate: false };
      return `
      <div class="bg-bg-elev border border-line rounded-xl px-5 py-3">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <span class="w-2 h-2 rounded-full ${s.dot} ${s.animate ? 'animate-pulse' : ''}"></span>
            <span class="font-semibold text-sm">${esc(r.domainName)}</span>
          </div>
          <span class="text-xs ${s.color}">${s.label}</span>
        </div>
        ${r.status === "transfer_paid" ? `
        <div class="mt-3 flex flex-col sm:flex-row gap-2" data-epp-form="${esc(r.id)}">
          <input type="text" autocomplete="off" spellcheck="false" placeholder="Pega aquí tu código EPP" class="flex-1 bg-bg-inset border border-line rounded-lg px-3 py-2 text-sm text-fg font-mono">
          <button class="btn-primary text-sm px-4 py-2 rounded-lg">Mandar transferencia</button>
        </div>
        <p class="text-xs text-red-500 mt-2 hidden" data-epp-error></p>` : ""}
      </div>`;
    }).join("");

    container.querySelectorAll("[data-epp-form]").forEach((form) => {
      const input = form.querySelector("input");
      const button = form.querySelector("button");
      const error = form.parentElement.querySelector("[data-epp-error]");
      button.addEventListener("click", async () => {
        const authCode = input.value.trim();
        if (!authCode) return;
        button.disabled = true;
        const r = await fetch(`/api/domains/transfer/${form.dataset.eppForm}/auth-code`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ authCode }),
        });
        const j = await r.json().catch(() => ({}));
        button.disabled = false;
        if (!r.ok) {
          error.textContent = j.error || "No se pudo mandar la transferencia.";
          error.classList.remove("hidden");
          return;
        }
        loadDomainRegistrations();
      });
    });

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

let aliasesActuales = [];

function renderAliases(aliases) {
  aliasesActuales = aliases;
  const list = document.getElementById("aliases-list");
  const empty = document.getElementById("aliases-empty");

  if (aliases.length === 0) {
    list.innerHTML = "";
    empty.classList.remove("hidden");
    return;
  }

  empty.classList.add("hidden");
  list.innerHTML = aliases.map(a => `
    <div class="bg-bg-inset border border-line rounded-lg px-4 sm:px-5 py-4 flex flex-col sm:flex-row sm:items-center gap-3 sm:justify-between">
      <div class="min-w-0">
        <div class="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span class="font-mono text-sm break-all ${a.enabled ? 'text-fg' : 'text-fg-subtle line-through'}">${a.alias === '*' ? '*' : esc(a.alias)}@${esc(selectedDomain.domain)}</span>
          ${a.destinations.length ? `<span class="text-fg-subtle">→</span>` : ''}
          ${a.destinations.map(d => `<span class="text-sm text-fg bg-bg-inset border border-line rounded-md px-2 py-0.5 break-all">${esc(d)}</span>`).join("")}
          ${a.mailboxEnabled ? `<span class="text-xs text-accent-text bg-accent/10 border border-accent/30 rounded-md px-2 py-0.5" title="El correo se guarda aquí y se lee con IMAP">Buzón${a.mailboxGraceUntil ? ' · sólo lectura' : ''}</span>` : ''}
        </div>
        ${a.forwardCount ? `<div class="text-xs text-fg-subtle mt-1">${a.forwardCount} reenviado${a.forwardCount === 1 ? '' : 's'}${a.lastFrom ? ` · último de ${esc(a.lastFrom)}` : ''}${a.lastAt ? ` · ${relativeTime(a.lastAt)}` : ''}</div>` : ''}
      </div>
      <div class="flex items-center gap-3 sm:gap-2 shrink-0">
        <button data-action="copy-alias" data-value="${a.alias === '*' ? '' : esc(a.alias) + '@' + esc(selectedDomain.domain)}" class="text-xs text-fg-subtle hover:text-fg transition-colors${a.alias === '*' ? ' hidden' : ''}" title="Copiar la dirección para compartirla">Copiar</button>
        <button data-action="edit-alias" data-alias="${esc(a.alias)}" data-destinations="${esc(a.destinations.join(', '))}" class="text-xs text-fg-subtle hover:text-fg transition-colors">Editar</button>
        <button data-action="mailbox-alias" data-alias="${esc(a.alias)}" data-has="${a.mailboxEnabled ? '1' : ''}" class="text-xs text-fg-subtle hover:text-fg transition-colors${a.alias === '*' ? ' hidden' : ''}" title="Buzón IMAP para leer en Apple Mail u Outlook">${a.mailboxEnabled ? 'Buzón' : 'Crear buzón'}</button>
        <button data-action="toggle-alias" data-alias="${esc(a.alias)}" data-enabled="${!a.enabled}" class="text-xs px-2 py-1 rounded ${a.enabled ? 'bg-accent/10 text-accent-text' : 'bg-line text-fg-muted'}">${a.enabled ? 'Activo' : 'Inactivo'}</button>
        <button data-action="remove-alias" data-alias="${esc(a.alias)}" class="text-xs text-fg-subtle hover:text-red-500 transition-colors">Eliminar</button>
      </div>
    </div>
  `).join("");
}

// --- Buzón IMAP ---
//
// La contraseña se muestra UNA sola vez y no se guarda en ningún lado: la entrega del
// correo va con la credencial de administrador del servidor, así que la del buzón no
// vuelve a hacer falta. Si se pierde, se genera otra.
async function abrirBuzon(alias, yaTiene) {
  const caja = document.getElementById("mailbox-body");
  const direccion = `${alias}@${selectedDomain.domain}`;
  document.getElementById("mailbox-title").textContent = direccion;
  caja.innerHTML = `<p class="text-sm text-fg-muted">Un momento…</p>`;
  showModal("modal-mailbox");

  if (yaTiene) {
    caja.innerHTML = `
      <p class="text-sm text-fg-muted">Este buzón ya existe. Configúralo en tu app de correo:</p>
      ${datosServidor(direccion)}
      <div class="flex flex-wrap gap-2 mt-5">
        <a href="/api/domains/${selectedDomain.id}/apple-profile?alias=${encodeURIComponent(alias)}" class="text-xs px-3 py-2 rounded bg-bg-inset text-fg hover:bg-line">Perfil para Apple Mail</a>
        <a href="/api/domains/${selectedDomain.id}/alias/${encodeURIComponent(alias)}/mailbox/export" class="text-xs px-3 py-2 rounded bg-bg-inset text-fg hover:bg-line">Descargar todo (.mbox)</a>
        <button type="button" data-mailbox="password" class="text-xs px-3 py-2 rounded bg-bg-inset text-fg hover:bg-line">Nueva contraseña</button>
        <button type="button" data-mailbox="delete" class="text-xs px-3 py-2 rounded text-red-500 hover:bg-red-950/40">Eliminar buzón</button>
      </div>`;
    return;
  }

  const res = await fetch(`/api/domains/${selectedDomain.id}/alias/${encodeURIComponent(alias)}/mailbox`, {
    method: "POST",
  });
  const data = await res.json();
  if (!res.ok) {
    caja.innerHTML = `<p class="text-sm text-red-500">${esc(data.error || "No se pudo crear el buzón")}</p>`;
    return;
  }
  playSound("success");
  caja.innerHTML = credencialesNuevas(data, alias);
  loadAliases();
}

// Botón de copiar con icono: el texto "Copiar" tres veces en un modal chico estorba,
// y al copiar el icono cambia a palomita 1.5 s (el sonido ya avisa).
function botonCopiar(valor, titulo) {
  return `<button type="button" data-mailbox="copy" data-value="${esc(valor)}" title="${esc(titulo)}" aria-label="${esc(titulo)}" class="shrink-0 p-1.5 rounded text-fg-subtle hover:text-fg hover:bg-line">
    <svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/></svg>
  </button>`;
}

function datosServidor(direccion) {
  const fila = (k, v, copia, titulo) => `
      <dt class="text-fg-subtle self-center">${k}</dt>
      <dd class="flex items-center gap-1 min-w-0"><span class="font-mono text-fg break-all">${v}</span>${botonCopiar(copia, titulo)}</dd>`;
  return `
    <dl class="mt-4 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
      ${fila("Usuario", esc(direccion), direccion, "Copiar usuario")}
      ${fila("Entrada (IMAP)", "imap.mailmask.studio · 993 · SSL/TLS", "imap.mailmask.studio", "Copiar servidor IMAP")}
      ${fila("Salida (SMTP)", "imap.mailmask.studio · 465 · SSL/TLS", "imap.mailmask.studio", "Copiar servidor SMTP")}
    </dl>`;
}

function credencialesNuevas(data, alias) {
  return `
    <p class="text-sm text-fg">Listo. <strong class="text-amber-400">Copia la contraseña ahora</strong>: no se guarda en ningún lado y no la volverás a ver.</p>
    <div class="mt-3 flex items-center gap-2">
      <code class="flex-1 font-mono text-sm bg-bg border border-line rounded px-3 py-2 break-all">${esc(data.password)}</code>
      ${botonCopiar(data.password, "Copiar contraseña")}
    </div>
    ${datosServidor(data.email)}
    <a href="/api/domains/${selectedDomain.id}/apple-profile?alias=${encodeURIComponent(alias)}" class="inline-block mt-4 text-xs px-3 py-2 rounded bg-bg-inset text-fg hover:bg-line">Perfil para Apple Mail</a>`;
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
    <div class="bg-bg-inset border border-line rounded-lg px-5 py-4 flex items-center justify-between">
      <div class="text-sm">
        <span class="text-fg-muted">Si</span>
        <span class="text-fg font-semibold">${fieldLabels[r.field]}</span>
        <span class="text-fg-muted">${matchLabels[r.match]}</span>
        <span class="text-red-500 font-mono">"${esc(r.value)}"</span>
        <span class="text-fg-muted mx-1">→</span>
        <span class="text-fg">${actionLabels[r.action]}</span>
        ${r.target ? `<span class="text-fg-muted ml-1">${esc(r.target)}</span>` : ''}
      </div>
      <button data-action="remove-rule" data-rule-id="${esc(r.id)}" class="text-xs text-fg-subtle hover:text-red-500 transition-colors">Eliminar</button>
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

  const limit = derechosDe(selectedDomain?.id).agentes === 0 ? 0 : Infinity;

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
  const { members, invites } = await res.json();
  renderMembers(members, invites);
}

const ROLE_LABELS = { admin: "Admin", agent: "Miembro" };

function roleChip(role) {
  return `<span class="text-xs ml-2 px-2 py-0.5 rounded ${role === 'admin' ? 'bg-accent/15 text-accent-text' : 'bg-line text-fg-muted'}">${ROLE_LABELS[role] ?? role}</span>`;
}

function renderMembers(members, invites = []) {
  const list = document.getElementById("members-list");
  const empty = document.getElementById("members-empty");

  if (members.length === 0 && invites.length === 0) {
    list.innerHTML = "";
    empty.classList.remove("hidden");
    return;
  }

  empty.classList.add("hidden");
  const fmtDate = (iso) => new Date(iso).toLocaleDateString("es-MX", { day: "numeric", month: "short" });
  list.innerHTML = `
    ${members.length ? `<p class="text-xs text-fg-subtle mb-2">${members.length} ${members.length === 1 ? "miembro" : "miembros"}</p>` : ""}
    ${members.map(m => `
      <div class="bg-bg-inset border border-line rounded-lg px-5 py-4 flex items-center justify-between">
        <div>
          <span class="text-sm text-fg">${esc(m.name)}</span>
          <span class="text-sm text-fg-subtle ml-2">${esc(m.email)}</span>
          ${roleChip(m.role)}
        </div>
        <button data-action="remove-member" data-agent-id="${esc(m.id)}" data-agent-name="${esc(m.name)}" class="text-xs text-fg-subtle hover:text-red-500 transition-colors">Eliminar</button>
      </div>
    `).join("")}
    ${invites.length ? `<p class="text-xs text-fg-subtle mt-4 mb-2">Invitaciones pendientes</p>` : ""}
    ${invites.map(i => `
      <div class="bg-bg-inset border border-dashed border-line rounded-lg px-5 py-4 flex items-center justify-between gap-3">
        <div class="min-w-0">
          <span class="text-xs px-2 py-0.5 rounded bg-amber-500/15 text-amber-600 mr-2">Pendiente · aún no acepta</span>
          <span class="text-sm text-fg">${esc(i.name)}</span>
          <span class="text-sm text-fg-subtle ml-2">${esc(i.email)}</span>
          <span class="text-xs text-fg-subtle ml-2">será ${(ROLE_LABELS[i.role] ?? i.role).toLowerCase()} · el enlace vence el ${fmtDate(i.expiresAt)}</span>
        </div>
        <div class="flex items-center gap-3 shrink-0 text-xs">
          <button data-action="copy-invite" data-url="${esc(i.inviteUrl)}" class="text-fg-muted hover:text-fg transition-colors">Copiar enlace</button>
          <button data-action="resend-invite" data-name="${esc(i.name)}" data-email="${esc(i.email)}" data-role="${esc(i.role)}" class="text-fg-muted hover:text-fg transition-colors">Reenviar</button>
          <button data-action="cancel-invite" data-token="${esc(i.token)}" class="text-fg-subtle hover:text-red-500 transition-colors">Cancelar</button>
        </div>
      </div>
    `).join("")}`;
}

async function cancelInvite(token) {
  const res = await fetch(`/api/domains/${selectedDomain.id}/agents/invites/${token}`, { method: "DELETE" });
  if (res.ok) {
    showToast("Invitación cancelada");
    await loadMembers();
  } else {
    const data = await res.json().catch(() => ({}));
    showToast(data.error || "Error al cancelar", true);
  }
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
    showToast("Invitación enviada · el enlace también se puede copiar abajo");
    await loadMembers();
  } else {
    const data = await res.json();
    showToast(data.error || "Error al invitar miembro", true);
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

let logsFilter = "all";
let lastLogs = [];
const OUTBOUND_STATUSES = new Set(["sent", "delivered", "bounced", "complained"]);

async function loadLogs() {
  if (!selectedDomain) return;
  const res = await fetch(`/api/domains/${selectedDomain.id}/logs?limit=100`);
  if (!res.ok) return;
  lastLogs = await res.json();
  renderLogs(applyLogsFilter(lastLogs));
  loadSuppressions();
}

function applyLogsFilter(logs) {
  if (logsFilter === "in") return logs.filter(l => !OUTBOUND_STATUSES.has(l.status));
  if (logsFilter === "out") return logs.filter(l => OUTBOUND_STATUSES.has(l.status));
  return logs;
}

document.getElementById("logs-filter")?.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-filter]");
  if (!btn) return;
  logsFilter = btn.dataset.filter;
  document.querySelectorAll("#logs-filter [data-filter]").forEach(b => {
    const on = b === btn;
    b.classList.toggle("bg-bg-inset", on);
    b.classList.toggle("text-fg", on);
    b.classList.toggle("text-fg-subtle", !on);
  });
  playSound("click");
  renderLogs(applyLogsFilter(lastLogs));
});

// --- Lista de supresión ---

async function loadSuppressions() {
  const list = document.getElementById("suppression-list");
  const empty = document.getElementById("suppression-empty");
  if (!list || !selectedDomain) return;
  const res = await fetch(`/api/domains/${selectedDomain.id}/suppressions`);
  if (!res.ok) return;
  const rows = await res.json();
  if (!rows.length) { list.innerHTML = ""; empty.classList.remove("hidden"); return; }
  empty.classList.add("hidden");
  const reasonLabel = { complaint: "marcó spam", manual: "bloqueado a mano" };
  list.innerHTML = rows.map(r => `
    <div class="flex items-center gap-3 text-xs bg-bg-inset border border-line rounded-md px-3 py-1.5">
      <code class="font-mono text-fg truncate">${esc(r.email)}</code>
      <span class="text-fg-subtle">${esc(reasonLabel[r.reason] || (r.reason.startsWith("bounce") ? "rebote permanente" : r.reason))}</span>
      <span class="text-fg-subtle ml-auto whitespace-nowrap">${relativeTime(r.createdAt)}</span>
      <button data-unsuppress="${esc(r.email)}" class="text-fg-muted hover:text-fg transition-colors">Quitar</button>
    </div>`).join("");
  list.querySelectorAll("[data-unsuppress]").forEach(btn => btn.addEventListener("click", async () => {
    const r = await fetch(`/api/domains/${selectedDomain.id}/suppressions/${encodeURIComponent(btn.dataset.unsuppress)}`, { method: "DELETE" });
    if (r.ok) { playSound("delete"); showToast("Dirección liberada"); loadSuppressions(); }
    else showToast("No se pudo quitar", true);
  }));
}

document.getElementById("suppression-form")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const input = document.getElementById("suppression-email");
  const email = input.value.trim();
  if (!email || !selectedDomain) return;
  const r = await fetch(`/api/domains/${selectedDomain.id}/suppressions`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email }),
  });
  if (r.ok) { playSound("success"); input.value = ""; loadSuppressions(); }
  else showToast((await r.json().catch(() => ({}))).error || "No se pudo bloquear", true);
});

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
    forwarded: "text-accent-text",
    discarded: "text-fg-subtle",
    failed: "text-red-500",
    rule_matched: "text-amber-600",
    sent: "text-fg-muted",
    delivered: "text-accent-text",
    bounced: "text-red-500",
    complained: "text-red-500",
  };
  const statusIcons = {
    forwarded: "✓ reenviado",
    discarded: "— descartado",
    failed: "✗ falló",
    rule_matched: "⚡ regla",
    sent: "⏱ enviado",
    delivered: "✓ entregado",
    bounced: "✗ rebotó",
    complained: "⚠ spam",
  };

  const rows = logs.map(l => {
    const date = new Date(l.timestamp);
    const time = date.toLocaleString("es-MX", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
    return `
      <tr class="border-b border-line">
        <td class="py-2 pr-3 text-fg-subtle whitespace-nowrap">${time}</td>
        <td class="py-2 pr-3 text-fg truncate max-w-[200px]" title="${esc(l.from)}">${esc(l.from)}</td>
        <td class="py-2 pr-3 text-fg-muted truncate max-w-[200px]" title="${esc(l.subject)}">${esc(l.subject)}</td>
        <td class="py-2 pr-3 text-fg-subtle truncate max-w-[120px]">${l.forwardedTo ? esc(l.forwardedTo) : '—'}</td>
        <td class="py-2 whitespace-nowrap ${statusColors[l.status] || "text-fg-muted"}"${l.error ? ` title="${esc(l.error)}"` : ""}>${statusIcons[l.status] || esc(l.status)}</td>
      </tr>`;
  }).join("");

  list.innerHTML = `
    <thead>
      <tr class="border-b border-line text-fg-subtle">
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
  statusEl.className = "text-xs px-2 py-1 rounded-full bg-bg-inset text-fg-muted animate-pulse";

  try {
    const res = await fetch(`/api/domains/${selectedDomain.id}/health`);
    if (!res.ok) return;
    const health = await res.json();
    selectedDomain._health = health;

    const badgeStyles = {
      ok: "bg-mask-500/15 text-accent-text",
      warning: "bg-amber-500/15 text-amber-600",
      error: "bg-red-500/10 text-red-600",
    };
    const badgeLabels = { ok: "Saludable", warning: "Atención", error: "Error" };
    statusEl.textContent = badgeLabels[health.status] || health.status;
    statusEl.className = `text-xs px-2 py-1 rounded-full ${badgeStyles[health.status] || badgeStyles.error}`;

    renderHealthPanel();
  } catch {
    statusEl.textContent = selectedDomain.verified ? "Verificado" : "Pendiente DNS";
    statusEl.className = `text-xs px-2 py-1 rounded-full ${selectedDomain.verified ? 'bg-mask-500/15 text-accent-text' : 'bg-amber-500/15 text-amber-600'}`;
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

  const iconOk = `<svg class="w-4 h-4 text-accent-text shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>`;
  const iconWarn = `<svg class="w-4 h-4 text-amber-600 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`;
  const iconErr = `<svg class="w-4 h-4 text-red-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>`;

  const summaryBg = { ok: "border-accent/30 bg-mask-500/10", warning: "border-amber-500/30 bg-amber-500/15", error: "border-red-500/30 bg-red-500/10" };
  const summaryText = { ok: "text-accent-text", warning: "text-amber-600", error: "text-red-500" };

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
              <span class="text-xs font-medium text-fg">${checkLabels[key]}</span>
              <span class="text-xs text-fg-subtle ml-1">— ${esc(c.detail)}</span>
            </div>
          </div>`;
        }).join("")}
      </div>
      <button id="btn-refresh-health" class="mt-3 text-xs text-fg-subtle hover:text-fg transition-colors">Actualizar diagnóstico</button>
    </div>`;
  document.getElementById("btn-refresh-health")?.addEventListener("click", loadDomainHealth);
}

// --- DNS ---

// Los registros que hay que copiar a mano en el proveedor del cliente. No desaparece con
// el editor: hay quien no va a delegar nunca su DNS con nosotros, y está bien.
function renderDnsRecords(contenedor) {
  if (!selectedDomain) return;
  const records = contenedor || document.getElementById("dns-records");

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
      level: "recomendado",
      benefit: "Algunos receptores revisan SPF además de DKIM. Con este registro, tus correos llegan a más bandejas y menos a spam.",
      hints: [
        `Este registro <strong>SPF</strong> autoriza a Amazon SES a enviar emails en nombre de tu dominio.`,
        `Si ya tienes un registro SPF, agrega <strong>include:amazonses.com</strong> antes del <strong>~all</strong> existente en vez de crear uno nuevo.`,
      ],
    },
    {
      type: "TXT",
      name: "_dmarc",
      value: `v=DMARC1; p=none; rua=mailto:dmarc@${d}`,
      level: "opcional",
      benefit: "Gmail y Yahoo tratan mejor a los dominios con política DMARC, y te llegan reportes de quién envía en tu nombre. Tu firma DKIM ya cumple, así que se activa sin riesgo.",
      hints: [
        `<strong>p=none</strong> solo observa: nada se bloquea. Cuando veas que todo pasa, súbelo a <strong>p=quarantine</strong> para que los receptores rechacen a quien se haga pasar por ti.`,
        `Los reportes llegan a <strong>dmarc@${esc(d)}</strong>. Crea ese alias en MailMask, o cambia la dirección por otra tuya.`,
      ],
    },
  ];

  const sharedDkimHint = `Los 3 registros CNAME son para <strong>DKIM</strong> — la firma digital que evita que tus emails caigan en spam.`;
  if (dnsItems.length > 2) dnsItems[2].hints.unshift(sharedDkimHint);

  const copyBtn = (val) => `<button data-action="copy" data-copy-value="${esc(val)}" class="text-fg-subtle hover:text-white transition-colors shrink-0 p-1 rounded hover:bg-line" title="Copiar"><svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg></button>`;

  const levelPill = (r) => r.level === "opcional"
    ? `<span class="text-[10px] uppercase tracking-widest font-semibold px-1.5 py-px rounded-full text-fg-muted border border-line">opcional</span>`
    : r.level === "recomendado"
      ? `<span class="text-[10px] uppercase tracking-widest font-semibold px-1.5 py-px rounded-full text-accent-text border border-accent/30">recomendado</span>`
      : "";

  // Una fila por registro: tipo · nombre · valor · copiar. En móvil nombre y valor se
  // apilan; la ayuda va plegada en <details> para que la tabla no mida dos pantallas.
  const cell = (label, val) => `
    <div class="min-w-0">
      <div class="sm:hidden text-[10px] uppercase tracking-widest text-fg-subtle mb-0.5">${label}</div>
      <div class="flex items-center gap-1 min-w-0">
        <code class="text-xs font-mono text-fg break-all select-all">${esc(val)}</code>
        ${copyBtn(val)}
      </div>
    </div>`;

  records.innerHTML = `
    <div class="hidden sm:grid grid-cols-[64px_minmax(0,1fr)_minmax(0,1.6fr)] gap-4 px-4 py-2 text-[10px] uppercase tracking-widest text-fg-subtle bg-bg-elev border-b border-line">
      <span>Tipo</span><span>Nombre</span><span>Valor</span>
    </div>
    <div class="divide-y divide-line">
      ${dnsItems.map(r => `
        <div class="px-4 py-3">
          <div class="grid grid-cols-1 sm:grid-cols-[64px_minmax(0,1fr)_minmax(0,1.6fr)] gap-2 sm:gap-4 sm:items-start">
            <div class="flex items-center gap-2 sm:block">
              <span class="inline-block font-mono font-bold text-xs text-fg bg-bg-inset px-2 py-0.5 rounded">${r.type}</span>
              <span class="sm:hidden">${levelPill(r)}</span>
            </div>
            ${cell("Nombre", r.name)}
            ${cell("Valor", r.value)}
          </div>
          <div class="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 sm:pl-[80px]">
            <span class="hidden sm:inline">${levelPill(r)}</span>
            ${r.benefit ? `<span class="text-xs text-fg-muted">${r.benefit}</span>` : ""}
            ${r.hints.length ? `
              <details class="text-xs">
                <summary class="cursor-pointer text-fg-subtle hover:text-fg select-none">Ayuda</summary>
                <ul class="mt-1.5 space-y-1 text-fg-subtle leading-relaxed list-disc pl-4">
                  ${r.hints.map(h => `<li>${h}</li>`).join("")}
                </ul>
              </details>` : ""}
          </div>
        </div>
      `).join("")}
    </div>`;
}

// --- Editor de DNS ---
//
// Tres estados: sin zona (el cliente elige delegar o configurar a mano), esperando la
// delegación (le enseñamos los nameservers y lo que copiamos), y activa (la tabla editable).

let _dnsEstado = null;
let _dnsTimer = null;

function dnsDetenerSondeo() {
  if (_dnsTimer) { clearInterval(_dnsTimer); _dnsTimer = null; }
}

async function loadDns() {
  dnsDetenerSondeo();
  const cont = document.getElementById("dns-records");
  if (!selectedDomain) return;
  cont.innerHTML = `<div class="px-4 py-6 text-sm text-fg-muted">Cargando…</div>`;

  try {
    const res = await fetch(`/api/domains/${selectedDomain.id}/dns`);
    if (!res.ok) throw new Error("no se pudo leer el DNS");
    _dnsEstado = await res.json();
  } catch {
    cont.innerHTML = `<div class="px-4 py-4 text-sm text-fg-muted">No pudimos leer el DNS. Mientras tanto, estos son los registros que hay que configurar:</div>`;
    const manual = document.createElement("div");
    cont.appendChild(manual);
    renderDnsRecords(manual);
    return;
  }

  const estado = _dnsEstado.zone.status;
  if (estado === "none") renderDnsSinZona(cont);
  else if (estado === "pending_delegation") renderDnsDelegacion(cont);
  else renderDnsTabla(cont);
}

function renderDnsSinZona(cont) {
  cont.innerHTML = `
    <div class="p-4 space-y-4">
      <div class="border border-line rounded-lg p-4 bg-bg-elev">
        <h4 class="font-semibold text-fg mb-1">Deja que MailMask lleve tu DNS</h4>
        <p class="text-sm text-fg-muted mb-3">
          Copiamos los registros que encontremos de tu proveedor actual y te damos los
          nameservers que hay que cambiar. Tu sitio sigue funcionando: sólo cambia quién
          responde las preguntas sobre <strong>${esc(selectedDomain.domain)}</strong>.
        </p>
        <button type="button" data-action="dns-crear-zona" class="bg-accent hover:bg-accent/90 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors">
          Activar el editor de DNS
        </button>
      </div>
      <details class="border border-line rounded-lg">
        <summary class="cursor-pointer select-none px-4 py-3 text-sm font-semibold text-fg">
          Prefiero configurarlo yo en mi proveedor
        </summary>
        <div id="dns-manual" class="border-t border-line"></div>
      </details>
    </div>`;
  renderDnsRecords(document.getElementById("dns-manual"));
  cont.querySelector('[data-action="dns-crear-zona"]').addEventListener("click", dnsCrearZona);
}

async function dnsCrearZona() {
  const btn = document.querySelector('[data-action="dns-crear-zona"]');
  btn.disabled = true;
  btn.textContent = "Preparando tu zona…";

  const res = await fetch(`/api/domains/${selectedDomain.id}/dns/zone`, { method: "POST" });
  const data = await res.json();
  if (!res.ok) {
    btn.disabled = false;
    btn.textContent = "Activar el editor de DNS";
    alert(data.error || "No se pudo crear la zona.");
    return;
  }
  playSound("success");
  loadDns();
}

function renderDnsDelegacion(cont) {
  const ns = _dnsEstado.zone.nameservers || [];
  cont.innerHTML = `
    <div class="p-4 space-y-4">
      <div class="border border-amber-500/30 bg-amber-500/10 rounded-lg p-4">
        <h4 class="font-semibold text-fg mb-1">Falta un paso en tu registrador</h4>
        <p class="text-sm text-fg-muted mb-3">
          Entra a donde compraste <strong>${esc(selectedDomain.domain)}</strong> y sustituye
          sus nameservers por estos. Hasta que lo hagas, lo que edites aquí no tiene efecto.
        </p>
        <div class="space-y-1">
          ${ns.map(n => `
            <div class="flex items-center gap-2">
              <code class="text-xs font-mono text-fg break-all select-all">${esc(n)}</code>
              <button type="button" data-action="copy" data-copy-value="${esc(n)}" class="text-fg-subtle hover:text-fg p-1 rounded hover:bg-line" title="Copiar">
                <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
              </button>
            </div>`).join("")}
        </div>
        <div class="mt-3 flex items-center gap-3">
          <button type="button" data-action="dns-comprobar" class="bg-bg-inset hover:bg-line text-fg text-sm font-semibold px-3 py-1.5 rounded-lg transition-colors">
            Ya los cambié
          </button>
          <span id="dns-delegacion-estado" class="text-xs text-fg-subtle"></span>
        </div>
      </div>
      <div>
        <p class="text-sm text-fg-muted mb-2">
          Esto es lo que hay en tu zona. Revísalo: <strong>lo que no esté aquí dejará de
          funcionar</strong> cuando cambies los nameservers.
        </p>
        <div class="border border-line rounded-lg overflow-hidden" id="dns-tabla"></div>
      </div>
    </div>`;

  renderDnsFilas(document.getElementById("dns-tabla"));
  cont.querySelector('[data-action="dns-comprobar"]').addEventListener("click", dnsComprobarDelegacion);
  // Mientras la pestaña esté a la vista, se pregunta solo.
  _dnsTimer = setInterval(dnsComprobarDelegacion, 60_000);
}

async function dnsComprobarDelegacion() {
  const el = document.getElementById("dns-delegacion-estado");
  if (!el) { dnsDetenerSondeo(); return; }
  el.textContent = "Comprobando…";

  const res = await fetch(`/api/domains/${selectedDomain.id}/dns/delegation`);
  const data = await res.json();
  if (data.delegated) {
    dnsDetenerSondeo();
    playSound("success");
    loadDns();
    return;
  }
  el.textContent = data.observed?.length
    ? `Todavía vemos ${data.observed[0]}. Los cambios de nameservers tardan de 1 a 48 horas.`
    : "Todavía no vemos el cambio. Puede tardar hasta 48 horas.";
}

function renderDnsTabla(cont) {
  cont.innerHTML = `
    <div class="p-4">
      <div class="flex items-center justify-between mb-3">
        <p class="text-sm text-fg-muted">MailMask lleva el DNS de este dominio.</p>
        <button type="button" data-action="dns-nuevo" class="bg-accent hover:bg-accent/90 text-white text-sm font-semibold px-3 py-1.5 rounded-lg transition-colors">
          + Añadir registro
        </button>
      </div>
      <div class="border border-line rounded-lg overflow-hidden" id="dns-tabla"></div>
    </div>`;
  renderDnsFilas(document.getElementById("dns-tabla"));
  cont.querySelector('[data-action="dns-nuevo"]').addEventListener("click", () => dnsFormulario(null));
}

function renderDnsFilas(tabla) {
  const registros = _dnsEstado.records || [];
  const candado = `<svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 018 0v4"/></svg>`;

  tabla.innerHTML = `
    <div class="hidden sm:grid grid-cols-[64px_minmax(0,1fr)_minmax(0,1.6fr)_64px_92px] gap-3 px-3 py-2 text-[10px] uppercase tracking-widest text-fg-subtle bg-bg-elev border-b border-line">
      <span>Tipo</span><span>Nombre</span><span>Valor</span><span>TTL</span><span></span>
    </div>
    <div class="divide-y divide-line">
      ${registros.map((r, i) => `
        <div class="px-3 py-2.5 grid grid-cols-1 sm:grid-cols-[64px_minmax(0,1fr)_minmax(0,1.6fr)_64px_92px] gap-2 sm:gap-3 sm:items-start">
          <div><span class="inline-block font-mono font-bold text-xs text-fg bg-bg-inset px-2 py-0.5 rounded">${esc(r.type)}</span></div>
          <div class="min-w-0"><code class="text-xs font-mono text-fg break-all">${esc(r.name)}</code></div>
          <div class="min-w-0">
            ${r.values.map(v => `<code class="block text-xs font-mono text-fg break-all">${esc(v)}</code>`).join("")}
          </div>
          <div class="text-xs text-fg-subtle">${r.ttl}</div>
          <div class="flex items-center gap-2">
            ${r.managed && !r.editable
              ? `<span class="inline-flex items-center gap-1 text-[10px] uppercase tracking-widest font-semibold text-accent-text">${candado} MailMask</span>`
              : `<button type="button" data-dns-editar="${i}" class="text-xs text-fg-subtle hover:text-fg">Editar</button>
                 ${r.managed ? "" : `<button type="button" data-dns-borrar="${i}" class="text-xs text-fg-subtle hover:text-red-500">Borrar</button>`}`}
          </div>
          ${r.managedReason
            // Visible como texto y no en un title=: en móvil no hay hover.
            ? `<div class="sm:col-span-5 text-xs text-fg-subtle sm:pl-[76px]">${esc(r.managedReason)}</div>`
            : ""}
        </div>`).join("")}
    </div>`;

  tabla.querySelectorAll("[data-dns-editar]").forEach(b =>
    b.addEventListener("click", () => dnsFormulario(registros[Number(b.dataset.dnsEditar)])));
  tabla.querySelectorAll("[data-dns-borrar]").forEach(b =>
    b.addEventListener("click", () => dnsBorrar(registros[Number(b.dataset.dnsBorrar)])));
}

const DNS_AYUDA = {
  A: "La dirección IPv4 del servidor. Ejemplo: 76.76.21.21",
  AAAA: "La dirección IPv6 del servidor.",
  CNAME: "El nombre al que apunta. No se puede usar en la raíz del dominio.",
  TXT: "Texto libre. Si es más largo de 255 caracteres lo partimos solos.",
  MX: "La prioridad va dentro del valor: 10 mail.ejemplo.com",
  NS: "Sólo para delegar un subdominio.",
  CAA: 'Qué autoridad puede emitir certificados: 0 issue "letsencrypt.org"',
  SRV: "prioridad peso puerto host. El nombre debe ser _servicio._protocolo.",
};

function dnsFormulario(registro) {
  const editando = !!registro;
  const tipos = ["A", "AAAA", "CNAME", "TXT", "MX", "NS", "CAA", "SRV"];
  const sufijo = `.${selectedDomain.domain}`;
  const nombreCorto = registro
    ? (registro.name === selectedDomain.domain ? "@" : registro.name.replace(sufijo, ""))
    : "";
  // En un registro parcialmente gestionado (el TXT de la raíz), lo nuestro no se puede quitar.
  const fijos = registro?.protectedValues || [];
  const editables = registro ? registro.values.filter(v => !fijos.includes(v)) : [];

  const dlg = document.createElement("div");
  dlg.className = "fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4";
  dlg.innerHTML = `
    <div class="bg-bg-elev border border-line rounded-xl w-full max-w-lg p-5">
      <h3 class="font-semibold text-fg mb-4">${editando ? "Editar registro" : "Añadir registro"}</h3>
      <div class="space-y-3">
        <div class="grid grid-cols-[110px_1fr] gap-3">
          <div>
            <label class="block text-xs text-fg-muted mb-1">Tipo</label>
            <select id="dns-f-tipo" ${editando ? "disabled" : ""} class="w-full bg-bg-inset border border-line rounded-lg px-2 py-2 text-sm text-fg">
              ${tipos.map(t => `<option ${registro?.type === t ? "selected" : ""}>${t}</option>`).join("")}
            </select>
          </div>
          <div>
            <label class="block text-xs text-fg-muted mb-1">Nombre</label>
            <input id="dns-f-nombre" ${editando ? "disabled" : ""} value="${esc(nombreCorto)}" placeholder="@ para la raíz, o www"
              class="w-full bg-bg-inset border border-line rounded-lg px-3 py-2 text-sm text-fg font-mono">
          </div>
        </div>
        ${fijos.length ? `
          <div>
            <label class="block text-xs text-fg-muted mb-1">De MailMask (no se puede quitar)</label>
            ${fijos.map(v => `<code class="block text-xs font-mono text-fg-subtle bg-bg-inset border border-line rounded px-2 py-1.5 break-all">${esc(v)}</code>`).join("")}
          </div>` : ""}
        <div>
          <label class="block text-xs text-fg-muted mb-1">Valor${fijos.length ? "es adicionales" : "(es)"} — uno por línea</label>
          <textarea id="dns-f-valores" rows="3" class="w-full bg-bg-inset border border-line rounded-lg px-3 py-2 text-sm text-fg font-mono">${esc(editables.join("\n"))}</textarea>
          <p id="dns-f-ayuda" class="text-xs text-fg-subtle mt-1"></p>
        </div>
        <div class="w-28">
          <label class="block text-xs text-fg-muted mb-1">TTL</label>
          <input id="dns-f-ttl" type="number" value="${registro?.ttl ?? 300}" class="w-full bg-bg-inset border border-line rounded-lg px-3 py-2 text-sm text-fg">
        </div>
        <p id="dns-f-error" class="text-sm text-red-500 hidden"></p>
        <div id="dns-f-sugerencia" class="hidden"></div>
      </div>
      <div class="flex justify-end gap-2 mt-5">
        <button type="button" data-action="cancelar" class="text-sm text-fg-muted hover:text-fg px-3 py-2">Cancelar</button>
        <button type="button" data-action="guardar" class="bg-accent hover:bg-accent/90 text-white text-sm font-semibold px-4 py-2 rounded-lg">Guardar</button>
      </div>
    </div>`;
  document.body.appendChild(dlg);

  const tipoEl = dlg.querySelector("#dns-f-tipo");
  const ayudaEl = dlg.querySelector("#dns-f-ayuda");
  const pintarAyuda = () => { ayudaEl.textContent = DNS_AYUDA[tipoEl.value] || ""; };
  tipoEl.addEventListener("change", pintarAyuda);
  pintarAyuda();

  const cerrar = () => dlg.remove();
  dlg.querySelector('[data-action="cancelar"]').addEventListener("click", cerrar);
  dlg.addEventListener("click", (e) => { if (e.target === dlg) cerrar(); });

  dlg.querySelector('[data-action="guardar"]').addEventListener("click", async () => {
    const errEl = dlg.querySelector("#dns-f-error");
    const sugEl = dlg.querySelector("#dns-f-sugerencia");
    errEl.classList.add("hidden");
    sugEl.classList.add("hidden");
    sugEl.innerHTML = "";

    const valores = [
      ...fijos,
      ...dlg.querySelector("#dns-f-valores").value.split("\n").map(v => v.trim()).filter(Boolean),
    ];

    const cuerpo = {
      name: dlg.querySelector("#dns-f-nombre").value.trim() || "@",
      type: tipoEl.value,
      ttl: Number(dlg.querySelector("#dns-f-ttl").value) || 300,
      values: valores,
    };

    const res = await fetch(`/api/domains/${selectedDomain.id}/dns/records`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(cuerpo),
    });
    const data = await res.json();

    if (!res.ok) {
      errEl.textContent = data.error || "No se pudo guardar.";
      errEl.classList.remove("hidden");
      // El servidor puede devolver los valores ya arreglados (el SPF del apex).
      if (data.suggestedValues) {
        sugEl.classList.remove("hidden");
        sugEl.innerHTML = `<button type="button" class="text-sm text-accent-text hover:underline">Corregir automáticamente</button>`;
        sugEl.querySelector("button").addEventListener("click", () => {
          dlg.querySelector("#dns-f-valores").value = data.suggestedValues.filter(v => !fijos.includes(v)).join("\n");
          sugEl.classList.add("hidden");
          errEl.classList.add("hidden");
        });
      }
      return;
    }

    playSound("success");
    cerrar();
    loadDns();
  });
}

async function dnsBorrar(registro) {
  if (!confirm(`¿Borrar el registro ${registro.type} de ${registro.name}? Esto puede tumbar lo que dependa de él.`)) return;

  const res = await fetch(`/api/domains/${selectedDomain.id}/dns/records`, {
    method: "DELETE",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: registro.name, type: registro.type }),
  });
  const data = await res.json();
  if (!res.ok) { alert(data.error || "No se pudo borrar."); return; }
  playSound("pop");
  loadDns();
}

async function verifyDns() {
  const resultEl = document.getElementById("verify-result");
  resultEl.textContent = "Verificando...";
  resultEl.className = "ml-3 text-sm text-fg-muted";

  const res = await fetch(`/api/domains/${selectedDomain.id}/verify`, { method: "POST" });
  const data = await res.json();

  if (data.verified) {
    resultEl.textContent = "✓ Dominio verificado";
    resultEl.className = "ml-3 text-sm text-accent-text";
    playSound("success");
    selectedDomain.verified = true;
    const statusEl = document.getElementById("detail-status");
    statusEl.textContent = "Verificado";
    statusEl.className = "text-xs px-2 py-1 rounded-full bg-accent/10 text-accent-text";
    loadDomainHealth();
  } else {
    resultEl.textContent = "✗ DNS no configurado aún. Verifica los registros e intenta de nuevo.";
    resultEl.className = "ml-3 text-sm text-amber-600";
  }
}

// --- SMTP helpers ---

const _smtpCopied = new Set();

function copySmtp(btn, text, key) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.innerHTML;
    btn.innerHTML = `<svg class="w-4 h-4 text-accent-text" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>`;
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

  const smtpAllowed = derechosDe(selectedDomain?.id).smtpRelay;

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
    <div class="bg-bg-inset border border-line rounded-lg px-5 py-4">
      <div class="flex items-center justify-between mb-2">
        <span class="font-semibold text-sm">${esc(c.label)}</span>
        <button data-revoke="${esc(c.id)}" class="text-xs text-red-500 hover:text-red-300 transition-colors flex items-center gap-1" title="Revocar credencial">
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
          Revocar
        </button>
      </div>
      <div class="flex items-center gap-2 text-xs text-fg-muted">
        <span>Usuario SMTP:</span>
        <code class="bg-bg-inset border border-line rounded px-2 py-0.5 font-mono text-fg select-all">${esc(c.accessKeyId)}</code>
        <button data-copy="${esc(c.accessKeyId)}" class="text-fg-subtle hover:text-fg transition-colors" title="Copiar usuario">${cpIcon}</button>
      </div>
      <div class="flex items-center gap-2 mt-2 text-xs text-fg-subtle">
        <span>${relativeTime(c.createdAt)}</span>
        <span class="inline-flex items-center gap-1 bg-accent/10 text-accent-text border border-green-800/40 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide">
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
    <p class="text-sm text-fg-muted mb-4">Usa estas credenciales en tu aplicación para enviar emails desde <strong class="text-fg">${esc(domain)}</strong>.</p>

    <div class="space-y-3">
      <div class="smtp-field">
        <div class="flex items-center justify-between mb-1">
          <span class="text-xs font-semibold text-fg-muted uppercase tracking-wide">Servidor SMTP</span>
        </div>
        <div class="flex items-center gap-2">
          <code class="flex-1 bg-bg-inset border border-line rounded-lg px-3 py-2.5 text-sm text-fg font-mono select-all">${esc(data.server)}</code>
          <button data-copy="${esc(data.server)}" data-copy-key="server" class="smtp-copy shrink-0 bg-bg-inset hover:bg-line border border-line rounded-lg p-2.5 text-fg-muted hover:text-fg transition-colors" title="Copiar">${copyIcon}</button>
        </div>
        <div class="flex gap-3 mt-2">
          <div class="flex items-center gap-2">
            <code class="bg-bg-inset border border-line rounded px-2 py-1 text-xs text-fg font-mono">587</code>
            <button data-copy="587" class="text-fg-subtle hover:text-fg transition-colors" title="Copiar puerto"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg></button>
            <span class="text-xs text-fg-subtle">Puerto</span>
          </div>
          <div class="flex items-center gap-2">
            <code class="bg-bg-inset border border-line rounded px-2 py-1 text-xs text-fg font-mono">STARTTLS</code>
            <button data-copy="STARTTLS" class="text-fg-subtle hover:text-fg transition-colors" title="Copiar seguridad"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg></button>
            <span class="text-xs text-fg-subtle">Seguridad</span>
          </div>
        </div>
      </div>

      <div class="smtp-field">
        <div class="flex items-center justify-between mb-1">
          <span class="text-xs font-semibold text-fg-muted uppercase tracking-wide">Usuario</span>
        </div>
        <div class="flex items-center gap-2">
          <code class="flex-1 bg-bg-inset border border-line rounded-lg px-3 py-2.5 text-sm text-fg font-mono select-all truncate">${esc(data.username)}</code>
          <button data-copy="${esc(data.username)}" data-copy-key="username" class="smtp-copy shrink-0 bg-bg-inset hover:bg-line border border-line rounded-lg p-2.5 text-fg-muted hover:text-fg transition-colors" title="Copiar">${copyIcon}</button>
        </div>
      </div>

      <div class="smtp-field">
        <div class="flex items-center justify-between mb-1">
          <span class="text-xs font-semibold text-amber-600 uppercase tracking-wide">Contraseña</span>
        </div>
        <p class="text-xs text-amber-600/70 mb-1.5">Copia esta contraseña ahora — no podrás verla de nuevo.</p>
        <div class="flex items-center gap-2">
          <code class="flex-1 bg-bg-inset border border-amber-500/30 rounded-lg px-3 py-2.5 text-sm text-fg font-mono select-all break-all">${esc(data.password)}</code>
          <button data-copy="${esc(data.password)}" data-copy-key="password" class="smtp-copy shrink-0 bg-bg-inset hover:bg-line border border-amber-500/30 rounded-lg p-2.5 text-amber-600 hover:text-yellow-300 transition-colors" title="Copiar">${copyIcon}</button>
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

async function saveSlug(slug, name) {
  const errEl = document.getElementById("edit-slug-error");
  errEl.classList.add("hidden");

  const res = await fetch("/api/referrals/slug", {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ slug }),
  });

  if (res.ok && name) {
    const r2 = await fetch("/api/referrals/name", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name }),
    });
    if (!r2.ok) {
      const data = await r2.json();
      errEl.textContent = data.error || "Error al guardar el nombre";
      errEl.classList.remove("hidden");
      return;
    }
  }

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
  list.innerHTML = `
    <table class="w-full text-sm">
      <thead>
        <tr class="text-left text-xs text-fg-subtle border-b border-line">
          <th class="pb-2 font-medium">Nombre</th>
          <th class="pb-2 font-medium">Key</th>
          <th class="pb-2 font-medium">Creada</th>
          <th class="pb-2 font-medium">Último uso</th>
          <th class="pb-2 font-medium text-right">Acciones</th>
        </tr>
      </thead>
      <tbody>
        ${keys.map(k => `
          <tr class="border-b border-line hover:bg-bg-inset">
            <td class="py-2.5 font-medium">${k.name}</td>
            <td class="py-2.5 text-fg-muted font-mono text-xs">${k.keyPrefix ? esc(k.keyPrefix) + "…" : "mk_…" + k.id.slice(-6)}</td>
            <td class="py-2.5 text-fg-subtle">${k.createdAt ? new Date(k.createdAt).toLocaleDateString() : "—"}</td>
            <td class="py-2.5 text-fg-subtle">${k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleDateString() : "Nunca"}</td>
            <td class="py-2.5 text-right">
              <button data-revoke-key="${k.id}" class="text-xs text-red-500 hover:text-red-300 transition-colors">Revocar</button>
            </td>
          </tr>
        `).join("")}
      </tbody>
    </table>`;
  list.querySelectorAll("[data-revoke-key]").forEach(btn => {
    btn.addEventListener("click", () => revokeApiKeyUI(btn.dataset.revokeKey));
  });
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
    el.classList.remove("active-tab", "text-fg");
    el.classList.add("text-fg-subtle");
  });

  document.getElementById(`tab-${tab}`).classList.remove("hidden");
  const activeBtn = document.querySelector(`.tab-btn[data-tab="${tab}"]`);
  activeBtn.classList.add("active-tab", "text-fg");
  activeBtn.classList.remove("text-fg-subtle");

  if (tab === "aliases") loadAliases();
  else if (tab === "rules") loadRules();
  else if (tab === "logs") loadLogs();
  else if (tab === "dns") { loadDns(); renderHealthPanel(); }
  else if (tab === "members") loadMembers();
  else if (tab === "smtp") loadSmtpCredentials();
  else if (tab === "webhooks") loadWebhooks();
  else if (tab === "apikeys") loadApiKeys();
}

// --- Webhooks (sólo lectura + probar/pausar/borrar; se crean con el SDK) ---

function webhooksSnippet() {
  return `import { MailMask } from "@easybits.cloud/mailmask";

const mm = new MailMask({ apiKey: process.env.MAILMASK_API_KEY });
const wh = await mm.webhooks.create("${selectedDomain.id}", {
  url: "https://tu-app.com/webhooks/mailmask",
  events: ["email.received", "email.delivered", "email.bounced"],
});
console.log(wh.secret); // se muestra una sola vez: guárdalo en tu .env`;
}

async function loadWebhooks() {
  const list = document.getElementById("webhooks-list");
  const empty = document.getElementById("webhooks-empty");
  const upgrade = document.getElementById("webhooks-upgrade");
  if (!selectedDomain) return;

  if (!derechosDe(selectedDomain?.id).webhooks) {
    list.innerHTML = "";
    empty.classList.add("hidden");
    upgrade.classList.remove("hidden");
    return;
  }
  upgrade.classList.add("hidden");

  const res = await fetch(`/api/domains/${selectedDomain.id}/webhooks`);
  if (!res.ok) return;
  const hooks = await res.json();
  if (!hooks.length) {
    list.innerHTML = "";
    document.getElementById("webhooks-snippet").textContent = webhooksSnippet();
    empty.classList.remove("hidden");
    return;
  }
  empty.classList.add("hidden");

  const deliveries = await Promise.all(hooks.map(async (h) => {
    const r = await fetch(`/api/domains/${selectedDomain.id}/webhooks/${h.id}/deliveries`);
    return r.ok ? (await r.json()).slice(0, 5) : [];
  }));

  const badge = (d) => d.status === "delivered"
    ? `<span class="text-accent-text">${d.lastStatusCode ?? "ok"}</span>`
    : d.status === "failed"
      ? `<span class="text-red-500">falló</span>`
      : `<span class="text-amber-600">reintento ${d.attempts}</span>`;

  list.innerHTML = hooks.map((h, i) => `
    <div class="bg-bg-inset border border-line rounded-lg px-5 py-4">
      <div class="flex items-center justify-between gap-3 mb-2">
        <code class="text-sm font-mono text-fg truncate">${esc(h.url)}</code>
        <div class="flex items-center gap-3 shrink-0">
          <span class="inline-flex items-center gap-1 ${h.enabled ? "bg-accent/10 text-accent-text border-green-800/40" : "bg-bg-inset text-fg-subtle border-line"} border rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide">
            <span class="w-1.5 h-1.5 ${h.enabled ? "bg-green-400" : "bg-fg-subtle"} rounded-full"></span>${h.enabled ? "Activo" : "Pausado"}
          </span>
          <button data-wh-test="${esc(h.id)}" class="text-xs text-fg-muted hover:text-fg transition-colors">Probar</button>
          <button data-wh-toggle="${esc(h.id)}" data-enabled="${h.enabled ? 1 : 0}" class="text-xs text-fg-muted hover:text-fg transition-colors">${h.enabled ? "Pausar" : "Reanudar"}</button>
          <button data-wh-delete="${esc(h.id)}" class="text-xs text-red-500 hover:text-red-300 transition-colors">Eliminar</button>
        </div>
      </div>
      <div class="flex flex-wrap gap-1.5 mb-3">
        ${h.events.map(e => `<span class="text-[11px] font-mono bg-bg-inset border border-line rounded px-1.5 py-0.5 text-fg">${esc(e)}</span>`).join("")}
      </div>
      ${deliveries[i].length ? `
        <div class="text-xs text-fg-subtle mb-1">Últimas entregas</div>
        <div class="space-y-1">
          ${deliveries[i].map(d => `
            <div class="flex items-center gap-3 text-xs text-fg-muted">
              <span class="font-mono text-fg w-32 truncate">${esc(d.event)}</span>
              ${badge(d)}
              <span class="text-fg-subtle">${relativeTime(d.createdAt)}</span>
              ${d.lastError ? `<span class="text-fg-subtle truncate" title="${esc(d.lastError)}">${esc(d.lastError)}</span>` : ""}
            </div>`).join("")}
        </div>` : `<div class="text-xs text-fg-subtle">Sin entregas todavía. "Probar" encola un ping que sale en el siguiente minuto.</div>`}
    </div>
  `).join("");

  list.querySelectorAll("[data-wh-test]").forEach(btn => btn.addEventListener("click", async () => {
    const r = await fetch(`/api/domains/${selectedDomain.id}/webhooks/${btn.dataset.whTest}/test`, { method: "POST"  });
    if (r.ok) { playSound("success"); showToast("Ping encolado: llega en el siguiente minuto"); }
    else showToast((await r.json().catch(() => ({}))).error || "No se pudo encolar", true);
  }));
  list.querySelectorAll("[data-wh-toggle]").forEach(btn => btn.addEventListener("click", async () => {
    const enabled = btn.dataset.enabled !== "1";
    const r = await fetch(`/api/domains/${selectedDomain.id}/webhooks/${btn.dataset.whToggle}`, {
      method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled }),
    });
    if (r.ok) { playSound("click"); loadWebhooks(); } else showToast("No se pudo actualizar", true);
  }));
  list.querySelectorAll("[data-wh-delete]").forEach(btn => btn.addEventListener("click", async () => {
    const r = await fetch(`/api/domains/${selectedDomain.id}/webhooks/${btn.dataset.whDelete}`, { method: "DELETE"  });
    if (r.ok) { playSound("delete"); showToast("Webhook eliminado"); loadWebhooks(); } else showToast("No se pudo eliminar", true);
  }));
}

// --- Modals ---

// Con un modal abierto, el fondo no debe desplazarse. Se lleva la cuenta de cuántos hay
// abiertos para que cerrar uno no libere el scroll si todavía queda otro.
let openModals = 0;

function lockBodyScroll() {
  if (openModals === 0) {
    // Se compensa el ancho de la barra de desplazamiento para que la página no salte
    // al ocultarla.
    const gap = window.innerWidth - document.documentElement.clientWidth;
    document.body.dataset.prevOverflow = document.body.style.overflow || "";
    document.body.dataset.prevPadding = document.body.style.paddingRight || "";
    document.body.style.overflow = "hidden";
    if (gap > 0) document.body.style.paddingRight = `${gap}px`;
  }
  openModals++;
}

function unlockBodyScroll() {
  openModals = Math.max(0, openModals - 1);
  if (openModals === 0) {
    document.body.style.overflow = document.body.dataset.prevOverflow ?? "";
    document.body.style.paddingRight = document.body.dataset.prevPadding ?? "";
    delete document.body.dataset.prevOverflow;
    delete document.body.dataset.prevPadding;
  }
}

function showModal(id) {
  const el = document.getElementById(id);
  if (!el || !el.classList.contains("hidden")) return; // ya estaba abierto: no contar doble
  el.classList.remove("hidden");
  lockBodyScroll();
}

function hideModal(id) {
  const el = document.getElementById(id);
  if (!el || el.classList.contains("hidden")) return; // ya estaba cerrado
  el.classList.add("hidden");
  unlockBodyScroll();
}

// Los precios los manda el servidor: esta lista estaba duplicada a mano y se quedó
// desfasada en cuanto cambiaron.
let AVAILABLE_TLDS = [];

async function cargarTlds() {
  if (AVAILABLE_TLDS.length) return AVAILABLE_TLDS;
  try {
    const res = await fetch("/api/domains/tlds");
    if (res.ok) AVAILABLE_TLDS = await res.json();
  } catch { /* sin lista, el grid no se pinta y el buscador sigue funcionando */ }
  return AVAILABLE_TLDS;
}

async function renderTldGrid(base) {
  await cargarTlds();
  const container = document.getElementById("add-domain-tld-list");
  const gridEl = document.getElementById("add-domain-tld-grid");
  if (!container || !gridEl) return;

  const name = base || "tudominio";
  container.innerHTML = AVAILABLE_TLDS.map(t => {
    const p = (t.price / 100).toLocaleString("es-MX", { minimumFractionDigits: 0, maximumFractionDigits: 0 });
    return `<button type="button" class="tld-suggestion group text-left bg-bg-inset hover:bg-bg-inset border border-line hover:border-accent/30 rounded-xl px-5 py-4 transition-all" data-domain="${esc(name + t.tld)}">
      <span class="block text-base font-bold text-accent-text group-hover:text-accent">${t.tld}</span>
      <span class="block text-xs text-fg-subtle mt-1.5">$${p} MXN/año</span>
      ${t.popular ? '<span class="inline-block text-[9px] bg-accent/25 text-accent-text px-1.5 py-0.5 rounded mt-1.5 leading-none">Popular</span>' : ''}
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

// --- Destinos como chips ---
// Un correo por etiqueta, con su ×. El input oculto `destinations` conserva la lista
// separada por comas, así que el envío al servidor no cambia.
function initChips(box) {
  if (!box || box._chips) return box?._chips;
  const input = box.querySelector(".chips-input");
  const hidden = box.querySelector("input[name=destinations]");
  const emailRe = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
  let items = [];
  const sync = () => { hidden.value = items.join(","); };
  const render = () => {
    box.querySelectorAll(".chip").forEach(c => c.remove());
    items.forEach((v, i) => {
      const chip = document.createElement("span");
      chip.className = "chip inline-flex items-center gap-1 rounded-md bg-line border border-line pl-2 pr-1 py-0.5 text-sm text-fg";
      chip.innerHTML = `<span>${esc(v)}</span><button type="button" class="text-fg-muted hover:text-red-500 leading-none px-1" aria-label="Quitar ${esc(v)}">&times;</button>`;
      chip.querySelector("button").addEventListener("click", () => { items.splice(i, 1); render(); input.focus(); });
      box.insertBefore(chip, input);
    });
    sync();
  };
  const commit = () => {
    const raw = input.value.split(/[,\s;]+/).map(v => v.trim().toLowerCase()).filter(Boolean);
    let bad = false;
    for (const v of raw) {
      if (!emailRe.test(v)) { bad = true; continue; }
      if (!items.includes(v)) items.push(v);
    }
    input.value = bad ? raw.filter(v => !emailRe.test(v)).join(", ") : "";
    input.classList.toggle("text-red-500", bad);
    render();
    return !bad;
  };
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === "," || e.key === "Tab" && input.value.trim()) { e.preventDefault(); commit(); }
    else if (e.key === "Backspace" && !input.value && items.length) { items.pop(); render(); }
  });
  input.addEventListener("blur", commit);
  input.addEventListener("paste", () => setTimeout(commit, 0));
  box.addEventListener("click", (e) => { if (e.target === box) input.focus(); });
  const api = {
    set(list) { items = (Array.isArray(list) ? list : String(list || "").split(",")).map(v => v.trim().toLowerCase()).filter(Boolean); input.value = ""; input.classList.remove("text-red-500"); render(); },
    get() { commit(); return items.slice(); },
    commit,
  };
  box._chips = api;
  render();
  return api;
}

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
  document.getElementById("btn-add-alias").addEventListener("click", () => {
    const form = document.getElementById("form-add-alias");
    initChips(form.querySelector("[data-chips]")).set([]);
    form.mailbox.checked = false;
    document.getElementById("add-alias-mailbox-row")?.classList.toggle("hidden", !derechosDe(selectedDomain?.id).mailboxes);
    showModal("modal-add-alias");
  });

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
      if (form && currentUser?.referralStats?.name) form.name.value = currentUser.referralStats.name;
      showModal("modal-edit-slug");
      return;
    }
  });

  // Form: Edit slug
  document.getElementById("form-edit-slug")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    await saveSlug(e.target.slug.value.trim().toLowerCase(), e.target.name.value.trim());
  });

  // (Add domain form replaced by unified search modal — handled via btn-add-domain-search)

  // Form: Add alias
  document.getElementById("form-add-alias").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    const errEl = document.getElementById("add-alias-error");
    errEl.classList.add("hidden");

    initChips(form.querySelector("[data-chips]")).commit();
    const destinations = form.destinations.value.split(",").map(d => d.trim().toLowerCase()).filter(Boolean);
    const conBuzon = form.mailbox?.checked === true;
    if (destinations.length === 0 && !conBuzon) {
      errEl.textContent = "Agrega al menos un destino, o marca que guarde el correo en un buzón";
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
      body: JSON.stringify({ alias: form.alias.value.trim().toLowerCase(), destinations, mailbox: conBuzon }),
    });

    if (res.ok) {
      const data = await res.json();
      playSound("pop");
      hideModal("modal-add-alias");
      form.reset();
      await loadAliases();
      await refreshUsage();
      // El buzón nació con la máscara: la contraseña se muestra UNA vez, aquí.
      if (data.buzon) {
        document.getElementById("mailbox-title").textContent = data.buzon.email;
        document.getElementById("mailbox-body").innerHTML = credencialesNuevas(data.buzon, data.alias);
        showModal("modal-mailbox");
      } else if (data.errorBuzon) {
        showToast(`La máscara se creó, pero el buzón no: ${data.errorBuzon}`, true);
      }
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

    initChips(form.querySelector("[data-chips]")).commit();
    const destinations = form.destinations.value.split(",").map(d => d.trim().toLowerCase()).filter(Boolean);
    // Sin destinos es válido SI la máscara guarda su correo en un buzón: eso es un
    // buzón sin reenvío, que es lo que permite dejar Gmail. Sin destinos y sin buzón,
    // en cambio, el correo no iría a ningún lado.
    const tieneBuzon = aliasesActuales.find(a => a.alias === form.alias.value)?.mailboxEnabled;
    if (destinations.length === 0 && !tieneBuzon) {
      errEl.textContent = "Agrega al menos un destino, o crea un buzón donde guardar el correo";
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

  // Event delegation: add-ons (el contenido se re-renderiza, así que no se puede
  // enganchar a los botones directamente)
  document.getElementById("addons-list")?.addEventListener("click", (e) => {
    const buy = e.target.closest("[data-action='buy-addon']");
    if (buy) { buyAddon(buy.dataset.kind, buy.dataset.domainId); return; }
    const cancel = e.target.closest("[data-action='cancel-addon']");
    if (cancel) cancelAddon(cancel.dataset.addonId);
  });

  // Delegación a nivel documento: el resumen de cobro se re-renderiza completo en cada
  // refresh, así que no hay a qué engancharse de forma permanente.
  document.addEventListener("click", (e) => {
    if (e.target.closest("[data-action='show-orders']")) { showOrdersModal(); return; }

    const dismiss = e.target.closest("[data-action='dismiss-order']");
    if (dismiss) {
      localStorage.setItem("mm:seen-order", dismiss.dataset.orderId);
      renderBillingSummary();
      return;
    }

    const copy = e.target.closest("[data-action='copy-order']");
    if (copy) {
      // Copiar el folio *es* el trámite de la factura.
      navigator.clipboard.writeText(copy.dataset.orderNumber).then(() => {
        playSound("copy");
        showToast("Folio copiado");
      }).catch(() => showToast("No se pudo copiar", true));
    }
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
    // Copiar la dirección completa, que es lo que se comparte: el alias solo, sin
    // el dominio, no le sirve a nadie.
    const copiar = e.target.closest("[data-action='copy-alias']");
    if (copiar) {
      navigator.clipboard.writeText(copiar.dataset.value);
      playSound("copy");
      const antes = copiar.textContent;
      copiar.textContent = "¡Copiado!";
      copiar.classList.add("text-accent-text");
      setTimeout(() => { copiar.textContent = antes; copiar.classList.remove("text-accent-text"); }, 1500);
      return;
    }
    const buzon = e.target.closest("[data-action='mailbox-alias']");
    if (buzon) { abrirBuzon(buzon.dataset.alias, Boolean(buzon.dataset.has)); return; }
    const remove = e.target.closest("[data-action='remove-alias']");
    if (remove) removeAlias(remove.dataset.alias);
    const edit = e.target.closest("[data-action='edit-alias']");
    if (edit) {
      const alias = edit.dataset.alias;
      document.getElementById("edit-alias-name").textContent = `${alias}@${selectedDomain.domain}`;
      const form = document.getElementById("form-edit-alias");
      form.alias.value = alias;
      initChips(form.querySelector("[data-chips]")).set(edit.dataset.destinations);
      document.getElementById("edit-alias-error").classList.add("hidden");
      showModal("modal-edit-alias");
    }
  });

  // Botones dentro del modal de buzón. La CSP prohíbe onclick en el HTML, así que
  // todo va por delegación.
  document.getElementById("mailbox-body")?.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-mailbox]");
    if (!b) return;
    const alias = document.getElementById("mailbox-title").textContent.split("@")[0];
    const base = `/api/domains/${selectedDomain.id}/alias/${encodeURIComponent(alias)}/mailbox`;

    if (b.dataset.mailbox === "copy") {
      navigator.clipboard.writeText(b.dataset.value);
      playSound("copy");
      const antes = b.innerHTML;
      b.innerHTML = '<svg class="h-4 w-4 text-mask-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>';
      setTimeout(() => { b.innerHTML = antes; }, 1500);
      return;
    }
    if (b.dataset.mailbox === "password") {
      if (!confirm("Se generará una contraseña nueva y la actual dejará de servir en todos tus dispositivos. ¿Seguir?")) return;
      const res = await fetch(`${base}/password`, { method: "POST" });
      const data = await res.json();
      document.getElementById("mailbox-body").innerHTML = res.ok
        ? credencialesNuevas({ ...data, email: `${alias}@${selectedDomain.domain}` }, alias)
        : `<p class="text-sm text-red-500">${esc(data.error)}</p>`;
      return;
    }
    if (b.dataset.mailbox === "delete") {
      // Esto borra correo y no se puede deshacer, así que se ofrece la descarga antes.
      if (!confirm("Se borrará el buzón Y TODO SU CORREO, sin vuelta atrás. Descárgalo antes si lo necesitas. ¿Seguir?")) return;
      const res = await fetch(base, { method: "DELETE" });
      const data = await res.json();
      if (!res.ok) {
        document.getElementById("mailbox-body").innerHTML = `<p class="text-sm text-red-500">${esc(data.error)}</p>`;
        return;
      }
      hideModal("modal-mailbox");
      loadAliases();
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
  document.getElementById("members-list")?.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-action]");
    if (!btn) return;
    const { action } = btn.dataset;
    if (action === "remove-member") removeMember(btn.dataset.agentId, btn.dataset.agentName);
    else if (action === "cancel-invite") cancelInvite(btn.dataset.token);
    else if (action === "copy-invite") {
      await navigator.clipboard.writeText(btn.dataset.url);
      const orig = btn.textContent;
      btn.textContent = "Copiado ✓";
      setTimeout(() => { btn.textContent = orig; }, 1500);
    } else if (action === "resend-invite") {
      btn.disabled = true;
      await inviteMember(btn.dataset.name, btn.dataset.email, btn.dataset.role);
    }
  });

  // Event delegation: DNS copy buttons with feedback
  document.getElementById("dns-records").addEventListener("click", (e) => {
    const copy = e.target.closest("[data-action='copy']");
    if (!copy) return;
    navigator.clipboard.writeText(copy.dataset.copyValue);
    const checkIcon = `<svg class="w-3.5 h-3.5 text-accent-text" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg>`;
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
