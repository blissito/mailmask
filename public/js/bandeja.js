// Mesa — keyboard-first helpdesk inbox
// Vanilla JS, no dependencies

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

// --- State ---
let currentUser = null;
let domains = [];
let selectedDomainId = null;
let conversations = [];
let selectedIdx = -1;
let activeConv = null;
let canDoActions = false; // false for basico plan
let canCompose = false;   // redactar correo nuevo viene con el dominio activado
let domainAliases = [];   // alias del dominio seleccionado, para el remitente
let composerMode = "reply"; // "reply" | "note"

// Editores con formato (composer.js). Sustituyen a los textareas pero los dejan en
// el DOM como espejo, así que el resto de este archivo puede seguir leyendo .value.
let replyEditor = null;
let composeEditor = null;

// Sube una imagen y devuelve su URL pública. El bucket es privado: la URL apunta a
// /api/img/:key, que es lo que el cliente de correo del destinatario podrá abrir.
// Sube un adjunto. A diferencia de las imágenes no se sirve por HTTP: viaja dentro
// del correo y el servidor lo borra de S3 al enviarlo.
async function uploadComposerFile(file) {
  const fd = new FormData();
  fd.append("file", file);
  const res = await fetch(`/api/domains/${selectedDomainId}/attachments`, { method: "POST", body: fd });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "No se pudo subir el archivo");
  return { key: data.key, filename: data.filename, size: data.size };
}

async function loadCannedResponses() {
  const res = await fetch(`/api/domains/${selectedDomainId}/canned`);
  if (!res.ok) throw new Error("No se pudieron cargar");
  return res.json();
}

async function uploadComposerImage(file) {
  const fd = new FormData();
  fd.append("file", file);
  const res = await fetch(`/api/domains/${selectedDomainId}/images`, { method: "POST", body: fd });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "No se pudo subir la imagen");
  return data.url;
}

function mountComposers() {
  if (!window.MailMaskComposer) return; // sin el bundle, se sigue usando el textarea
  const replyArea = document.getElementById("composer-textarea");
  // El aviso de "escribiendo" se engancha al contenedor del compositor y no al
  // editor: Tiptap reemplaza el textarea por un div contenteditable.
  const zonaCompositor = document.getElementById("composer");
  if (zonaCompositor && !zonaCompositor.dataset.presencia) {
    zonaCompositor.dataset.presencia = "1";
    zonaCompositor.addEventListener("keydown", marcarEscribiendo);
  }
  if (replyArea && !replyEditor) {
    replyEditor = window.MailMaskComposer.create({
      textarea: replyArea,
      onSubmit: () => sendReply(),
      uploadImage: uploadComposerImage,
      uploadFile: uploadComposerFile,
      loadCanned: loadCannedResponses,
    });
  }
  const composeArea = document.getElementById("compose-body");
  if (composeArea && !composeEditor) {
    composeEditor = window.MailMaskComposer.create({
      textarea: composeArea,
      onSubmit: () => sendNew(),
      uploadImage: uploadComposerImage,
      uploadFile: uploadComposerFile,
      loadCanned: loadCannedResponses,
    });
  }
}

// Los toast del compositor viajan por evento para no acoplarlo a este archivo.
window.addEventListener("mm:toast", (e) => toast(e.detail));
// El no-leído lo manda el servidor por conversación: antes vivía sólo en esta
// pestaña, así que se perdía al recargar y era el mismo para todo el equipo.
let unreadIds = new Set();
// Las que ENTRARON con la pestaña abierta. Es un conjunto aparte de `unreadIds`
// a propósito: la animación de llegada sólo tiene sentido para lo que acaba de
// llegar. Aplicársela a todo lo no leído dejaba la lista entera latiendo sola.
let convsNuevasEnVivo = new Set();
// Selección múltiple para borrar en lote. Vive sólo en la pestaña: no tiene
// sentido recordar una selección entre recargas.
let seleccionadas = new Set();
let ultimaMarcada = -1;
let unreadCount = 0;
// Presencia de los compañeros en el dominio, tal como llega por SSE.
let presencias = [];

// --- Init ---
document.addEventListener("DOMContentLoaded", async () => {
  await checkAuth();
  await loadDomains();
  setupListeners();
  setupKeyboard();
  engancharClicksLista();
  mountComposers();
  iniciarLatidoPresencia();

  // Cerrar la pestaña siempre aborta el SSE y el servidor limpia la presencia ahí;
  // el beacon sólo adelanta el aviso para que el compañero no espere 35 segundos.
  const soltarPresencia = () => {
    if (!selectedDomainId) return;
    const carga = JSON.stringify({ domainId: selectedDomainId, conversationId: null });
    navigator.sendBeacon?.("/api/bandeja/presence", new Blob([carga], { type: "application/json" }));
  };
  window.addEventListener("pagehide", soltarPresencia);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") soltarPresencia();
    else if (activeConv) enviarPresencia(activeConv.id, "viewing");
  });
});

// --- Auth ---
async function checkAuth() {
  const res = await fetch("/api/auth/me");
  if (!res.ok) return window.location.href = "/login";
  currentUser = await res.json();
  document.getElementById("user-email").textContent = currentUser.email;
  if (currentUser.isAdmin) { const al = document.getElementById("admin-link"); if (al) al.style.display = ""; }

  canDoActions = true;
  // Responder está incluido en todos los planes; iniciar un correo nuevo no.
  canCompose = currentUser.limits?.sendsUnlocked === true;
}

// --- Domains ---
async function loadDomains() {
  const res = await fetch("/api/domains");
  if (!res.ok) return;
  domains = await res.json();

  const sel = document.getElementById("domain-select");
  if (domains.length === 0) {
    sel.innerHTML = '<option value="">No hay dominios</option>';
    return;
  }

  sel.innerHTML = domains.map(d =>
    `<option value="${esc(d.id)}">${esc(d.domain)}</option>`
  ).join("");

  // Al recargar se vuelve al dominio donde estabas, no al primero de la lista.
  let recordado = null;
  try { recordado = localStorage.getItem("bandeja.domainId"); } catch {}
  selectedDomainId = domains.some(d => d.id === recordado) ? recordado : domains[0].id;
  sel.value = selectedDomainId;
  await loadAliasesForCompose();
  await loadConversations();
  connectSSE(selectedDomainId);
}

// Alias reales del dominio, para el selector de remitente. Tienen que ser alias
// existentes: si no, la respuesta del contacto no se reenvía a ningún buzón.
async function loadAliasesForCompose() {
  domainAliases = [];
  if (!selectedDomainId) return;
  try {
    const res = await fetch(`/api/domains/${selectedDomainId}/alias`);
    if (!res.ok) return;
    const list = await res.json();
    domainAliases = (list || []).filter(a => a.enabled && a.alias !== "*");
  } catch { /* el botón se deshabilita solo si queda vacío */ }
  updateComposeButton();
}

function updateComposeButton() {
  const btn = document.getElementById("btn-compose");
  if (!btn) return;
  if (!canCompose) {
    btn.disabled = true;
    btn.title = "Activa el dominio ($99/mes) para escribir correos nuevos";
  } else if (domainAliases.length === 0) {
    btn.disabled = true;
    btn.title = "Crea un alias en este dominio para poder escribir";
  } else {
    btn.disabled = false;
    btn.title = "Redactar (C)";
  }
}

// --- Redactar ---
function openComposeModal() {
  if (!canCompose) {
    toast("Tu plan no incluye enviar correos nuevos. Agrega el add-on desde el panel.");
    return;
  }
  if (domainAliases.length === 0) {
    toast("Necesitas un alias activo en este dominio.");
    return;
  }
  const domain = domains.find(d => d.id === selectedDomainId);
  document.getElementById("compose-from").innerHTML = domainAliases
    .map(a => `<option value="${esc(a.alias)}">${esc(a.alias)}@${esc(domain?.domain ?? "")}</option>`)
    .join("");
  document.getElementById("compose-to").value = "";
  document.getElementById("compose-subject").value = "";
  document.getElementById("compose-body").value = "";
  document.getElementById("compose-cc").value = "";
  document.getElementById("compose-bcc").value = "";
  document.getElementById("compose-copy-row").hidden = true;
  composeEditor?.clear();
  const err = document.getElementById("compose-error");
  err.classList.add("hidden");
  err.textContent = "";
  document.getElementById("modal-compose").classList.remove("hidden");
  lockBodyScroll();
  document.getElementById("compose-to").focus();
}

function closeComposeModal() {
  const el = document.getElementById("modal-compose");
  if (el.classList.contains("hidden")) return;
  el.classList.add("hidden");
  unlockBodyScroll();
}

async function sendNew() {
  const btn = document.getElementById("compose-send");
  const err = document.getElementById("compose-error");
  const to = document.getElementById("compose-to").value.trim();
  const subject = document.getElementById("compose-subject").value.trim();
  const body = (composeEditor ? composeEditor.getMarkdown() : document.getElementById("compose-body").value).trim();
  const fromAlias = document.getElementById("compose-from").value;

  const fail = (msg) => { err.textContent = msg; err.classList.remove("hidden"); };
  err.classList.add("hidden");
  if (!to || !subject || !body) return fail("Completa destinatario, asunto y mensaje.");

  btn.disabled = true;
  btn.textContent = "Enviando...";
  try {
    const res = await fetch("/api/bandeja/conversations", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        domainId: selectedDomainId, to, subject, markdown: body, fromAlias,
        cc: splitAddresses(document.getElementById("compose-cc").value),
        bcc: splitAddresses(document.getElementById("compose-bcc").value),
        attachments: composeEditor ? composeEditor.getAttachments() : [],
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) return fail(data.error || "No se pudo enviar el correo.");

    closeComposeModal();
    playSound("whoosh");
    toast(data.warning || "Correo enviado");
    await loadConversations();
    // Abrir el hilo recién creado, si se guardó.
    if (data.conversationId) {
      const conv = conversations.find(c => c.id === data.conversationId);
      if (conv) openConversation(conv);
    }
  } catch (e) {
    fail("Error de red. Intenta de nuevo.");
  } finally {
    btn.disabled = false;
    btn.textContent = "Enviar";
  }
}

// --- Conversations ---
// El filtrado y la búsqueda viven en el servidor desde que la lista pagina: el
// cliente ya no tiene todas las conversaciones, sólo la página que pidió, así
// que filtrar aquí mostraría resultados incompletos sin avisar.
let nextCursor = null;
let cargandoPagina = false;

function paramsDeFiltros() {
  const p = new URLSearchParams({ domainId: selectedDomainId });
  const status = document.getElementById("status-filter").value;
  const alias = document.getElementById("alias-filter").value;
  const q = document.getElementById("search-input").value.trim();
  if (status) p.set("status", status);
  if (alias) p.set("to", alias);
  if (q) p.set("q", q);
  return p;
}

async function loadConversations(opts = {}) {
  if (!selectedDomainId) return;
  const masPaginas = opts.append === true;
  if (cargandoPagina) return;
  if (masPaginas && !nextCursor) return;
  cargandoPagina = true;

  const params = paramsDeFiltros();
  if (masPaginas) params.set("cursor", nextCursor);

  try {
    const res = await fetch(`/api/bandeja/conversations?${params}`);
    if (!res.ok) {
      if (!masPaginas) { conversations = []; nextCursor = null; renderList(); }
      return;
    }
    const data = await res.json();
    conversations = masPaginas ? conversations.concat(data.items) : data.items;
    nextCursor = data.nextCursor ?? null;
    if (Array.isArray(data.aliases)) populateAliasFilter(data.aliases);
    for (const c of data.items) {
      if (c.unread) unreadIds.add(c.id); else unreadIds.delete(c.id);
    }
    if (typeof data.unreadCount === "number") { unreadCount = data.unreadCount; updateTitle(); }
    if (Array.isArray(data.presence)) { presencias = data.presence; renderPresence(); }
    mostrarAvisoIndexado(data);
    renderList();
  } finally {
    cargandoPagina = false;
  }
}

// Los aliases los calcula el servidor: derivarlos de `conversations` sólo vería
// los de la página cargada, así que el filtro perdería opciones al paginar.
function populateAliasFilter(aliases) {
  const sel = document.getElementById("alias-filter");
  const prev = sel.value;
  sel.innerHTML = '<option value="">Todos los alias</option>' +
    aliases.map(a => `<option value="${esc(a)}">${esc(a.split("@")[0])}</option>`).join("");
  if (prev && aliases.includes(prev)) sel.value = prev;
}

// Mientras el backfill del índice avanza, buscar puede no encontrar correo viejo.
// Decirlo evita que parezca que la búsqueda está rota.
function mostrarAvisoIndexado(data) {
  const aviso = document.getElementById("search-notice");
  if (!aviso) return;
  const pendiente = data.backfillPendiente;
  if (data.mode === "search-degraded") {
    aviso.textContent = "Búsqueda limitada a remitente y asunto.";
    aviso.classList.remove("mesa-hidden");
  } else if (pendiente > 0) {
    aviso.textContent = `Aún estamos indexando correos antiguos (${pendiente} pendientes).`;
    aviso.classList.remove("mesa-hidden");
  } else {
    aviso.classList.add("mesa-hidden");
  }
}

function actualizarBotonLimpiar() {
  const campo = document.getElementById("search-input");
  document.getElementById("search-clear")?.classList.toggle("mesa-hidden", !campo.value);
}

function limpiarBusqueda() {
  const campo = document.getElementById("search-input");
  campo.value = "";
  actualizarBotonLimpiar();
  campo.focus();
  loadConversations();
}

function renderList() {
  const container = document.getElementById("conv-list");
  const empty = document.getElementById("list-empty");

  // Sin filtrado en cliente: lo que hay en `conversations` es exactamente lo que
  // el servidor devolvió para los filtros activos.
  const filtered = conversations;

  const sufijo = nextCursor ? "+" : "";
  const buscando = !!document.getElementById("search-input")?.value.trim();
  const sustantivo = filtered.length !== 1 ? "conversaciones" : "conversación";
  document.getElementById("conv-count").textContent = buscando
    ? `${filtered.length}${sufijo} ${filtered.length !== 1 ? "resultados" : "resultado"}`
    : `${filtered.length}${sufijo} ${sustantivo}`;

  if (filtered.length === 0) {
    // Clear any rendered items but keep the empty state
    container.querySelectorAll(".mesa-conv").forEach(el => el.remove());
    // "No hay nada" y "tu búsqueda no encontró nada" son mensajes distintos: el
    // primero desorienta cuando acabas de buscar algo que no existe.
    const consulta = document.getElementById("search-input")?.value.trim();
    const titulo = document.getElementById("empty-title");
    const desc = document.getElementById("empty-desc");
    const btnLimpiar = document.getElementById("empty-clear-search");
    if (consulta) {
      if (titulo) titulo.textContent = "Sin resultados";
      if (desc) desc.textContent = `No encontramos nada para «${consulta}».`;
      btnLimpiar?.classList.remove("mesa-hidden");
    } else {
      if (titulo) titulo.textContent = "Sin conversaciones";
      if (desc) desc.textContent = "Activa Bandeja en la configuración de tu dominio para ver los emails entrantes aquí.";
      btnLimpiar?.classList.add("mesa-hidden");
    }
    empty.classList.remove("mesa-hidden");
    return;
  }

  empty.classList.add("mesa-hidden");
  const html = filtered.map((c, i) => convRowHtml(c, i)).join("");

  // Replace only conversation items, preserve empty state element
  container.querySelectorAll(".mesa-conv").forEach(el => el.remove());
  container.insertAdjacentHTML("beforeend", html);

  // El botón va siempre al final de la lista, después de las filas.
  const btnMas = document.getElementById("btn-load-more");
  if (btnMas) {
    btnMas.classList.toggle("mesa-hidden", !nextCursor);
    container.appendChild(btnMas);
  }
}

/**
 * El HTML de UNA fila. Está separado de renderList porque abrir una conversación
 * o moverse con j/k no debe reconstruir la lista entera: hacerlo borraba y volvía
 * a insertar los treinta elementos y todos parpadeaban a la vez.
 */
function convRowHtml(c, i) {
  {
    const initials = c.from.split("@")[0].slice(0, 2);
    const time = formatTime(c.lastMessageAt);
    const isActive = activeConv?.id === c.id;
    const isSelected = i === selectedIdx;
    let classes = "mesa-conv";
    if (isActive) classes += " active";
    if (isSelected) classes += " selected";
    if (c.deletedAt) classes += " deleted";
    if (c.status === "snoozed") classes += " mesa-conv--snoozed";
    if (unreadIds.has(c.id)) classes += " mesa-conv--unread";
    if (convsNuevasEnVivo.has(c.id)) classes += " is-new";

    let meta = `<span class="mesa-status-dot ${esc(c.status)}"></span>`;
    if (c.to) meta += `<span class="mesa-tag mesa-tag-alias">${esc(c.to.split("@")[0])}</span>`;
    if (c.deletedAt) meta += `<span class="mesa-tag mesa-tag-deleted">eliminado</span>`;
    if (c.priority === "urgent") meta += `<span class="mesa-tag mesa-tag-urgent">urgente</span>`;
    if (c.status === "snoozed" && c.snoozedUntil) {
      const hasta = new Date(c.snoozedUntil);
      meta += `<span class="mesa-tag mesa-tag-snoozed">💤 ${esc(hasta.toLocaleString("es-MX", { dateStyle: "short", timeStyle: "short" }))}</span>`;
    }
    if (c.assignedTo) meta += `<span class="mesa-tag mesa-tag-assigned">${esc(c.assignedTo.split("@")[0])}</span>`;

    const puntoPresencia = presencias.some(p => p.conversationId === c.id && p.email !== currentUser?.email)
      ? `<span class="mesa-presence-dot" title="Alguien más está en este hilo"></span>` : "";
    if (seleccionadas.has(c.id)) classes += " mesa-conv--marcada";
    return `<div class="${classes}" data-idx="${i}" data-id="${esc(c.id)}">
      <label class="mesa-conv-check" title="Marcar (x)">
        <input type="checkbox" ${seleccionadas.has(c.id) ? "checked" : ""} tabindex="-1">
      </label>
      <div class="mesa-avatar">${esc(initials)}</div>
      <div class="mesa-conv-body">
        <div class="mesa-conv-header">
          <span class="mesa-conv-from">${esc(c.from)}</span>
          <span class="mesa-conv-time">${puntoPresencia}${esc(time)}</span>
        </div>
        <div class="mesa-conv-subject">${esc(c.subject)}</div>
        ${c.snippet ? `<div class="mesa-conv-snippet">${resaltar(c.snippet)}</div>` : ""}
        <div class="mesa-conv-meta">${meta}</div>
      </div>
    </div>`;
  }
}

/**
 * Marca cuál fila está abierta y cuál tiene el cursor de teclado, tocando sólo
 * las clases. Antes esto pasaba por renderList y por eso toda la lista parpadeaba
 * al seleccionar una conversación.
 */
function actualizarSeleccion() {
  document.querySelectorAll("#conv-list .mesa-conv").forEach((el) => {
    const idx = parseInt(el.dataset.idx);
    el.classList.toggle("active", el.dataset.id === activeConv?.id);
    el.classList.toggle("selected", idx === selectedIdx);
  });
}

// Un solo listener delegado en el contenedor: así reemplazar una fila suelta no
// obliga a volver a enganchar nada.
function engancharClicksLista() {
  const container = document.getElementById("conv-list");
  if (!container || container.dataset.clicks) return;
  container.dataset.clicks = "1";
  container.addEventListener("click", (ev) => {
    const fila = ev.target.closest(".mesa-conv");
    if (!fila || !container.contains(fila)) return;
    const idx = parseInt(fila.dataset.idx);
    if (Number.isNaN(idx) || !conversations[idx]) return;

    // Marcar no es abrir: la casilla se queda con el click.
    if (ev.target.closest(".mesa-conv-check")) {
      ev.preventDefault();
      alternarMarcada(idx, ev.shiftKey);
      return;
    }
    selectedIdx = idx;
    openConversation(conversations[idx]);
  });
}

/**
 * Marca o desmarca una fila. Con shift extiende desde la última marcada, que es
 * lo que uno espera al limpiar una bandeja entera.
 */
function alternarMarcada(idx, conShift) {
  const conv = conversations[idx];
  if (!conv) return;

  if (conShift && ultimaMarcada >= 0 && ultimaMarcada !== idx) {
    const desde = Math.min(ultimaMarcada, idx);
    const hasta = Math.max(ultimaMarcada, idx);
    // El rango se marca entero, sin alternar una por una: si ya estaban marcadas
    // se quedan, que es como se comporta cualquier lista con shift.
    for (let i = desde; i <= hasta; i++) {
      if (conversations[i]) seleccionadas.add(conversations[i].id);
    }
  } else if (seleccionadas.has(conv.id)) {
    seleccionadas.delete(conv.id);
  } else {
    seleccionadas.add(conv.id);
  }

  ultimaMarcada = idx;
  renderList();
  renderBarraSeleccion();
}

function limpiarSeleccion() {
  seleccionadas.clear();
  ultimaMarcada = -1;
  renderList();
  renderBarraSeleccion();
}

function renderBarraSeleccion() {
  const barra = document.getElementById("bulk-bar");
  if (!barra) return;
  const n = seleccionadas.size;
  barra.classList.toggle("mesa-hidden", n === 0);
  document.getElementById("bulk-count").textContent =
    `${n} ${n === 1 ? "seleccionada" : "seleccionadas"}`;
}

async function borrarSeleccionadas() {
  const ids = [...seleccionadas];
  if (ids.length === 0) return;
  if (!confirm(`¿Eliminar ${ids.length} conversación${ids.length === 1 ? "" : "es"}? Se mueven a la papelera por 15 días.`)) return;

  const res = await fetch("/api/bandeja/conversations/bulk-delete", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ domainId: selectedDomainId, ids }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    toast(data.error || "No se pudieron eliminar");
    return;
  }
  // Si la abierta iba en el lote, el detalle se queda mostrando algo que ya no está.
  if (activeConv && seleccionadas.has(activeConv.id)) {
    activeConv = null;
    document.getElementById("detail-loaded").classList.add("mesa-hidden");
    document.getElementById("detail-empty").classList.remove("mesa-hidden");
  }
  seleccionadas.clear();
  ultimaMarcada = -1;
  renderBarraSeleccion();
  toast(`${data.deleted} eliminada${data.deleted === 1 ? "" : "s"}`);
  await loadConversations();
}

// --- Open conversation detail ---
// En pantallas angostas la lista y el detalle no caben lado a lado: la clase en
// <body> decide cuál se ve. En escritorio no tiene efecto.
function showMobileDetail(on) {
  document.body.classList.toggle("mesa-mobile-detail", on);
}

async function openConversation(conv) {
  activeConv = conv;
  showMobileDetail(true);
  if (unreadIds.has(conv.id)) {
    // El GET del detalle la marca leída en el servidor; aquí sólo se adelanta la UI.
    unreadIds.delete(conv.id);
    convsNuevasEnVivo.delete(conv.id);
    unreadCount = Math.max(0, unreadCount - 1);
    updateTitle();
    // Quitar la negrita de no leída toca sólo esta fila, no la lista entera.
    renderConvRow(conv.id);
  }
  enviarPresencia(conv.id, "viewing");
  document.getElementById("detail-empty").classList.add("mesa-hidden");
  const loaded = document.getElementById("detail-loaded");
  loaded.classList.remove("mesa-hidden");

  document.getElementById("detail-subject").textContent = conv.subject;
  document.getElementById("detail-from").textContent = conv.from;
  document.getElementById("detail-to").textContent = conv.to;
  document.getElementById("detail-count").textContent = conv.messageCount;

  const isDeleted = !!conv.deletedAt;

  // Show/hide actions based on plan and deleted state
  const composer = document.getElementById("composer");
  const banner = document.getElementById("upgrade-banner");
  const btnReply = document.getElementById("btn-reply");
  const btnAssign = document.getElementById("btn-assign");
  const btnCloseConv = document.getElementById("btn-close-conv");
  const btnUrgent = document.getElementById("btn-urgent");
  const btnDelete = document.getElementById("btn-delete-conv");
  const btnRestore = document.getElementById("btn-restore-conv");

  btnUrgent.classList.toggle("active", conv.priority === "urgent");

  if (isDeleted) {
    composer.classList.add("mesa-hidden");
    banner.classList.add("mesa-hidden");
    btnReply.classList.add("mesa-hidden");
    btnAssign.classList.add("mesa-hidden");
    btnCloseConv.classList.add("mesa-hidden");
    btnUrgent.classList.add("mesa-hidden");
    btnDelete.classList.add("mesa-hidden");
    btnRestore.classList.remove("mesa-hidden");
  } else if (canDoActions) {
    composer.classList.add("mesa-hidden");
    banner.classList.add("mesa-hidden");
    btnReply.classList.remove("mesa-hidden");
    btnAssign.classList.remove("mesa-hidden");
    btnCloseConv.classList.remove("mesa-hidden");
    btnUrgent.classList.remove("mesa-hidden");
    btnDelete.classList.remove("mesa-hidden");
    btnRestore.classList.add("mesa-hidden");
  } else {
    composer.classList.add("mesa-hidden");
    banner.classList.remove("mesa-hidden");
    btnReply.classList.remove("mesa-hidden");
    btnAssign.classList.remove("mesa-hidden");
    btnCloseConv.classList.remove("mesa-hidden");
    btnUrgent.classList.remove("mesa-hidden");
    btnDelete.classList.add("mesa-hidden");
    btnRestore.classList.add("mesa-hidden");
  }

  // Load messages
  const res = await fetch(`/api/bandeja/conversations/${conv.id}?domainId=${selectedDomainId}`);
  if (!res.ok) return;
  const data = await res.json();

  renderMessages(data.messages ?? [], data.notes ?? []);
  actualizarSeleccion();
}

// Estado de entrega de un saliente. Lo alimenta el webhook de eventos de SES
// (delivery / bounce / complaint) cruzado por el id interno del mensaje.
const DELIVERY_LABELS = {
  sent: ["enviado", "⏱"],
  delivered: ["entregado", "✓"],
  bounced: ["rebotó", "✗"],
  complained: ["marcado como spam", "⚠"],
};
function deliveryBadge(msg) {
  const status = msg.deliveryStatus || "sent";
  const [label, icon] = DELIVERY_LABELS[status] || DELIVERY_LABELS.sent;
  const title = msg.deliveryDetail ? ` title="${esc(msg.deliveryDetail)}"` : "";
  return `<span class="mesa-msg-dir outbound delivery-${status}" data-msg-id="${esc(msg.id)}"${title}>${icon} ${label}</span>`;
}

/**
 * El cuerpo de un mensaje. Los entrantes sin texto plano sólo traen HTML, y antes
 * se escapaba: el lector veía las etiquetas. Meterlo con innerHTML sería XSS con
 * correo de desconocidos, así que va en un iframe con `sandbox` vacío —sin
 * allow-scripts y en origen opaco—, que es lo que hacen Gmail y Front.
 *
 * El alto es fijo con scroll propio: ajustarlo al contenido exige un postMessage
 * desde dentro, y dentro no corre JavaScript. Es el precio de no ejecutar nada.
 */
// Qué decirle al lector cuando el original ya no se pudo leer. Son tres cosas
// distintas y antes las tres decían "(Error al cargar el mensaje)".
const AVISOS_CUERPO = {
  index: "Mostramos una versión sin formato ni adjuntos: el original ya no está disponible.",
  gone: "El contenido de este correo ya no está disponible.",
  error: "No pudimos cargar este correo. Vuelve a intentarlo.",
};

function cuerpoMensaje(item) {
  const aviso = AVISOS_CUERPO[item.bodyDegraded]
    ? `<div class="mesa-msg-aviso">${esc(AVISOS_CUERPO[item.bodyDegraded])}</div>`
    : "";
  if (item.bodyDegraded) return aviso + (item.body ? esc(item.body) : "");
  // El HTML manda cuando existe: en un correo sólo-HTML el `body` es texto derivado
  // (etiquetas fuera) y se ve peor que el original en el iframe.
  if (!item.html) return item.body ? esc(item.body) : "";
  // srcdoc escapado: el HTML del correo viaja como atributo, no como marcado.
  return `<iframe class="mesa-msg-html" sandbox referrerpolicy="no-referrer" srcdoc="${esc(item.html)}"></iframe>`;
}

function renderMessages(messages, notes) {
  const container = document.getElementById("messages-container");

  // Interleave messages and notes by time
  const items = [
    ...messages.map((m, i) => ({ ...m, _type: "message", _msgIdx: i })),
    ...notes.map(n => ({ ...n, _type: "note", createdAt: n.createdAt })),
  ].sort((a, b) => a.createdAt.localeCompare(b.createdAt));

  container.innerHTML = items.map(item => {
    if (item._type === "note") {
      return `<div class="mesa-note">
        <div class="mesa-note-header">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
          ${esc(item.author)} &middot; ${formatTime(item.createdAt)}
        </div>
        <div class="mesa-note-body">${esc(item.body)}</div>
      </div>`;
    }

    const dir = item.direction;
    const attachmentsHtml = renderAttachments(item.attachments, item._msgIdx);
    return `<div class="mesa-msg ${dir}">
      <div class="mesa-msg-header">
        <span class="mesa-msg-from">${esc(item.from)}</span>
        ${dir === "inbound" ? `<span class="mesa-msg-dir inbound">recibido</span>` : deliveryBadge(item)}
        <span class="mesa-msg-time">${formatTime(item.createdAt)}</span>
      </div>
      <div class="mesa-msg-body">${cuerpoMensaje(item)}</div>
      ${attachmentsHtml}
    </div>`;
  }).join("");

  // Scroll to bottom
  container.scrollTop = container.scrollHeight;
}

// Separa "a@x.com, b@y.com" en lista. El servidor vuelve a validar cada dirección;
// esto es sólo para no mandar basura evidente.
function splitAddresses(value) {
  return String(value || "")
    .split(/[,;\s]+/)
    .map(v => v.trim())
    .filter(Boolean);
}

// --- Firma del dominio ---

async function openSignatureModal() {
  if (!selectedDomainId) return toast("Selecciona un dominio primero");
  const err = document.getElementById("signature-error");
  err.classList.add("hidden");
  const area = document.getElementById("signature-body");
  area.value = "";
  try {
    const res = await fetch(`/api/domains/${selectedDomainId}`);
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      area.value = data.signature || "";
      pintarLogoFirma(data.signatureLogoKey);
    }
  } catch { /* se abre vacía */ }
  document.getElementById("modal-signature").classList.remove("hidden");
  lockBodyScroll();
  area.focus();
}

/** Muestra la vista previa del logo, o el hueco si no hay. */
function pintarLogoFirma(key) {
  const img = document.getElementById("signature-logo-img");
  const vacio = document.getElementById("signature-logo-empty");
  const quitar = document.getElementById("signature-logo-remove");
  if (!img) return;
  if (key) {
    // Se pide con un parámetro anti-caché: el objeto se sirve como inmutable, y
    // sin esto el navegador seguiría mostrando el logo anterior tras reemplazarlo.
    img.src = `/api/domain-logo/${key}?v=${Date.now()}`;
    img.hidden = false;
    vacio.classList.add("mesa-hidden");
    quitar.classList.remove("mesa-hidden");
  } else {
    img.hidden = true;
    img.removeAttribute("src");
    vacio.classList.remove("mesa-hidden");
    quitar.classList.add("mesa-hidden");
  }
}

async function subirLogoFirma(file) {
  const err = document.getElementById("signature-error");
  err.classList.add("hidden");
  if (!file) return;
  const fd = new FormData();
  fd.append("file", file);
  const res = await fetch(`/api/domains/${selectedDomainId}/logo`, { method: "POST", body: fd });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    err.textContent = data.error || "No se pudo subir el logo";
    err.classList.remove("hidden");
    return;
  }
  // La respuesta trae la URL completa; para la vista previa basta la llave.
  pintarLogoFirma(data.logoUrl.split("/api/domain-logo/")[1]);
  toast("Logo actualizado");
}

async function quitarLogoFirma() {
  const res = await fetch(`/api/domains/${selectedDomainId}/logo`, { method: "DELETE" });
  if (res.ok) {
    pintarLogoFirma(null);
    toast("Logo quitado");
  }
}

async function saveSignature() {
  const err = document.getElementById("signature-error");
  const btn = document.getElementById("signature-save");
  btn.disabled = true;
  try {
    const res = await fetch(`/api/domains/${selectedDomainId}/signature`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ signature: document.getElementById("signature-body").value }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      err.textContent = data.error || "No se pudo guardar";
      err.classList.remove("hidden");
      return;
    }
    closeModal("modal-signature");
    toast("Firma guardada");
  } finally {
    btn.disabled = false;
  }
}

// --- Respuestas guardadas ---

async function openCannedModal() {
  if (!selectedDomainId) return toast("Selecciona un dominio primero");
  document.getElementById("canned-error").classList.add("hidden");
  document.getElementById("canned-title").value = "";
  document.getElementById("canned-body").value = "";
  await renderCannedList();
  document.getElementById("modal-canned").classList.remove("hidden");
  lockBodyScroll();
}

async function renderCannedList() {
  const list = document.getElementById("canned-list");
  list.textContent = "";
  let items = [];
  try {
    items = await loadCannedResponses();
  } catch {
    list.textContent = "No se pudieron cargar.";
    return;
  }
  if (!items.length) {
    const p = document.createElement("p");
    p.className = "mesa-field-label";
    p.textContent = "Todavía no hay ninguna. Agrega la primera abajo.";
    list.appendChild(p);
    return;
  }
  for (const item of items) {
    const fila = document.createElement("div");
    fila.className = "mm-file-chip";
    fila.style.maxWidth = "100%";
    fila.style.marginBottom = "6px";

    const nombre = document.createElement("span");
    nombre.className = "mm-file-name";
    nombre.textContent = item.title;

    const quitar = document.createElement("button");
    quitar.type = "button";
    quitar.className = "mm-file-remove";
    quitar.textContent = "×";
    quitar.title = `Eliminar ${item.title}`;
    quitar.addEventListener("click", async () => {
      await fetch(`/api/domains/${selectedDomainId}/canned/${item.id}`, { method: "DELETE" });
      await renderCannedList();
    });

    fila.append(nombre, quitar);
    list.appendChild(fila);
  }
}

async function saveCanned() {
  const err = document.getElementById("canned-error");
  const title = document.getElementById("canned-title").value.trim();
  const body = document.getElementById("canned-body").value.trim();
  if (!title || !body) {
    err.textContent = "Escribe un título y el contenido.";
    err.classList.remove("hidden");
    return;
  }
  const res = await fetch(`/api/domains/${selectedDomainId}/canned`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ title, body }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    err.textContent = data.error || "No se pudo guardar";
    err.classList.remove("hidden");
    return;
  }
  err.classList.add("hidden");
  document.getElementById("canned-title").value = "";
  document.getElementById("canned-body").value = "";
  await renderCannedList();
  toast("Respuesta guardada");
}

function closeModal(id) {
  const el = document.getElementById(id);
  if (!el || el.classList.contains("hidden")) return;
  el.classList.add("hidden");
  unlockBodyScroll();
}

// --- Actions ---
async function sendReply() {
  if (!activeConv || !canDoActions) return;
  const textarea = document.getElementById("composer-textarea");
  // El editor manda markdown; el servidor lo convierte a HTML de correo. Sin el
  // bundle cargado se cae al textarea y sigue funcionando como texto plano.
  const text = (replyEditor ? replyEditor.getMarkdown() : textarea.value).trim();
  if (!text) return;

  const btn = document.getElementById("btn-send");
  btn.disabled = true;

  if (composerMode === "note") {
    const res = await fetch(`/api/bandeja/conversations/${activeConv.id}/note`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ domainId: selectedDomainId, body: text }),
    });
    btn.disabled = false;
    if (res.ok) {
      // La nota interna no sale por correo: se guarda el markdown tal cual.
      replyEditor ? replyEditor.clear() : (textarea.value = "");
      toast("Nota agregada");
      openConversation(activeConv);
    } else {
      const err = await res.json().catch(() => ({}));
      toast(err.error || "Error al agregar nota");
    }
  } else {
    const res = await fetch(`/api/bandeja/conversations/${activeConv.id}/reply`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        domainId: selectedDomainId,
        markdown: text,
        attachments: replyEditor ? replyEditor.getAttachments() : [],
      }),
    });
    btn.disabled = false;
    if (res.ok) {
      replyEditor ? replyEditor.clear() : (textarea.value = "");
      playSound("whoosh");
      toast("Respuesta enviada");
      openConversation(activeConv);
    } else {
      const err = await res.json().catch(() => ({}));
      toast(err.error || "Error al enviar");
    }
  }
}

async function assignConversation() {
  if (!activeConv || !canDoActions) return;
  document.getElementById("modal-assign").classList.remove("hidden");
  document.getElementById("assign-email").focus();
}

// --- Posponer ---
//
// Las fechas se calculan aquí, con la zona del navegador, y se mandan en ISO UTC:
// "mañana a las 9" tiene que ser su mañana, no la del servidor.

function fechaSnooze(clave) {
  const d = new Date();
  if (clave === "1h") { d.setHours(d.getHours() + 1); return d; }
  if (clave === "tarde") {
    d.setHours(18, 0, 0, 0);
    // Si ya pasaron las seis, "esta tarde" es la de mañana.
    if (d <= new Date()) d.setDate(d.getDate() + 1);
    return d;
  }
  if (clave === "manana") { d.setDate(d.getDate() + 1); d.setHours(9, 0, 0, 0); return d; }
  if (clave === "lunes") {
    const faltan = (8 - d.getDay()) % 7 || 7;
    d.setDate(d.getDate() + faltan);
    d.setHours(9, 0, 0, 0);
    return d;
  }
  return null;
}

function toggleSnoozeMenu(mostrar) {
  const menu = document.getElementById("snooze-menu");
  if (!menu) return;
  menu.classList.toggle("mesa-hidden", mostrar === false ? true : mostrar === true ? false : !menu.classList.contains("mesa-hidden"));
}

async function posponer(hasta) {
  if (!activeConv || !canDoActions) return;
  if (!(hasta instanceof Date) || !Number.isFinite(hasta.getTime())) return;
  if (hasta <= new Date()) { toast("Elige una fecha futura"); return; }
  const res = await fetch(`/api/bandeja/conversations/${activeConv.id}`, {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ domainId: selectedDomainId, status: "snoozed", snoozedUntil: hasta.toISOString() }),
  });
  toggleSnoozeMenu(false);
  if (res.ok) {
    toast(`Pospuesta hasta ${hasta.toLocaleString("es-MX", { dateStyle: "medium", timeStyle: "short" })}`);
    activeConv = null;
    document.getElementById("detail-loaded").classList.add("mesa-hidden");
    document.getElementById("detail-empty").classList.remove("mesa-hidden");
    await loadConversations();
  } else {
    const err = await res.json().catch(() => ({}));
    toast(err.error || "No se pudo posponer");
  }
}

async function closeConversation() {
  if (!activeConv || !canDoActions) return;
  const newStatus = activeConv.status === "closed" ? "open" : "closed";
  const res = await fetch(`/api/bandeja/conversations/${activeConv.id}`, {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ domainId: selectedDomainId, status: newStatus }),
  });
  if (res.ok) {
    toast(newStatus === "closed" ? "Conversación cerrada" : "Conversación reabierta");
    await loadConversations();
    if (activeConv) openConversation({ ...activeConv, status: newStatus });
  } else {
    const err = await res.json().catch(() => ({ error: "Error al actualizar" }));
    toast(err.error || "Error al actualizar");
  }
}

async function deleteConversation() {
  if (!activeConv || !canDoActions) return;
  if (!confirm("¿Eliminar esta conversación? Se moverá a la papelera por 15 días.")) return;
  const res = await fetch(`/api/bandeja/conversations/${activeConv.id}?domainId=${selectedDomainId}`, {
    method: "DELETE",
  });
  if (res.ok) {
    toast("Conversación eliminada");
    activeConv = null;
    document.getElementById("detail-empty").classList.remove("mesa-hidden");
    document.getElementById("detail-loaded").classList.add("mesa-hidden");
    await loadConversations();
  } else {
    const err = await res.json().catch(() => ({}));
    toast(err.error || "Error al eliminar");
  }
}

async function restoreConversationAction() {
  if (!activeConv || !canDoActions) return;
  const res = await fetch(`/api/bandeja/conversations/${activeConv.id}/restore`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ domainId: selectedDomainId }),
  });
  if (res.ok) {
    toast("Conversación restaurada");
    activeConv = null;
    document.getElementById("detail-empty").classList.remove("mesa-hidden");
    document.getElementById("detail-loaded").classList.add("mesa-hidden");
    await loadConversations();
  } else {
    const err = await res.json().catch(() => ({}));
    toast(err.error || "Error al restaurar");
  }
}

async function toggleUrgent() {
  if (!activeConv || !canDoActions) return;
  const newPriority = activeConv.priority === "urgent" ? "normal" : "urgent";
  const res = await fetch(`/api/bandeja/conversations/${activeConv.id}`, {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ domainId: selectedDomainId, priority: newPriority }),
  });
  if (res.ok) {
    if (newPriority === "urgent") playSound("urgent");
    toast(newPriority === "urgent" ? "Marcada como urgente" : "Prioridad normal");
    activeConv.priority = newPriority;
    document.getElementById("btn-urgent").classList.toggle("active", newPriority === "urgent");
    await loadConversations();
  } else {
    const err = await res.json().catch(() => ({ error: "Error al actualizar" }));
    toast(err.error || "Error al actualizar");
  }
}

// --- Event listeners ---
function setupListeners() {
  document.getElementById("btn-logout").addEventListener("click", async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    window.location.href = "/login";
  });

  document.getElementById("domain-select").addEventListener("change", (e) => {
    selectedDomainId = e.target.value;
    try { localStorage.setItem("bandeja.domainId", selectedDomainId); } catch {}
    activeConv = null;
    selectedIdx = -1;
    unreadIds.clear();
    convsNuevasEnVivo.clear();
    seleccionadas.clear();
    ultimaMarcada = -1;
    renderBarraSeleccion();
    unreadCount = 0;
    updateTitle();
    document.getElementById("detail-empty").classList.remove("mesa-hidden");
    document.getElementById("detail-loaded").classList.add("mesa-hidden");
    loadAliasesForCompose();
    loadConversations();
    connectSSE(selectedDomainId);
  });

  // Los tres filtros van al servidor: recargan la primera página en vez de
  // recortar en cliente un array que ya no es la lista completa.
  document.getElementById("status-filter").addEventListener("change", () => {
    loadConversations();
  });

  document.getElementById("alias-filter").addEventListener("change", () => {
    loadConversations();
  });

  // Debounce: sin esto, escribir "factura" son siete consultas con su búsqueda
  // de texto completo cada una.
  let temporizadorBusqueda = null;
  const campoBusqueda = document.getElementById("search-input");
  campoBusqueda.addEventListener("input", () => {
    actualizarBotonLimpiar();
    clearTimeout(temporizadorBusqueda);
    temporizadorBusqueda = setTimeout(() => loadConversations(), 300);
  });
  // Escape limpia y vuelve a la lista completa. Sin esto había que borrar a mano
  // letra por letra para hacer la siguiente búsqueda.
  campoBusqueda.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") {
      ev.stopPropagation();
      if (campoBusqueda.value) limpiarBusqueda();
      else campoBusqueda.blur();
    }
  });
  document.getElementById("search-clear")?.addEventListener("click", limpiarBusqueda);
  document.getElementById("empty-clear-search")?.addEventListener("click", limpiarBusqueda);

  const btnMas = document.getElementById("btn-load-more");
  if (btnMas) btnMas.addEventListener("click", () => loadConversations({ append: true }));

  document.getElementById("btn-reply").addEventListener("click", () => abrirCompositor("reply"));

  document.getElementById("btn-assign").addEventListener("click", assignConversation);
  document.getElementById("bulk-all")?.addEventListener("click", () => {
    // "Visibles" es literal: sólo la página cargada. Marcar lo que no se ha
    // traído sería prometer un borrado que el tope de 200 no puede cumplir.
    for (const c of conversations) seleccionadas.add(c.id);
    renderList();
    renderBarraSeleccion();
  });
  document.getElementById("bulk-none")?.addEventListener("click", limpiarSeleccion);
  document.getElementById("bulk-delete")?.addEventListener("click", borrarSeleccionadas);
  document.getElementById("tab-bandeja").addEventListener("click", () => mostrarPestana("bandeja"));
  document.getElementById("tab-metrics").addEventListener("click", () => mostrarPestana("metrics"));
  document.getElementById("metrics-range").addEventListener("change", cargarMetricas);
  document.getElementById("btn-close-conv").addEventListener("click", closeConversation);
  const btnSnooze = document.getElementById("btn-snooze");
  if (btnSnooze) {
    btnSnooze.addEventListener("click", (ev) => { ev.stopPropagation(); toggleSnoozeMenu(); });
    document.querySelectorAll("#snooze-menu [data-snooze]").forEach(b => {
      b.addEventListener("click", () => posponer(fechaSnooze(b.dataset.snooze)));
    });
    const custom = document.getElementById("snooze-custom");
    if (custom) custom.addEventListener("change", () => { if (custom.value) posponer(new Date(custom.value)); });
    document.addEventListener("click", (ev) => {
      if (!ev.target.closest(".mesa-snooze-wrap")) toggleSnoozeMenu(false);
    });
  }
  document.getElementById("btn-urgent").addEventListener("click", toggleUrgent);
  document.getElementById("btn-delete-conv").addEventListener("click", deleteConversation);
  document.getElementById("btn-restore-conv").addEventListener("click", restoreConversationAction);
  document.getElementById("btn-send").addEventListener("click", sendReply);

  // Firma, respuestas guardadas y el desplegable de Cc/Cco.
  document.getElementById("btn-signature").addEventListener("click", openSignatureModal);
  const inputLogo = document.getElementById("signature-logo-file");
  if (inputLogo) {
    inputLogo.addEventListener("change", () => {
      subirLogoFirma(inputLogo.files?.[0]);
      // Sin esto, volver a elegir el MISMO archivo no dispara `change`.
      inputLogo.value = "";
    });
  }
  document.getElementById("signature-logo-remove")?.addEventListener("click", quitarLogoFirma);
  document.getElementById("signature-cancel").addEventListener("click", () => closeModal("modal-signature"));
  document.getElementById("signature-save").addEventListener("click", saveSignature);

  document.getElementById("btn-canned").addEventListener("click", openCannedModal);
  document.getElementById("canned-close").addEventListener("click", () => closeModal("modal-canned"));
  document.getElementById("canned-save").addEventListener("click", saveCanned);

  document.getElementById("compose-copy-toggle").addEventListener("click", () => {
    const row = document.getElementById("compose-copy-row");
    row.hidden = !row.hidden;
    if (!row.hidden) document.getElementById("compose-cc").focus();
  });

  // Composer mode toggle
  document.getElementById("mode-reply").addEventListener("click", () => {
    composerMode = "reply";
    updateComposerMode();
  });
  document.getElementById("mode-note").addEventListener("click", () => {
    composerMode = "note";
    updateComposerMode();
  });

  // Ctrl+Enter to send
  document.getElementById("btn-back")?.addEventListener("click", () => {
    showMobileDetail(false);
  });

  document.getElementById("composer-textarea").addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      sendReply();
    }
  });

  // Compose modal
  document.getElementById("btn-compose").addEventListener("click", openComposeModal);
  document.getElementById("compose-cancel").addEventListener("click", closeComposeModal);
  document.getElementById("compose-send").addEventListener("click", sendNew);
  document.getElementById("compose-body").addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); sendNew(); }
  });

  // Assign modal
  document.getElementById("assign-cancel").addEventListener("click", () => {
    const el = document.getElementById("modal-assign");
    if (el.classList.contains("hidden")) return;
    el.classList.add("hidden");
    unlockBodyScroll();
  });
  document.getElementById("assign-confirm").addEventListener("click", async () => {
    const email = document.getElementById("assign-email").value.trim();
    if (!email || !activeConv) return;
    const res = await fetch(`/api/bandeja/conversations/${activeConv.id}/assign`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ domainId: selectedDomainId, assignedTo: email }),
    });
    document.getElementById("modal-assign").classList.add("hidden");
    if (res.ok) {
      toast(`Asignada a ${email}`);
      await loadConversations();
    } else {
      const err = await res.json().catch(() => ({}));
      toast(err.error || "Error al asignar");
    }
  });

  // Click outside modal to close
  document.getElementById("modal-assign").addEventListener("click", (e) => {
    if (e.target === e.currentTarget) {
      e.currentTarget.classList.add("hidden");
    }
  });

  // Welcome toast
  const params = new URLSearchParams(window.location.search);
  if (params.get("welcome") === "1") {
    toast("Bienvenido a Bandeja");
    window.history.replaceState({}, "", "/bandeja");
  }
}

// El compositor estorba para leer: nace plegado y se abre con Responder / Nota
// (botón o tecla). Al cambiar de hilo o enviar vuelve a plegarse.
function abrirCompositor(mode) {
  composerMode = mode;
  document.getElementById("composer").classList.remove("mesa-hidden");
  updateComposerMode();
  replyEditor ? replyEditor.focus() : document.getElementById("composer-textarea").focus();
}

function updateComposerMode() {
  const replyBtn = document.getElementById("mode-reply");
  const noteBtn = document.getElementById("mode-note");
  const sendBtn = document.getElementById("btn-send");
  const textarea = document.getElementById("composer-textarea");

  if (composerMode === "note") {
    replyBtn.classList.remove("active");
    noteBtn.classList.add("active");
    sendBtn.classList.add("note-mode");
    sendBtn.textContent = "Agregar nota";
    textarea.placeholder = "Nota interna (solo visible para tu equipo)...";
  } else {
    replyBtn.classList.add("active");
    noteBtn.classList.remove("active");
    sendBtn.classList.remove("note-mode");
    sendBtn.textContent = "Enviar";
    textarea.placeholder = "Escribe tu respuesta...";
  }
}

// --- Keyboard shortcuts ---
function setupKeyboard() {
  document.addEventListener("keydown", (e) => {
    // 🔴 El compositor es Tiptap: reemplaza el <textarea> por un <div
    // contenteditable, así que mirar sólo el tagName dejaba pasar TODOS los
    // atajos mientras se escribía una respuesta. Escribir "Ap" disparaba
    // asignar y redactar. `isContentEditable` es lo que cubre ese caso; el
    // closest cubre escribir dentro de un hijo del editor (negritas, enlaces).
    const el = e.target;
    const tag = el.tagName;
    const isTyping =
      tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" ||
      el.isContentEditable === true ||
      !!el.closest?.("[contenteditable='true'], .ProseMirror");

    if (e.key === "Escape") {
      // Close modal if open
      const composeModal = document.getElementById("modal-compose");
      if (composeModal && !composeModal.classList.contains("hidden")) {
        closeComposeModal();
        return;
      }
      const modal = document.getElementById("modal-assign");
      if (!modal.classList.contains("hidden")) {
        modal.classList.add("hidden");
        return;
      }
      // Blur composer
      if (isTyping) {
        e.target.blur();
        return;
      }
      // Plegar el compositor antes de soltar el hilo
      const comp = document.getElementById("composer");
      if (comp && !comp.classList.contains("mesa-hidden")) {
        comp.classList.add("mesa-hidden");
        return;
      }
      // Deselect conversation
      if (activeConv) {
        activeConv = null;
        document.getElementById("detail-empty").classList.remove("mesa-hidden");
        document.getElementById("detail-loaded").classList.add("mesa-hidden");
        actualizarSeleccion();
        return;
      }
    }

    if (isTyping) return;

    // Con el modal abierto, el foco puede estar en el body (por ejemplo tras hacer click
    // en el título). Sin esto, teclear una "c" mientras se escribe reabriría el modal y
    // borraría el borrador.
    const composeOpen = !document.getElementById("modal-compose")?.classList.contains("hidden");
    const assignOpen = !document.getElementById("modal-assign")?.classList.contains("hidden");
    if (composeOpen || assignOpen) return;

    if (e.key === "j") {
      e.preventDefault();
      const filtered = getFilteredConversations();
      if (selectedIdx < filtered.length - 1) {
        selectedIdx++;
        actualizarSeleccion();
        scrollToSelected();
      } else if (nextCursor) {
        // Al final de la página cargada: traer la siguiente sin que el usuario
        // tenga que soltar el teclado para ir al botón.
        loadConversations({ append: true }).then(() => {
          if (selectedIdx < conversations.length - 1) {
            selectedIdx++;
            actualizarSeleccion();
            scrollToSelected();
          }
        });
      }
    }
    if (e.key === "k") {
      e.preventDefault();
      if (selectedIdx > 0) {
        selectedIdx--;
        actualizarSeleccion();
        scrollToSelected();
      }
    }
    if (e.key === "o" || e.key === "Enter") {
      e.preventDefault();
      const filtered = getFilteredConversations();
      if (selectedIdx >= 0 && selectedIdx < filtered.length) {
        openConversation(filtered[selectedIdx]);
      }
    }
    if (e.key === "r" && canDoActions) {
      e.preventDefault();
      abrirCompositor("reply");
    }
    if (e.key === "c") {
      e.preventDefault();
      openComposeModal();
      return;
    }
    if (e.key === "n" && canDoActions) {
      e.preventDefault();
      abrirCompositor("note");
    }
    if (e.key === "a" && canDoActions) {
      e.preventDefault();
      assignConversation();
    }
    if (e.key === "e" && canDoActions) {
      e.preventDefault();
      closeConversation();
    }
    if (e.key === "x" && canDoActions) {
      e.preventDefault();
      if (selectedIdx >= 0) alternarMarcada(selectedIdx, e.shiftKey);
      return;
    }
    if (e.key === "s" && canDoActions && activeConv) {
      e.preventDefault();
      toggleSnoozeMenu();
    }
    if (e.key === "#" && canDoActions) {
      e.preventDefault();
      // Con filas marcadas, eliminar es eliminar esas: borrar sólo la abierta
      // ignorando una selección visible sería obedecer a medias.
      if (seleccionadas.size > 0) borrarSeleccionadas();
      else deleteConversation();
    }
    if (e.key === "/") {
      e.preventDefault();
      document.getElementById("search-input").focus();
    }
  });
}

// Antes esto duplicaba la lógica de filtro de renderList, con el resultado de
// que j/k podían recorrer una lista distinta de la que se veía en pantalla.
// Ahora ambos leen el mismo array, que es lo que el servidor mandó.
// El fragmento llega del servidor en TEXTO PLANO a propósito: insertar HTML
// venido del servidor —aunque sea nuestro— dentro de contenido de un correo
// ajeno es la vía corta a un XSS. Se escapa todo y el resaltado se arma aquí,
// sobre los términos que el usuario tecleó.
function resaltar(fragmento) {
  const consulta = document.getElementById("search-input").value.trim();
  let salida = esc(fragmento);
  if (!consulta) return salida;
  const terminos = consulta.split(/\s+/).filter(t => t.length > 1);
  for (const t of terminos) {
    const escapado = esc(t).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    salida = salida.replace(new RegExp(escapado, "gi"), m => `<mark>${m}</mark>`);
  }
  return salida;
}

function getFilteredConversations() {
  return conversations;
}

function scrollToSelected() {
  const items = document.querySelectorAll(".mesa-conv");
  if (items[selectedIdx]) {
    items[selectedIdx].scrollIntoView({ block: "nearest" });
  }
}

// --- Attachments ---
function renderAttachments(attachments, msgIdx) {
  if (!attachments || attachments.length === 0) return "";
  const chips = attachments.map(att => {
    const url = `/api/bandeja/conversations/${activeConv.id}/attachments/${msgIdx}/${att.index}?domainId=${selectedDomainId}`;
    const isImage = att.contentType.startsWith("image/");
    const icon = isImage
      ? `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/></svg>`
      : `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>`;
    const sizeKb = Math.round(att.size / 1024) || 1;
    const preview = isImage ? `<img class="mesa-att-preview" src="${esc(url)}" alt="${esc(att.filename)}" loading="lazy">` : "";
    return `<a class="mesa-att-chip" href="${esc(url)}" target="_blank" title="${esc(att.filename)}">
      ${icon}
      <span class="mesa-att-name">${esc(att.filename)}</span>
      <span class="mesa-att-size">${sizeKb}KB</span>
    </a>${preview}`;
  }).join("");
  return `<div class="mesa-attachments">${chips}</div>`;
}

// --- Helpers ---
function formatTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  const now = new Date();
  const diff = now.getTime() - d.getTime();

  if (diff < 60000) return "ahora";
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h`;
  if (diff < 604800000) return `${Math.floor(diff / 86400000)}d`;
  return d.toLocaleDateString("es-MX", { month: "short", day: "numeric" });
}

function toast(msg) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 2500);
}

function updateTitle() {
  document.title = unreadCount > 0 ? `(${unreadCount}) Bandeja` : "Bandeja";
}

let audioCtx = null;
document.addEventListener("click", () => {
  if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  if (audioCtx.state === "suspended") audioCtx.resume();
});

function playNotifSound() {
  if (!audioCtx || audioCtx.state !== "running") return;
  const osc = audioCtx.createOscillator();
  const gain = audioCtx.createGain();
  osc.type = "sine";
  osc.frequency.value = 800;
  gain.gain.value = 0.15;
  osc.connect(gain);
  gain.connect(audioCtx.destination);
  osc.start();
  gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.1);
  osc.stop(audioCtx.currentTime + 0.1);
}

function playSound(type) {
  if (!audioCtx || audioCtx.state !== "running") return;
  const t = audioCtx.currentTime;
  if (type === "whoosh") {
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
  } else if (type === "urgent") {
    // Two quick high beeps — alarm feel
    [0, 0.1].forEach(offset => {
      const o = audioCtx.createOscillator(), g = audioCtx.createGain();
      o.type = "square";
      o.frequency.value = 880;
      g.gain.value = 0.1;
      o.connect(g); g.connect(audioCtx.destination);
      o.start(t + offset);
      g.gain.exponentialRampToValueAtTime(0.001, t + offset + 0.06);
      o.stop(t + offset + 0.06);
    });
  }
}

// --- Parche puntual de una fila ---
//
// Ninguna mutación que llega por SSE recarga la lista: recargar reordena, pierde
// la posición del cursor de teclado y desperdicia una consulta. Se parchea el
// objeto local y se repinta su fila.

function patchConv(id, fields) {
  const c = conversations.find(x => x.id === id);
  if (!c) return null;
  Object.assign(c, fields);
  if (activeConv && activeConv.id === id) Object.assign(activeConv, fields);
  return c;
}

/** Quita una fila con transición, sin recargar la lista. */
function removerFila(id) {
  const idx = conversations.findIndex(c => c.id === id);
  if (idx < 0) return;
  conversations.splice(idx, 1);
  const el = document.querySelector(`.mesa-conv[data-id="${CSS.escape(id)}"]`);
  if (el) {
    el.classList.add("mesa-conv--saliendo");
    setTimeout(() => renderList(), 200);
  } else {
    renderList();
  }
}

/**
 * Repinta una sola fila. Si la conversación ya no pasa el filtro activo —cerraste
 * un hilo mientras alguien mira "Abiertas"— se quita en vez de recargar.
 */
function renderConvRow(id) {
  const c = conversations.find(x => x.id === id);
  if (!c) return;
  const filtroEstado = document.getElementById("status-filter")?.value || "";
  const fuera = filtroEstado && filtroEstado !== "unread" && filtroEstado !== "deleted" && c.status !== filtroEstado;
  if (fuera) { removerFila(id); return; }

  const el = document.querySelector(`#conv-list .mesa-conv[data-id="${CSS.escape(id)}"]`);
  if (!el) { renderList(); return; }
  // Sólo esta fila. El índice se conserva del DOM para no desalinear j/k.
  el.outerHTML = convRowHtml(c, parseInt(el.dataset.idx));
  actualizarSeleccion();
}

// --- Presencia (detección de colisión) ---

let ultimoTyping = 0;
let latidoPresencia = null;

function enviarPresencia(conversationId, state) {
  if (!selectedDomainId) return;
  fetch("/api/bandeja/presence", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ domainId: selectedDomainId, conversationId, state }),
  }).catch(() => {});
}

/** El typing se manda con acelerador de 5s, no por tecla. */
function marcarEscribiendo() {
  const ahora = Date.now();
  if (ahora - ultimoTyping < 5000) return;
  ultimoTyping = ahora;
  if (activeConv) enviarPresencia(activeConv.id, "typing");
}

function iniciarLatidoPresencia() {
  if (latidoPresencia) clearInterval(latidoPresencia);
  // 15s contra un TTL de 35s: aguanta que se pierda un latido sin parpadear.
  latidoPresencia = setInterval(() => {
    if (activeConv && document.visibilityState === "visible") {
      enviarPresencia(activeConv.id, "viewing");
    }
  }, 15000);
}

// Conversaciones donde ahora mismo hay OTRA persona. Se recuerda entre eventos
// para repintar sólo lo que cambió: el latido llega cada 15 s y casi siempre trae
// lo mismo, así que repintar por recibirlo hacía parpadear la lista sola.
let convsConPresencia = new Set();

function aplicarPresenciaEnLista() {
  const ahora = new Set(
    presencias
      .filter(p => p.conversationId && p.email !== currentUser?.email)
      .map(p => p.conversationId)
  );
  const cambiadas = new Set([...ahora, ...convsConPresencia]);
  for (const id of cambiadas) {
    if (ahora.has(id) !== convsConPresencia.has(id)) renderConvRow(id);
  }
  convsConPresencia = ahora;
}

function renderPresence() {
  const barra = document.getElementById("presence-bar");
  if (!barra) return;
  const otros = presencias.filter(p =>
    p.email !== currentUser?.email && activeConv && p.conversationId === activeConv.id);
  if (otros.length === 0) {
    barra.classList.add("mesa-hidden");
    barra.textContent = "";
    return;
  }
  // Escribiendo gana sobre viendo: es el aviso que de verdad evita la colisión.
  const escribiendo = otros.filter(p => p.state === "typing");
  const nombres = (lista) => lista.map(p => esc(p.name || p.email.split("@")[0])).join(", ");
  barra.innerHTML = escribiendo.length
    ? `<span class="mesa-presence-typing">✍️ ${nombres(escribiendo)} ${escribiendo.length > 1 ? "están" : "está"} escribiendo<span class="mesa-dots"><i></i><i></i><i></i></span></span>`
    : `<span>👁 ${nombres(otros)} también ${otros.length > 1 ? "están viendo" : "está viendo"} este hilo</span>`;
  barra.classList.remove("mesa-hidden");
}

// --- Métricas del equipo ---
//
// Sin librería de gráficas: son barras con divs y un alto en porcentaje. Meter
// una dependencia de 200 KB para treinta barras no se paga.

/**
 * Gráfica de área en SVG, sin librería.
 *
 * `viewBox` con `preserveAspectRatio="none"` deja que el SVG se estire con el
 * contenedor: no hay que medir nada en JS ni recalcular al cambiar el tamaño de
 * la ventana. El eje X va de 0 a 100 y el Y de 0 a 100 invertido.
 */
function graficaArea(porDia) {
  if (!porDia || porDia.length === 0) return "";

  const tope = Math.max(...porDia.map(d => d.entrantes + d.salientes));
  if (tope === 0) {
    // Una línea plana en cero parece un error de carga. Mejor decirlo.
    return `<p class="mesa-metric-note">Sin correo en este periodo.</p>`;
  }

  const n = porDia.length;
  // Con un solo día no hay pendiente que dibujar; se reparte igual y sale una
  // banda plana, que es lo correcto.
  const x = (i) => (n === 1 ? 50 : (i / (n - 1)) * 100);
  const y = (v) => 100 - (v / tope) * 100;

  const linea = (valor) => porDia.map((d, i) => `${x(i).toFixed(2)},${y(valor(d)).toFixed(2)}`).join(" ");
  const area = (valor) => `M0,100 L${linea(valor)} L100,100 Z`;

  // Apiladas: la de arriba es el total, la de abajo sólo los entrantes. Dibujar
  // el total primero y los entrantes encima da el efecto de pila sin recortes.
  const total = (d) => d.entrantes + d.salientes;
  const entrantes = (d) => d.entrantes;

  const puntos = porDia.map((d, i) => {
    const t = total(d);
    if (t === 0) return "";
    return `<circle cx="${x(i).toFixed(2)}" cy="${y(t).toFixed(2)}" r="1.6" class="mesa-chart-dot">
      <title>${esc(formatoDiaCorto(d.dia))}: ${d.entrantes} recibidos, ${d.salientes} enviados</title>
    </circle>`;
  }).join("");

  return `
    <div class="mesa-chart-legend">
      <span><i class="mesa-swatch mesa-swatch-in"></i>Recibidos</span>
      <span><i class="mesa-swatch mesa-swatch-out"></i>Enviados</span>
      <span class="mesa-chart-max">máx. ${tope} al día</span>
    </div>
    <svg class="mesa-chart-svg" viewBox="0 0 100 100" preserveAspectRatio="none" role="img"
         aria-label="Correo recibido y enviado por día">
      <path class="mesa-area-out" d="${area(total)}"></path>
      <path class="mesa-area-in" d="${area(entrantes)}"></path>
      <polyline class="mesa-line-out" points="${linea(total)}"></polyline>
      <polyline class="mesa-line-in" points="${linea(entrantes)}"></polyline>
      ${puntos}
    </svg>
    <div class="mesa-chart-axis">
      <span>${esc(formatoDiaCorto(porDia[0].dia))}</span>
      <span>${esc(formatoDiaCorto(porDia[porDia.length - 1].dia))}</span>
    </div>`;
}

/** "2026-09-06" → "6 sep". Con 90 días no caben 90 etiquetas, sólo los extremos. */
function formatoDiaCorto(iso) {
  const [a, m, d] = String(iso).split("-").map(Number);
  if (!a || !m || !d) return iso;
  // Se construye en local con el día ya partido: `new Date("2026-09-06")` se
  // interpreta en UTC y en México mostraría el día anterior.
  return new Date(a, m - 1, d).toLocaleDateString("es-MX", { day: "numeric", month: "short" });
}

function minutosLegibles(m) {
  if (m === null || m === undefined) return "—";
  if (m < 60) return `${m} min`;
  if (m < 60 * 24) return `${(m / 60).toFixed(1)} h`;
  return `${(m / 1440).toFixed(1)} días`;
}

// Lo que sólo sirve para la lista y estorba en Métricas. El selector de dominio
// NO va aquí: las métricas son por dominio, así que ahí sigue haciendo falta.
const SOLO_LISTA = [
  "status-filter", "alias-filter", "conv-count",
  "search-input", "search-clear", "bulk-bar", "search-notice",
];

function mostrarPestana(cual) {
  const enMetricas = cual === "metrics";
  document.querySelector(".mesa-main").classList.toggle("mesa-hidden", enMetricas);
  document.getElementById("metrics-pane").classList.toggle("mesa-hidden", !enMetricas);
  document.getElementById("tab-bandeja").classList.toggle("active", !enMetricas);
  document.getElementById("tab-metrics").classList.toggle("active", enMetricas);

  // La barra de atajos se veía en Métricas y ninguno de esos atajos funciona ahí:
  // anunciar teclas muertas es peor que no anunciarlas.
  document.querySelector(".mesa-shortcuts")?.classList.toggle("mesa-hidden", enMetricas);
  document.querySelector(".mesa-search-wrap")?.classList.toggle("mesa-hidden", enMetricas);
  for (const id of SOLO_LISTA) {
    const el = document.getElementById(id);
    if (!el) continue;
    if (enMetricas) {
      // Se recuerda si ya estaba oculto por su cuenta (la barra de selección, el
      // aviso del índice) para no revelarlo al volver.
      el.dataset.ocultoAntes = el.classList.contains("mesa-hidden") ? "1" : "";
      el.classList.add("mesa-hidden");
    } else if (el.dataset.ocultoAntes !== "1") {
      el.classList.remove("mesa-hidden");
    }
  }

  if (enMetricas) cargarMetricas();
}

async function cargarMetricas() {
  if (!selectedDomainId) return;
  const dias = document.getElementById("metrics-range").value;
  const res = await fetch(`/api/bandeja/metrics?domainId=${encodeURIComponent(selectedDomainId)}&days=${dias}`);
  if (!res.ok) { toast("No se pudieron cargar las métricas"); return; }
  const m = await res.json();

  const tarjeta = (valor, etiqueta, nota) =>
    `<div class="mesa-metric-card"><div class="mesa-metric-value">${esc(valor)}</div>
     <div class="mesa-metric-label">${esc(etiqueta)}</div>
     ${nota ? `<div class="mesa-metric-note">${esc(nota)}</div>` : ""}</div>`;

  document.getElementById("metrics-cards").innerHTML = [
    tarjeta(minutosLegibles(m.primeraRespuesta.medianaMin), "Primera respuesta (mediana)", `${m.primeraRespuesta.contestadas} contestadas`),
    tarjeta(minutosLegibles(m.primeraRespuesta.p90Min), "Primera respuesta (p90)", "9 de cada 10 por debajo"),
    tarjeta(m.totals.sinResponder, "Sin responder", "entraron y nadie contestó"),
    tarjeta(m.totals.abiertasSinAsignar, "Abiertas sin asignar", "de toda la bandeja"),
    tarjeta(m.totals.entrantes, "Correos recibidos"),
    tarjeta(m.totals.salientes, "Respuestas enviadas"),
    tarjeta(minutosLegibles(m.duracionHilo.medianaMin), "Duración del hilo (mediana)", "del primer al último mensaje, no hasta el cierre"),
  ].join("");

  document.getElementById("metrics-chart").innerHTML = graficaArea(m.porDia);

  const cont = document.getElementById("metrics-agents");
  cont.innerHTML = m.porAgente.length === 0
    ? `<p class="mesa-metric-note">Nadie tiene conversaciones asignadas en este periodo.</p>`
    : `<table class="mesa-metrics-table">
        <thead><tr><th>Persona</th><th>Conversaciones</th><th>Respuestas</th></tr></thead>
        <tbody>${m.porAgente.map(a => `<tr><td>${esc(a.agente)}</td><td>${a.conversaciones}</td><td>${a.respuestas}</td></tr>`).join("")}</tbody>
       </table>
       <p class="mesa-metric-note">Se cuenta por conversación asignada: al responder, el remitente es el alias del dominio, no la persona.</p>`;
}

// --- SSE for real-time updates ---

let sseSource = null;

function connectSSE(domainId) {
  if (sseSource) { sseSource.close(); sseSource = null; }
  if (!domainId) return;

  sseSource = new EventSource(`/api/bandeja/sse?domainId=${encodeURIComponent(domainId)}`);

  sseSource.addEventListener("new_conversation", async (e) => {
    try {
      const data = e.data ? JSON.parse(e.data) : {};
      const convId = data.conversationId;
      if (convId) { unreadIds.add(convId); convsNuevasEnVivo.add(convId); }
      unreadCount++;
      updateTitle();
      await loadConversations();
      const sender = data.from ? data.from.slice(0, 40) : "";
      toast(sender ? `Nueva conversación de ${sender}` : "Nueva conversación");
      playNotifSound();
    } catch (err) {
      console.error("SSE new_conversation error:", err);
      loadConversations();
    }
  });

  sseSource.addEventListener("new_message", async (e) => {
    try {
      const data = JSON.parse(e.data);
      const convId = data.conversationId;
      await loadConversations();
      if (activeConv && activeConv.id === convId) {
        const updated = conversations.find(c => c.id === convId);
        if (updated) openConversation(updated);
      } else {
        if (convId) { unreadIds.add(convId); convsNuevasEnVivo.add(convId); }
        unreadCount++;
        updateTitle();
      }
      const subj = data.subject ? data.subject.slice(0, 40) : "conversación";
      toast(`Nuevo mensaje en: ${subj}`);
      playNotifSound();
    } catch (err) {
      console.error("SSE new_message error:", err);
      loadConversations();
    }
  });

  // Mutaciones de compañeros. Todas traen `actor`: la propia acción ya se reflejó
  // en la UI de quien la hizo, repintarla otra vez sería parpadeo.
  const mio = (d) => d.actor && currentUser && d.actor === currentUser.email;

  sseSource.addEventListener("conv_updated", (e) => {
    try {
      const d = JSON.parse(e.data);
      if (mio(d)) return;
      if (!patchConv(d.conversationId, { status: d.status, priority: d.priority, snoozedUntil: d.snoozedUntil })) return;
      renderConvRow(d.conversationId);
    } catch (err) { console.error("SSE conv_updated:", err); }
  });

  sseSource.addEventListener("conv_assigned", (e) => {
    try {
      const d = JSON.parse(e.data);
      if (mio(d)) return;
      if (!patchConv(d.conversationId, { assignedTo: d.assignedTo || undefined })) return;
      renderConvRow(d.conversationId);
      if (d.assignedTo === currentUser?.email) toast("Te asignaron una conversación");
    } catch (err) { console.error("SSE conv_assigned:", err); }
  });

  sseSource.addEventListener("conv_replied", (e) => {
    try {
      const d = JSON.parse(e.data);
      if (mio(d)) return;
      if (patchConv(d.conversationId, { lastMessageAt: d.lastMessageAt, messageCount: d.messageCount })) {
        // Un compañero contestó: para mí el hilo tiene algo nuevo que no he leído.
        if (!activeConv || activeConv.id !== d.conversationId) {
          unreadIds.add(d.conversationId);
          unreadCount++;
          updateTitle();
        }
        renderConvRow(d.conversationId);
      }
      if (activeConv && activeConv.id === d.conversationId) openConversation(activeConv);
    } catch (err) { console.error("SSE conv_replied:", err); }
  });

  sseSource.addEventListener("conv_note", (e) => {
    try {
      const d = JSON.parse(e.data);
      if (mio(d)) return;
      if (activeConv && activeConv.id === d.conversationId) openConversation(activeConv);
    } catch (err) { console.error("SSE conv_note:", err); }
  });

  sseSource.addEventListener("conv_deleted", (e) => {
    try {
      const d = JSON.parse(e.data);
      if (mio(d)) return;
      if (activeConv && activeConv.id === d.conversationId) {
        activeConv = null;
        document.getElementById("detail-loaded").classList.add("mesa-hidden");
        document.getElementById("detail-empty").classList.remove("mesa-hidden");
        toast("Alguien eliminó esta conversación");
      }
      removerFila(d.conversationId);
    } catch (err) { console.error("SSE conv_deleted:", err); }
  });

  sseSource.addEventListener("convs_deleted", (e) => {
    try {
      const d = JSON.parse(e.data);
      if (mio(d)) return;
      for (const id of d.conversationIds ?? []) {
        if (activeConv && activeConv.id === id) {
          activeConv = null;
          document.getElementById("detail-loaded").classList.add("mesa-hidden");
          document.getElementById("detail-empty").classList.remove("mesa-hidden");
          toast("Alguien eliminó esta conversación");
        }
        removerFila(id);
      }
    } catch (err) { console.error("SSE convs_deleted:", err); }
  });

  sseSource.addEventListener("conv_restored", (e) => {
    try {
      const d = JSON.parse(e.data);
      if (mio(d)) return;
      loadConversations();
    } catch (err) { console.error("SSE conv_restored:", err); }
  });

  sseSource.addEventListener("conv_unsnoozed", (e) => {
    try {
      const d = JSON.parse(e.data);
      // No trae actor: el cron no es de nadie, así que le llega a todo el equipo.
      if (patchConv(d.conversationId, { status: "open", snoozedUntil: undefined })) {
        renderConvRow(d.conversationId);
      } else {
        loadConversations();
      }
      toast(`Volvió: ${(d.subject || "conversación").slice(0, 40)}`);
    } catch (err) { console.error("SSE conv_unsnoozed:", err); }
  });

  sseSource.addEventListener("presence", (e) => {
    try {
      presencias = JSON.parse(e.data).agents || [];
      renderPresence();
      aplicarPresenciaEnLista();
    } catch (err) { console.error("SSE presence:", err); }
  });

  // Estado de entrega: sólo se repinta el badge del mensaje si la conversación está abierta.
  sseSource.addEventListener("delivery_status", (e) => {
    try {
      const data = JSON.parse(e.data);
      if (!activeConv || activeConv.id !== data.conversationId) return;
      const badge = document.querySelector(`.mesa-msg-dir[data-msg-id="${data.messageId}"]`);
      if (!badge) return;
      const status = data.status || badge.className.match(/delivery-(\w+)/)?.[1] || "sent";
      const [label, icon] = DELIVERY_LABELS[status] || DELIVERY_LABELS.sent;
      badge.className = `mesa-msg-dir outbound delivery-${status}`;
      badge.textContent = `${icon} ${label}`;
      if (data.detail) badge.title = data.detail;
      if (data.status === "delivered") playSound("pop");
      else if (data.status === "bounced" || data.status === "complained") toast(`El correo a ${activeConv.from} ${label}`);
    } catch (err) {
      console.error("SSE delivery_status error:", err);
    }
  });

  sseSource.addEventListener("ping", () => {}); // ignore keepalive

  sseSource.onerror = () => {
    sseSource.close();
    sseSource = null;
    // Reconnect after 5s
    setTimeout(() => { if (selectedDomainId) connectSSE(selectedDomainId); }, 5000);
  };
}
