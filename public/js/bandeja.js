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
let canCompose = false;   // redactar correo nuevo requiere el add-on de envíos
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
let newConvIds = new Set();
let unreadCount = 0;

// --- Init ---
document.addEventListener("DOMContentLoaded", async () => {
  await checkAuth();
  await loadDomains();
  setupListeners();
  setupKeyboard();
  mountComposers();
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

  selectedDomainId = domains[0].id;
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
    btn.title = "Necesitas el add-on de envíos para escribir correos nuevos";
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

function renderList() {
  const container = document.getElementById("conv-list");
  const empty = document.getElementById("list-empty");

  // Sin filtrado en cliente: lo que hay en `conversations` es exactamente lo que
  // el servidor devolvió para los filtros activos.
  const filtered = conversations;

  const sufijo = nextCursor ? "+" : "";
  document.getElementById("conv-count").textContent =
    `${filtered.length}${sufijo} ${filtered.length !== 1 ? "conversaciones" : "conversación"}`;

  if (filtered.length === 0) {
    // Clear any rendered items but keep the empty state
    container.querySelectorAll(".mesa-conv").forEach(el => el.remove());
    empty.classList.remove("mesa-hidden");
    return;
  }

  empty.classList.add("mesa-hidden");
  const html = filtered.map((c, i) => {
    const initials = c.from.split("@")[0].slice(0, 2);
    const time = formatTime(c.lastMessageAt);
    const isActive = activeConv?.id === c.id;
    const isSelected = i === selectedIdx;
    let classes = "mesa-conv";
    if (isActive) classes += " active";
    if (isSelected) classes += " selected";
    if (c.deletedAt) classes += " deleted";
    if (newConvIds.has(c.id)) classes += " is-new";

    let meta = `<span class="mesa-status-dot ${esc(c.status)}"></span>`;
    if (c.to) meta += `<span class="mesa-tag mesa-tag-alias">${esc(c.to.split("@")[0])}</span>`;
    if (c.deletedAt) meta += `<span class="mesa-tag mesa-tag-deleted">eliminado</span>`;
    if (c.priority === "urgent") meta += `<span class="mesa-tag mesa-tag-urgent">urgente</span>`;
    if (c.assignedTo) meta += `<span class="mesa-tag mesa-tag-assigned">${esc(c.assignedTo.split("@")[0])}</span>`;

    return `<div class="${classes}" data-idx="${i}">
      <div class="mesa-avatar">${esc(initials)}</div>
      <div class="mesa-conv-body">
        <div class="mesa-conv-header">
          <span class="mesa-conv-from">${esc(c.from)}</span>
          <span class="mesa-conv-time">${esc(time)}</span>
        </div>
        <div class="mesa-conv-subject">${esc(c.subject)}</div>
        ${c.snippet ? `<div class="mesa-conv-snippet">${resaltar(c.snippet)}</div>` : ""}
        <div class="mesa-conv-meta">${meta}</div>
      </div>
    </div>`;
  }).join("");

  // Replace only conversation items, preserve empty state element
  container.querySelectorAll(".mesa-conv").forEach(el => el.remove());
  container.insertAdjacentHTML("beforeend", html);

  // El botón va siempre al final de la lista, después de las filas.
  const btnMas = document.getElementById("btn-load-more");
  if (btnMas) {
    btnMas.classList.toggle("mesa-hidden", !nextCursor);
    container.appendChild(btnMas);
  }

  // Click handlers
  container.querySelectorAll(".mesa-conv").forEach(el => {
    el.addEventListener("click", () => {
      const idx = parseInt(el.dataset.idx);
      selectedIdx = idx;
      openConversation(filtered[idx]);
    });
  });
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
  if (newConvIds.has(conv.id)) {
    newConvIds.delete(conv.id);
    unreadCount = Math.max(0, unreadCount - 1);
    updateTitle();
  }
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
    composer.classList.remove("mesa-hidden");
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
  renderList(); // re-render to highlight active
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
      <div class="mesa-msg-body">${esc(item.body || item.html || "")}</div>
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
    if (res.ok) area.value = data.signature || "";
  } catch { /* se abre vacía */ }
  document.getElementById("modal-signature").classList.remove("hidden");
  lockBodyScroll();
  area.focus();
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
    activeConv = null;
    selectedIdx = -1;
    newConvIds.clear();
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
  document.getElementById("search-input").addEventListener("input", () => {
    clearTimeout(temporizadorBusqueda);
    temporizadorBusqueda = setTimeout(() => loadConversations(), 300);
  });

  const btnMas = document.getElementById("btn-load-more");
  if (btnMas) btnMas.addEventListener("click", () => loadConversations({ append: true }));

  document.getElementById("btn-reply").addEventListener("click", () => {
    composerMode = "reply";
    updateComposerMode();
    replyEditor ? replyEditor.focus() : document.getElementById("composer-textarea").focus();
  });

  document.getElementById("btn-assign").addEventListener("click", assignConversation);
  document.getElementById("btn-close-conv").addEventListener("click", closeConversation);
  document.getElementById("btn-urgent").addEventListener("click", toggleUrgent);
  document.getElementById("btn-delete-conv").addEventListener("click", deleteConversation);
  document.getElementById("btn-restore-conv").addEventListener("click", restoreConversationAction);
  document.getElementById("btn-send").addEventListener("click", sendReply);

  // Firma, respuestas guardadas y el desplegable de Cc/Cco.
  document.getElementById("btn-signature").addEventListener("click", openSignatureModal);
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
    // Skip if typing in input/textarea
    const tag = e.target.tagName;
    const isTyping = tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";

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
      // Deselect conversation
      if (activeConv) {
        activeConv = null;
        document.getElementById("detail-empty").classList.remove("mesa-hidden");
        document.getElementById("detail-loaded").classList.add("mesa-hidden");
        renderList();
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
        renderList();
        scrollToSelected();
      } else if (nextCursor) {
        // Al final de la página cargada: traer la siguiente sin que el usuario
        // tenga que soltar el teclado para ir al botón.
        loadConversations({ append: true }).then(() => {
          if (selectedIdx < conversations.length - 1) {
            selectedIdx++;
            renderList();
            scrollToSelected();
          }
        });
      }
    }
    if (e.key === "k") {
      e.preventDefault();
      if (selectedIdx > 0) {
        selectedIdx--;
        renderList();
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
      composerMode = "reply";
      updateComposerMode();
      replyEditor ? replyEditor.focus() : document.getElementById("composer-textarea").focus();
    }
    if (e.key === "c") {
      e.preventDefault();
      openComposeModal();
      return;
    }
    if (e.key === "n" && canDoActions) {
      e.preventDefault();
      composerMode = "note";
      updateComposerMode();
      replyEditor ? replyEditor.focus() : document.getElementById("composer-textarea").focus();
    }
    if (e.key === "a" && canDoActions) {
      e.preventDefault();
      assignConversation();
    }
    if (e.key === "e" && canDoActions) {
      e.preventDefault();
      closeConversation();
    }
    if (e.key === "#" && canDoActions) {
      e.preventDefault();
      deleteConversation();
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
      if (convId) newConvIds.add(convId);
      unreadCount++;
      updateTitle();
      await loadConversations();
      renderList();
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
        if (convId) newConvIds.add(convId);
        unreadCount++;
        updateTitle();
        renderList();
      }
      const subj = data.subject ? data.subject.slice(0, 40) : "conversación";
      toast(`Nuevo mensaje en: ${subj}`);
      playNotifSound();
    } catch (err) {
      console.error("SSE new_message error:", err);
      loadConversations();
    }
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
