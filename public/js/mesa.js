// Mesa — keyboard-first helpdesk inbox
// Vanilla JS, no dependencies

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// --- State ---
let currentUser = null;
let domains = [];
let selectedDomainId = null;
let conversations = [];
let selectedIdx = -1;
let activeConv = null;
let canDoActions = false; // false for basico plan
let composerMode = "reply"; // "reply" | "note"

// --- Init ---
document.addEventListener("DOMContentLoaded", async () => {
  await checkAuth();
  await loadDomains();
  setupListeners();
  setupKeyboard();
});

// --- Auth ---
async function checkAuth() {
  const res = await fetch("/api/auth/me");
  if (!res.ok) return window.location.href = "/login";
  currentUser = await res.json();
  document.getElementById("user-email").textContent = currentUser.email;

  const plan = currentUser.subscription?.plan ?? "basico";
  canDoActions = plan !== "basico";
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
  await loadConversations();
}

// --- Conversations ---
async function loadConversations() {
  if (!selectedDomainId) return;
  const status = document.getElementById("status-filter").value;
  let url = `/api/bandeja/conversations?domainId=${selectedDomainId}`;
  if (status) url += `&status=${status}`;

  const res = await fetch(url);
  if (!res.ok) {
    conversations = [];
    renderList();
    return;
  }
  conversations = await res.json();
  renderList();
}

function renderList() {
  const container = document.getElementById("conv-list");
  const empty = document.getElementById("list-empty");
  const search = document.getElementById("search-input").value.toLowerCase();

  let filtered = conversations;
  if (search) {
    filtered = conversations.filter(c =>
      c.from.toLowerCase().includes(search) ||
      c.subject.toLowerCase().includes(search)
    );
  }

  document.getElementById("conv-count").textContent =
    `${filtered.length} conversación${filtered.length !== 1 ? "es" : ""}`;

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

    let meta = `<span class="mesa-status-dot ${esc(c.status)}"></span>`;
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
        <div class="mesa-conv-meta">${meta}</div>
      </div>
    </div>`;
  }).join("");

  // Replace only conversation items, preserve empty state element
  container.querySelectorAll(".mesa-conv").forEach(el => el.remove());
  container.insertAdjacentHTML("beforeend", html);

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
async function openConversation(conv) {
  activeConv = conv;
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
        <span class="mesa-msg-dir ${dir}">${dir === "inbound" ? "recibido" : "enviado"}</span>
        <span class="mesa-msg-time">${formatTime(item.createdAt)}</span>
      </div>
      <div class="mesa-msg-body">${esc(item.body || item.html || "")}</div>
      ${attachmentsHtml}
    </div>`;
  }).join("");

  // Scroll to bottom
  container.scrollTop = container.scrollHeight;
}

// --- Actions ---
async function sendReply() {
  if (!activeConv || !canDoActions) return;
  const textarea = document.getElementById("composer-textarea");
  const text = textarea.value.trim();
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
      textarea.value = "";
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
      body: JSON.stringify({ domainId: selectedDomainId, body: text }),
    });
    btn.disabled = false;
    if (res.ok) {
      textarea.value = "";
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
    toast(newPriority === "urgent" ? "Marcada como urgente" : "Prioridad normal");
    activeConv.priority = newPriority;
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
    document.getElementById("detail-empty").classList.remove("mesa-hidden");
    document.getElementById("detail-loaded").classList.add("mesa-hidden");
    loadConversations();
  });

  document.getElementById("status-filter").addEventListener("change", () => {
    loadConversations();
  });

  document.getElementById("search-input").addEventListener("input", () => {
    renderList();
  });

  document.getElementById("btn-reply").addEventListener("click", () => {
    composerMode = "reply";
    updateComposerMode();
    document.getElementById("composer-textarea").focus();
  });

  document.getElementById("btn-assign").addEventListener("click", assignConversation);
  document.getElementById("btn-close-conv").addEventListener("click", closeConversation);
  document.getElementById("btn-urgent").addEventListener("click", toggleUrgent);
  document.getElementById("btn-delete-conv").addEventListener("click", deleteConversation);
  document.getElementById("btn-restore-conv").addEventListener("click", restoreConversationAction);
  document.getElementById("btn-send").addEventListener("click", sendReply);

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
  document.getElementById("composer-textarea").addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      sendReply();
    }
  });

  // Assign modal
  document.getElementById("assign-cancel").addEventListener("click", () => {
    document.getElementById("modal-assign").classList.add("hidden");
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

    if (e.key === "j") {
      e.preventDefault();
      const filtered = getFilteredConversations();
      if (selectedIdx < filtered.length - 1) {
        selectedIdx++;
        renderList();
        scrollToSelected();
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
      document.getElementById("composer-textarea").focus();
    }
    if (e.key === "n" && canDoActions) {
      e.preventDefault();
      composerMode = "note";
      updateComposerMode();
      document.getElementById("composer-textarea").focus();
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

function getFilteredConversations() {
  const search = document.getElementById("search-input").value.toLowerCase();
  if (!search) return conversations;
  return conversations.filter(c =>
    c.from.toLowerCase().includes(search) ||
    c.subject.toLowerCase().includes(search)
  );
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
