// Pantalla de la Bandeja dentro de ChatGPT y Claude (MCP Apps, recurso `ui://mailmask/bandeja.html`).
// El host la pinta en un iframe aislado al llamar `inbox_list` y le pasa el resultado; desde
// aquí sólo se llaman tools de bajo riesgo (`inbox_list`, `inbox_read`, `inbox_mark`). Responder
// NO se hace aquí: se le pide al modelo y el envío pasa por la confirmación del host.
// Tarjeta en el chat = lista corta y 2 botones (guía de UI del Apps SDK); filtros, detalle y
// acciones viven en pantalla completa. Se compila con `npm run build:widgets`.
import { App, PostMessageTransport, applyDocumentTheme } from "@modelcontextprotocol/ext-apps";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

type Conversation = {
  id: string; contact: string; alias: string; subject: string; status: string; unread: boolean | null;
  assignedTo: string | null; priority: string; tags: string[]; lastMessageAt: string;
  messageCount: number; snoozedUntil: string | null; snippet: string;
};
type ListResult = { conversations: Conversation[]; nextCursor: string | null; unreadCount: number; aliases: string[] };
type Message = { id: string; direction: "inbound" | "outbound"; from: string; date: string; text: string; attachments: { filename: string }[] };
type Detail = {
  id: string; contact: string; alias: string; subject: string; status: string; priority: string;
  assignedTo: string | null; messages: Message[]; notes: { author: string; body: string; date: string }[];
};
type Filter = "open" | "unread" | "snoozed" | "closed";

const INLINE_ROWS = 8;

const state = {
  domainId: "",
  list: null as ListResult | null,
  fullscreen: false,
  filter: "open" as Filter,
  alias: "",
  selected: null as Detail | null,
  loading: false,
  error: "",
};

const root = document.getElementById("app")!;
const app = new App({ name: "MailMask Bandeja", version: "1.0.0" }, {});

const esc = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
const sender = (contact: string) => (/^\s*"?([^"<]+?)"?\s*</.exec(contact)?.[1] ?? contact).trim();
const localPart = (address: string) => address.split("@")[0];

function relativeTime(iso: string): string {
  const d = new Date(iso);
  const mins = Math.round((Date.now() - d.getTime()) / 60_000);
  if (mins < 1) return "ahora";
  if (mins < 60) return `${mins} min`;
  if (mins < 24 * 60) return `${Math.round(mins / 60)} h`;
  if (mins < 7 * 24 * 60) return `${Math.round(mins / 1440)} d`;
  return d.toLocaleDateString("es-MX", { day: "numeric", month: "short" });
}

function structured<T>(r: CallToolResult): T {
  if (r.isError) throw new Error(r.content?.map((c) => ("text" in c ? c.text : "")).join(" ") || "Falló la herramienta");
  return r.structuredContent as T;
}

async function call<T>(name: string, args: Record<string, unknown>): Promise<T> {
  return structured<T>(await app.callServerTool({ name, arguments: args }));
}

async function run(job: () => Promise<void>) {
  state.loading = true; state.error = ""; render();
  try { await job(); } catch (e) { state.error = (e as Error).message; }
  state.loading = false; render();
}

const reload = () => run(async () => {
  state.list = await call<ListResult>("inbox_list", {
    domainId: state.domainId, status: state.filter, ...(state.alias ? { alias: state.alias } : {}), limit: 50,
  });
});

const open = (id: string) => run(async () => {
  state.selected = await call<Detail>("inbox_read", { domainId: state.domainId, conversationId: id });
  const row = state.list?.conversations.find((c) => c.id === id);
  if (row) row.unread = false;
});

const mark = (changes: Record<string, unknown>) => run(async () => {
  const id = state.selected!.id;
  await call("inbox_mark", { domainId: state.domainId, conversationId: id, ...changes });
  state.selected = null;
  state.list = await call<ListResult>("inbox_list", {
    domainId: state.domainId, status: state.filter, ...(state.alias ? { alias: state.alias } : {}), limit: 50,
  });
});

async function goFullscreen() {
  const ctx = app.getHostContext();
  if (ctx?.availableDisplayModes && !ctx.availableDisplayModes.includes("fullscreen")) return;
  const r = await app.requestDisplayMode({ mode: "fullscreen" });
  state.fullscreen = r.mode === "fullscreen";
  render();
}

function ask(text: string) {
  void app.sendMessage({ role: "user", content: [{ type: "text", text }] });
}

function rowHtml(c: Conversation): string {
  const badges = [
    c.priority === "urgent" ? `<span class="tag urgent">Urgente</span>` : "",
    c.status === "snoozed" ? `<span class="tag">Pospuesta</span>` : "",
  ].join("");
  const who = c.assignedTo ? `<span class="avatar" title="${esc(c.assignedTo)}">${esc(c.assignedTo[0]?.toUpperCase())}</span>` : "";
  const on = state.selected?.id === c.id ? " on" : "";
  const label = `${c.unread ? "Sin leer. " : ""}${sender(c.contact)}: ${c.subject || "sin asunto"}`;
  return `<button class="row${c.unread ? " unread" : ""}${on}" data-open="${esc(c.id)}" aria-label="${esc(label)}">
    <span class="dot"></span>
    <span class="main">
      <span class="line1"><span class="from">${esc(sender(c.contact))}</span><span class="chip">${esc(localPart(c.alias))}</span>${badges}<span class="time">${esc(relativeTime(c.lastMessageAt))}</span></span>
      <span class="subject">${esc(c.subject || "(sin asunto)")}</span>
      <span class="snippet">${esc(c.snippet)}</span>
    </span>
    ${who}
  </button>`;
}

function countsHtml(l: ListResult): string {
  const unassigned = l.conversations.filter((c) => !c.assignedTo).length;
  const urgent = l.conversations.filter((c) => c.priority === "urgent").length;
  return `<div class="counts">
    <span><b>${l.unreadCount}</b> sin leer</span>
    <span><b>${unassigned}</b> sin asignar</span>
    <span class="${urgent ? "hot" : ""}"><b>${urgent}</b> urgentes</span>
  </div>`;
}

function inlineHtml(l: ListResult): string {
  const rows = l.conversations.slice(0, INLINE_ROWS);
  return `${countsHtml(l)}
    <div class="list">${rows.length ? rows.map(rowHtml).join("") : `<p class="empty">No hay conversaciones aquí.</p>`}</div>
    <div class="actions">
      <button class="primary" data-act="full">Abrir bandeja</button>
      <button data-act="urgent">Resumir lo urgente</button>
    </div>`;
}

function detailHtml(d: Detail): string {
  const msgs = d.messages.map((m) => `<article class="msg ${m.direction}">
      <header><b>${esc(sender(m.from))}</b><span>${esc(relativeTime(m.date))}</span></header>
      <div class="body">${esc(m.text)}</div>
      ${m.attachments.length ? `<footer>📎 ${m.attachments.map((a) => esc(a.filename)).join(", ")}</footer>` : ""}
    </article>`).join("");
  const notes = d.notes.map((n) => `<article class="note"><header><b>Nota interna · ${esc(n.author)}</b><span>${esc(relativeTime(n.date))}</span></header><div class="body">${esc(n.body)}</div></article>`).join("");
  return `<section class="detail">
    <div class="detail-top">
      <button data-act="back">← Volver</button>
      <h2>${esc(d.subject || "(sin asunto)")}</h2>
      <p class="meta">${esc(sender(d.contact))} → ${esc(d.alias)}</p>
    </div>
    <div class="thread">${msgs}${notes}</div>
    <div class="actions wrap">
      <button class="primary" data-act="reply">Responder</button>
      ${d.status !== "closed" ? `<button data-mark="close">Cerrar</button>` : `<button data-mark="reopen">Reabrir</button>`}
      <button data-mark="snooze">Posponer a mañana</button>
      ${d.priority === "urgent" ? `<button data-mark="normal">Quitar urgente</button>` : `<button data-mark="urgent">Urgente</button>`}
    </div>
  </section>`;
}

function fullscreenHtml(l: ListResult): string {
  const filters: [Filter, string][] = [["open", "Abiertas"], ["unread", "Sin leer"], ["snoozed", "Pospuestas"], ["closed", "Cerradas"]];
  const aliases = l.aliases ?? [];
  return `<div class="toolbar">
      ${filters.map(([f, label]) => `<button class="pill${state.filter === f ? " on" : ""}" data-filter="${f}">${label}</button>`).join("")}
      ${aliases.length > 1 ? `<select data-alias><option value="">Todas las direcciones</option>${aliases.map((a) => `<option value="${esc(a)}"${state.alias === a ? " selected" : ""}>${esc(a)}</option>`).join("")}</select>` : ""}
    </div>
    ${countsHtml(l)}
    <div class="split">
      <div class="list scroll">${l.conversations.length ? l.conversations.map(rowHtml).join("") : `<p class="empty">No hay conversaciones aquí.</p>`}</div>
      ${state.selected ? detailHtml(state.selected) : `<p class="empty pick">Elige una conversación.</p>`}
    </div>`;
}

function render() {
  const l = state.list;
  document.documentElement.classList.toggle("fullscreen", state.fullscreen);
  // La guía de UI de ChatGPT no quiere el logo dentro de la tarjeta: sólo en pantalla completa.
  const head = `<header class="brand">${state.fullscreen ? MASK_SVG : ""}<span>Bandeja</span>${state.loading ? `<span class="spinner" role="status" aria-label="Cargando"></span>` : ""}</header>`;
  const error = state.error ? `<p class="error">${esc(state.error)}</p>` : "";
  if (!l) { root.innerHTML = `${head}${error || `<p class="empty">Cargando…</p>`}`; return; }
  // En la tarjeta, abrir una fila lleva a pantalla completa con el detalle.
  root.innerHTML = head + error + (state.fullscreen ? fullscreenHtml(l) : inlineHtml(l));
}

root.addEventListener("click", (e) => {
  const el = (e.target as HTMLElement).closest("button");
  if (!el || state.loading) return;
  const id = el.dataset.open;
  if (id) {
    if (!state.fullscreen) void goFullscreen().then(() => open(id)); else void open(id);
    return;
  }
  if (el.dataset.filter) { state.filter = el.dataset.filter as Filter; state.selected = null; void reload(); return; }
  switch (el.dataset.act) {
    case "full": void goFullscreen(); return;
    case "urgent": ask("Resume las conversaciones urgentes y sin leer de mi Bandeja de MailMask y dime cuáles contestar primero."); return;
    case "back": state.selected = null; render(); return;
    case "reply": {
      const d = state.selected!;
      ask(`Redacta una respuesta para la conversación «${d.subject}» de ${sender(d.contact)} en mi Bandeja de MailMask (domainId ${state.domainId}, conversationId ${d.id}). Enséñamela antes de enviarla.`);
      return;
    }
  }
  const tomorrow = new Date(Date.now() + 24 * 3600_000); tomorrow.setHours(9, 0, 0, 0);
  switch (el.dataset.mark) {
    case "close": void mark({ status: "closed" }); return;
    case "reopen": void mark({ status: "open" }); return;
    case "snooze": void mark({ status: "snoozed", snoozedUntil: tomorrow.toISOString() }); return;
    case "urgent": void mark({ priority: "urgent" }); return;
    case "normal": void mark({ priority: "normal" }); return;
  }
});

root.addEventListener("change", (e) => {
  const el = e.target as HTMLSelectElement;
  if (el.matches("[data-alias]")) { state.alias = el.value; state.selected = null; void reload(); }
});

app.ontoolinput = (p) => {
  const args = (p.arguments ?? {}) as { domainId?: string; status?: Filter; alias?: string };
  if (args.domainId) state.domainId = args.domainId;
  if (args.status && ["open", "unread", "snoozed", "closed"].includes(args.status)) state.filter = args.status;
  if (args.alias) state.alias = args.alias;
};
app.ontoolresult = (r) => {
  try { state.list = structured<ListResult>(r as CallToolResult); } catch (e) { state.error = (e as Error).message; }
  render();
};
app.onhostcontextchanged = (ctx) => {
  if (ctx.theme) applyDocumentTheme(ctx.theme);
  if (ctx.displayMode) { state.fullscreen = ctx.displayMode === "fullscreen"; render(); }
};

const MASK_SVG = `<svg width="20" height="20" viewBox="0 0 80 80" fill="none" aria-hidden="true"><ellipse cx="40" cy="42" rx="28" ry="24" fill="rgb(var(--mascara-sombra))"/><ellipse cx="40" cy="38" rx="28" ry="22" fill="rgb(var(--mascara))"/><ellipse cx="28" cy="36" rx="8" ry="6.3" fill="#ffffff" stroke="rgb(var(--gold))" stroke-width="1.8"/><ellipse cx="52" cy="36" rx="8" ry="6.3" fill="#ffffff" stroke="rgb(var(--gold))" stroke-width="1.8"/><circle cx="28.6" cy="36.4" r="5.2" fill="#a97142"/><circle cx="52.6" cy="36.4" r="5.2" fill="#a97142"/><circle cx="28.6" cy="36.4" r="2.6" fill="#3b2412"/><circle cx="52.6" cy="36.4" r="2.6" fill="#3b2412"/><circle cx="30.2" cy="34.9" r="1.9" fill="#ffffff"/><circle cx="54.2" cy="34.9" r="1.9" fill="#ffffff"/></svg>`;

render();
app.connect(new PostMessageTransport(window.parent, window.parent)).then(() => {
  const ctx = app.getHostContext();
  if (ctx?.theme) applyDocumentTheme(ctx.theme);
  state.fullscreen = ctx?.displayMode === "fullscreen";
  render();
}).catch((e) => { state.error = `No se pudo conectar con el chat: ${(e as Error).message}`; render(); });
