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

async function init() {
  const res = await fetch("/api/admin/backups");
  if (res.status === 401 || res.status === 403) {
    window.location.href = "/app";
    return;
  }

  const me = await fetch("/api/auth/me");
  if (me.ok) {
    const user = await me.json();
    document.getElementById("user-email").textContent = user.email;
  }

  const backups = await res.json();
  render(backups);

  document.getElementById("backups-list").addEventListener("click", async (e) => {
    const btn = e.target.closest(".btn-delete-backup");
    if (!btn) return;
    const key = btn.dataset.key;
    if (!confirm(`¿Eliminar backup "${key}"?`)) return;
    btn.disabled = true;
    btn.textContent = "Eliminando...";
    try {
      const delRes = await fetch(`/api/admin/backups/${encodeURIComponent(key)}`, { method: "DELETE" });
      if (delRes.ok) {
        const listRes = await fetch("/api/admin/backups");
        if (listRes.ok) render(await listRes.json());
      } else {
        const data = await delRes.json();
        alert(data.error || "Error al eliminar");
      }
    } catch {
      alert("Error de conexión");
    }
  });

  document.getElementById("btn-trigger").addEventListener("click", triggerBackup);

  document.getElementById("btn-logout").addEventListener("click", async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    window.location.href = "/login";
  });
}

function render(backups) {
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
        <a href="/api/admin/backups/${encodeURIComponent(b.key)}"
           class="text-sm text-red-400 hover:text-red-300 transition-colors">
          Descargar
        </a>
        <button data-key="${esc(b.key)}"
                class="btn-delete-backup text-sm text-zinc-500 hover:text-red-400 transition-colors">
          Eliminar
        </button>
      </div>
    </div>
  `).join("");
}

async function triggerBackup() {
  const btn = document.getElementById("btn-trigger");
  const status = document.getElementById("trigger-status");
  btn.disabled = true;
  btn.textContent = "Creando...";
  status.classList.add("hidden");

  try {
    const res = await fetch("/api/admin/backups/trigger", { method: "POST" });
    const data = await res.json();

    if (res.ok) {
      status.className = "mt-4 p-3 rounded-lg text-sm bg-green-900/50 border border-green-800 text-green-300";
      status.textContent = "Backup creado: " + data.key + " (" + data.users + " usuarios)";
      const listRes = await fetch("/api/admin/backups");
      if (listRes.ok) render(await listRes.json());
    } else {
      status.className = "mt-4 p-3 rounded-lg text-sm bg-red-900/50 border border-red-800 text-red-300";
      status.textContent = data.error || "Error al crear backup";
    }
  } catch {
    status.className = "mt-4 p-3 rounded-lg text-sm bg-red-900/50 border border-red-800 text-red-300";
    status.textContent = "Error de conexion";
  }

  status.classList.remove("hidden");
  btn.disabled = false;
  btn.textContent = "Crear backup ahora";
}

document.addEventListener("DOMContentLoaded", init);
