document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-toggle-password]");
  if (!btn) return;
  const input = btn.parentElement.querySelector("input");
  const isPassword = input.type === "password";
  input.type = isPassword ? "text" : "password";
  btn.querySelector(".eye-open").classList.toggle("hidden", !isPassword);
  btn.querySelector(".eye-closed").classList.toggle("hidden", isPassword);
});

// Botón de Google: es un enlace, así que no hay submit que deshabilitar. Al hacer clic
// se apaga y muestra "Conectando con Google…" hasta que el navegador navega.
(() => {
  const a = document.getElementById("google-login");
  if (!a) return;
  a.addEventListener("click", () => {
    if (a.dataset.loading) return;
    a.dataset.loading = "1";
    a.classList.add("opacity-60", "pointer-events-none");
    a.setAttribute("aria-busy", "true");
    const label = a.lastChild;
    if (label && label.nodeType === Node.TEXT_NODE) label.textContent = " Conectando con Google…";
  });
  // Si el usuario vuelve con "atrás", el botón debe revivir.
  window.addEventListener("pageshow", () => {
    delete a.dataset.loading;
    a.classList.remove("opacity-60", "pointer-events-none");
    a.removeAttribute("aria-busy");
    const label = a.lastChild;
    if (label && label.nodeType === Node.TEXT_NODE) label.textContent = " Continuar con Google";
  });
})();
