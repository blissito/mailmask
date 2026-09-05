// Tema claro/oscuro del sitio público. Va en <head> sin defer para que no haya
// parpadeo: aplica la elección guardada antes del primer pintado. Sin elección
// guardada no pone data-theme y manda prefers-color-scheme (ver input.css).
(function () {
  var KEY = "mailmask_theme";
  var root = document.documentElement;
  var saved = null;
  try { saved = localStorage.getItem(KEY); } catch (e) {}
  if (saved === "dark" || saved === "light") root.setAttribute("data-theme", saved);

  function current() {
    var t = root.getAttribute("data-theme");
    if (t) return t;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  function paint(btn) {
    var dark = current() === "dark";
    btn.setAttribute("aria-label", dark ? "Cambiar a tema claro" : "Cambiar a tema oscuro");
    btn.setAttribute("aria-pressed", String(dark));
  }
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
      paint(btn);
      btn.addEventListener("click", function () {
        var next = current() === "dark" ? "light" : "dark";
        root.setAttribute("data-theme", next);
        try { localStorage.setItem(KEY, next); } catch (e) {}
        document.querySelectorAll("[data-theme-toggle]").forEach(paint);
      });
    });
  });
})();
