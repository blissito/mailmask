// Landing /correo-en-tu-dominio: animaciones al verse, el input-dirección y el botón magnético.
// Se carga en <head> sin defer para marcar <html> antes de pintar.
document.documentElement.classList.add("js-anim");

(function () {
  "use strict";

  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Quita lo que la gente pega de más: protocolo, www, ruta y una @ al principio.
  function cleanDomain(raw) {
    return String(raw || "")
      .trim()
      .toLowerCase()
      .replace(/^[a-z]+:\/\//, "")
      .replace(/^.*@/, "")
      .replace(/^www\./, "")
      .replace(/[\/?#].*$/, "")
      .replace(/\s+/g, "");
  }

  var DOMAIN_RE = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/;

  // Cambia el dominio de ejemplo por el que escribe la persona en todos los dibujos.
  function paint(domain) {
    var shown = domain || "estudiorios.mx";
    document.querySelectorAll("[data-dominio]").forEach(function (el) {
      el.textContent = shown;
    });
    document.querySelectorAll("[data-dominio-correo]").forEach(function (el) {
      el.textContent = (el.getAttribute("data-local") || "hola") + "@" + shown;
    });
  }

  // Vuelve a correr las animaciones de entrada de un dibujo (tachón, correo nuevo, sello).
  var lastReplay = 0;
  function replay(drawing) {
    if (reduce || !drawing || Date.now() - lastReplay < 2400) return;
    lastReplay = Date.now();
    drawing.querySelectorAll('[class*="a-"]').forEach(function (el) {
      el.style.animation = "none";
      void el.getBoundingClientRect();
      el.style.animation = "";
    });
  }

  function initForm() {
    var form = document.getElementById("form-dominio");
    var input = document.getElementById("dominio");
    var hint = document.getElementById("aviso-dominio");
    var cta = document.getElementById("cta-final");
    if (!form || !input) return;
    var defaultHint = hint.textContent;
    var heroCard = document.querySelector(".pantalla .dibujo");
    var typingTimer = null;
    var lastPainted = "";
    if (heroCard) heroCard.addEventListener("mouseenter", function () { replay(heroCard); });

    function registerUrl(domain) {
      return "/register" + (domain ? "?dominio=" + encodeURIComponent(domain) : "");
    }

    input.addEventListener("input", function () {
      var domain = cleanDomain(input.value);
      var ok = DOMAIN_RE.test(domain);
      paint(ok ? domain : "");
      hint.classList.remove("error");
      hint.textContent = ok ? "Así se va a ver: hola@" + domain : defaultHint;
      if (cta) cta.href = registerUrl(ok ? domain : "");
      // Al terminar de escribir un dominio válido, la tarjeta vuelve a tachar el Gmail y sella el nuevo.
      clearTimeout(typingTimer);
      if (ok && domain !== lastPainted) {
        typingTimer = setTimeout(function () {
          lastPainted = domain;
          lastReplay = 0;
          replay(heroCard);
        }, 600);
      }
    });

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var domain = cleanDomain(input.value);
      if (domain && !DOMAIN_RE.test(domain)) {
        hint.classList.add("error");
        hint.textContent = "Escribe sólo el dominio, por ejemplo estudiorios.mx.";
        input.focus();
        return;
      }
      try {
        if (domain) localStorage.setItem("mailmask_dominio", domain);
      } catch (err) {}
      if (window.gtag) window.gtag("event", "campana_dominio", { domain_typed: domain ? "si" : "no", transport_type: "beacon" });
      window.location.href = registerUrl(domain);
    });
  }

  // Cada pantalla corre sus animaciones una sola vez, cuando se ve.
  function initReveal() {
    var screens = document.querySelectorAll(".pantalla");
    if (reduce || !("IntersectionObserver" in window)) {
      screens.forEach(function (s) { s.classList.add("visto"); });
      return;
    }
    var io = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("visto");
            io.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.3 }
    );
    screens.forEach(function (s) { io.observe(s); });
  }

  // Receta magnetic-button de motion-anything: jala el botón hacia el cursor unos px.
  function initMagnetic() {
    if (reduce || (window.matchMedia && window.matchMedia("(hover: none)").matches)) return;
    document.querySelectorAll(".magnetic").forEach(function (btn) {
      var strength = parseFloat(btn.getAttribute("data-magnet-strength")) || 0.3;
      btn.addEventListener("pointermove", function (e) {
        var r = btn.getBoundingClientRect();
        var dx = e.clientX - (r.left + r.width / 2);
        var dy = e.clientY - (r.top + r.height / 2);
        btn.style.transform = "translate(" + dx * strength + "px," + dy * strength + "px)";
      });
      btn.addEventListener("pointerleave", function () {
        btn.style.transform = "";
      });
    });
  }

  // Video del short: mudo por defecto; el botón prende el sonido y lo regresa al inicio.
  function initVideo() {
    var video = document.getElementById("video-short");
    var btn = document.getElementById("video-sonido");
    if (!video || !btn) return;
    btn.addEventListener("click", function () {
      var on = video.muted;
      video.muted = !on;
      if (on) { video.currentTime = 0; video.play(); }
      btn.setAttribute("aria-pressed", on ? "true" : "false");
      btn.textContent = on ? "Silenciar" : "Activar sonido";
    });
  }

  function init() {
    initForm();
    initVideo();
    initReveal();
    initMagnetic();
  }

  if (document.readyState !== "loading") init();
  else document.addEventListener("DOMContentLoaded", init);
})();
