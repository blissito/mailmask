// Precios de /pricing en dólares, sólo como referencia. El cobro sigue en MXN: MercadoPago
// México no cobra en otra moneda, así que aquí sólo cambia cómo se leen los montos.
// `precioEnMoneda` lo usa también el toggle anual de landing.js para formatear.
// Pruebas: pricing-fx.test.ts (aUsd) y pricing-usd.test.ts (la página). Ficha: docs/agents/precios-usd.md
(function (raiz) {
  // Redondea al centavo más cercano. Sin un tipo de cambio utilizable no hay monto en dólares.
  function aUsd(mxn, tipo) {
    if (!Number.isFinite(mxn) || !Number.isFinite(tipo) || tipo <= 0) return null;
    return "≈ US$" + (Math.round((mxn / tipo) * 100) / 100).toFixed(2);
  }

  var estado = { moneda: "mxn", tipo: null, fecha: null };

  // Texto de un monto en la moneda activa. Si no hay tipo de cambio, siempre es MXN.
  function precioEnMoneda(mxn) {
    var usd = estado.moneda === "usd" ? aUsd(Number(mxn), estado.tipo) : null;
    return usd !== null ? usd : "$" + Number(mxn).toLocaleString("es-MX");
  }

  raiz.aUsd = aUsd;
  raiz.precioEnMoneda = precioEnMoneda;

  if (typeof document === "undefined") return;

  // Reescribe todo lo que muestra un monto. Los precios guardan su valor en MXN en `data-mxn`,
  // así que nunca se lee de vuelta el texto que ya cambió.
  function pintar() {
    var usd = estado.moneda === "usd";
    document.querySelectorAll("[data-mxn]").forEach(function (el) {
      el.textContent = (el.dataset.prefijo || "") + precioEnMoneda(el.dataset.mxn);
    });
    document.querySelectorAll(".unidad-moneda").forEach(function (el) {
      el.textContent = usd ? " USD aprox./mes" : " MXN/mes";
    });
    document.querySelectorAll("[data-solo-mxn]").forEach(function (el) { el.hidden = usd; });
    document.querySelectorAll("[data-solo-usd]").forEach(function (el) { el.hidden = !usd; });
    document.querySelectorAll(".pricing-card[data-savings]").forEach(function (card) {
      var ahorro = card.querySelector(".plan-savings");
      if (!ahorro.classList.contains("hidden")) ahorro.textContent = "Ahorras " + precioEnMoneda(card.dataset.savings);
    });
  }

  function marcar(moneda) {
    estado.moneda = moneda;
    document.querySelectorAll("[data-moneda]").forEach(function (b) {
      var activo = b.dataset.moneda === moneda;
      b.setAttribute("aria-pressed", String(activo));
      b.className = "px-4 py-1.5 rounded-full " + (activo ? "bg-accent text-white" : "text-fg-muted");
    });
    var url = new URL(location.href);
    if (moneda === "usd") url.searchParams.set("moneda", "usd");
    else url.searchParams.delete("moneda");
    history.replaceState(null, "", url);
    pintar();
  }

  function iniciar() {
    fetch("/api/fx")
      .then(function (res) { return res.ok ? res.json() : null; })
      .then(function (dato) {
        // Sin tipo de cambio el selector no aparece y la página se queda en MXN, como antes.
        if (!dato || aUsd(1, Number(dato.rate)) === null) return;
        estado.tipo = Number(dato.rate);
        estado.fecha = new Date(dato.fetchedAt);
        document.getElementById("tipo-cambio").textContent =
          "1 US$ ≈ $" + estado.tipo.toFixed(2) + " MXN, tipo de cambio del " +
          estado.fecha.toLocaleDateString("es-MX", { day: "numeric", month: "long" });
        document.querySelectorAll("[data-moneda]").forEach(function (b) {
          b.addEventListener("click", function () { marcar(b.dataset.moneda); });
        });
        document.getElementById("selector-moneda").classList.remove("hidden");
        if (new URLSearchParams(location.search).get("moneda") === "usd") marcar("usd");
      })
      .catch(function () { /* Sin red: la página se queda en MXN. */ });
  }

  document.addEventListener("DOMContentLoaded", iniciar);
})(typeof window !== "undefined" ? window : globalThis);
