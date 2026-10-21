// Recorrido de /correo-en-tu-dominio: la persona escribe su dominio y le da «Crear gratis» →
// /register?dominio=… lo guarda → /app abre «Agregar dominio» ya con él, una sola vez.
// Corre el JS real de los tres archivos en node:vm con un DOM mínimo de mentira.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const leer = (ruta: string) => readFileSync(new URL(ruta, import.meta.url), "utf8");
const landingJs = leer("./public/js/correo-en-tu-dominio.js");
const landingHtml = leer("./public/correo-en-tu-dominio.html");
const registerJs = leer("./public/js/register.js");
const appJs = leer("./public/js/app.js");

function fakeStorage() {
  const m = new Map<string, string>();
  return {
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null),
    setItem: (k: string, v: string) => void m.set(k, String(v)),
    removeItem: (k: string) => void m.delete(k),
  };
}

function fakeEl(extra: Record<string, unknown> = {}) {
  const listeners: Record<string, (e: unknown) => void> = {};
  const classes = new Set<string>();
  return {
    listeners,
    classes,
    value: "",
    textContent: "",
    href: "/register",
    focused: false,
    classList: { add: (c: string) => classes.add(c), remove: (c: string) => classes.delete(c) },
    addEventListener: (t: string, fn: (e: unknown) => void) => void (listeners[t] = fn),
    focus() { this.focused = true; },
    ...extra,
  };
}

// Carga la landing y devuelve el formulario listo para enviarse.
function landing() {
  const form = fakeEl(), input = fakeEl(), hint = fakeEl({ textContent: "Gratis y sin tarjeta." }), cta = fakeEl();
  const els: Record<string, unknown> = { "form-dominio": form, dominio: input, "aviso-dominio": hint, "cta-final": cta };
  const ctx: Record<string, any> = {
    document: {
      readyState: "complete",
      documentElement: { classList: { add() {} } },
      getElementById: (id: string) => els[id] ?? null,
      querySelector: () => null,
      querySelectorAll: () => [],
    },
    localStorage: fakeStorage(),
    location: { href: "/correo-en-tu-dominio" },
    // prefers-reduced-motion: sin animaciones ni IntersectionObserver
    matchMedia: () => ({ matches: true }),
    setTimeout: () => 0,
    clearTimeout: () => {},
  };
  ctx.window = ctx;
  vm.runInNewContext(landingJs, ctx);
  const enviar = (valor: string) => {
    input.value = valor;
    input.listeners.input?.({});
    form.listeners.submit({ preventDefault() {} });
  };
  return { ctx, hint, cta, input, enviar };
}

test("sin JS el formulario igual llega a /register?dominio=", () => {
  assert.match(landingHtml, /<form[^>]*id="form-dominio"[^>]*action="\/register"[^>]*method="get"/);
  assert.match(landingHtml, /<input id="dominio" name="dominio"/);
});

test("Crear gratis con un dominio manda a /register?dominio= y lo guarda", () => {
  const { ctx, cta, enviar } = landing();
  enviar("https://www.EstudioRios.mx/contacto");
  assert.equal(ctx.location.href, "/register?dominio=estudiorios.mx");
  assert.equal(ctx.localStorage.getItem("mailmask_dominio"), "estudiorios.mx");
  assert.equal(cta.href, "/register?dominio=estudiorios.mx", "el CTA del cierre también lleva el dominio");
});

test("si pega un correo completo se queda con el dominio", () => {
  const { ctx, enviar } = landing();
  enviar("hola@estudiorios.com.mx");
  assert.equal(ctx.location.href, "/register?dominio=estudiorios.com.mx");
});

test("un dominio inválido no navega y explica qué escribir", () => {
  const { ctx, hint, input, enviar } = landing();
  enviar("mi negocio");
  assert.equal(ctx.location.href, "/correo-en-tu-dominio");
  assert.ok(hint.classes.has("error"));
  assert.match(hint.textContent, /Escribe sólo el dominio/);
  assert.ok(input.focused);
  assert.equal(ctx.localStorage.getItem("mailmask_dominio"), null);
});

test("vacío va al registro sin dominio", () => {
  const { ctx, enviar } = landing();
  enviar("");
  assert.equal(ctx.location.href, "/register");
});

test("/register guarda ?dominio= para la app", () => {
  const bloque = registerJs.match(/const _dominioParam[\s\S]*?\n}\n/)?.[0];
  assert.ok(bloque, "register.js ya no lee ?dominio=");
  const ctx: Record<string, any> = { location: { search: "?dominio=estudiorios.mx" }, localStorage: fakeStorage(), URLSearchParams };
  vm.runInNewContext(bloque, ctx);
  assert.equal(ctx.localStorage.getItem("mailmask_dominio"), "estudiorios.mx");
});

// Corre openDomainFromLanding() de app.js con los dominios de la cuenta dados.
function app(guardado: string | null, dominios: string[] = [], search = "") {
  const fn = appJs.match(/function openDomainFromLanding\(\) \{[\s\S]*?\n}\n/)?.[0];
  assert.ok(fn, "app.js ya no tiene openDomainFromLanding()");
  const input = { value: "" };
  const ctx: Record<string, any> = {
    location: { search },
    localStorage: fakeStorage(),
    URLSearchParams,
    domains: dominios.map((domain) => ({ domain })),
    abierto: 0,
    buscado: 0,
    showAddDomainModal() { ctx.abierto++; },
    searchDomainAvailability() { ctx.buscado++; },
    document: { getElementById: (id: string) => (id === "add-domain-input" ? input : null) },
  };
  if (guardado !== null) ctx.localStorage.setItem("mailmask_dominio", guardado);
  vm.runInNewContext(fn + "\nopenDomainFromLanding();", ctx);
  return { ctx, input };
}

test("la app abre «Agregar dominio» con el dominio de la landing y busca", () => {
  const { ctx, input } = app("estudiorios.mx");
  assert.equal(ctx.abierto, 1);
  assert.equal(input.value, "estudiorios.mx");
  assert.equal(ctx.buscado, 1);
  assert.equal(ctx.localStorage.getItem("mailmask_dominio"), null, "una sola vez: se borra al usarse");
});

test("no lo abre si el dominio ya está en la cuenta", () => {
  const { ctx } = app("estudiorios.mx", ["estudiorios.mx"]);
  assert.equal(ctx.abierto, 0);
  assert.equal(ctx.localStorage.getItem("mailmask_dominio"), null);
});

test("no abre nada sin dominio guardado o con basura", () => {
  assert.equal(app(null).ctx.abierto, 0);
  assert.equal(app("<script>").ctx.abierto, 0);
});

test("?dominio= en la URL de /app también sirve", () => {
  const { ctx, input } = app(null, [], "?dominio=estudiorios.mx");
  assert.equal(ctx.abierto, 1);
  assert.equal(input.value, "estudiorios.mx");
});
