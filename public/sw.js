// Service worker de la Bandeja (PWA). Existe para que el navegador la deje
// instalar; no guarda correo: los cuerpos viven en S3 y la lista cambia por SSE,
// así que una copia local sólo serviría datos viejos. Todo va a la red.
// Si no hay red, la navegación cae en una pantalla mínima en vez del dinosaurio.
const OFFLINE_HTML = `<!doctype html><html lang="es-MX"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sin conexión — Bandeja</title>
<body style="margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#16120f;color:#f5efe6;font:16px/1.5 system-ui,sans-serif;text-align:center;padding:24px">
<div><p style="font-size:20px;font-weight:700;margin:0 0 8px">Sin conexión</p>
<p style="margin:0 0 20px;color:#b8ada0">La Bandeja necesita internet para traer tu correo.</p>
<button onclick="location.reload()" style="font:inherit;font-weight:600;padding:12px 22px;border-radius:999px;border:2px solid #f5efe6;background:#f04b5a;color:#fff">Reintentar</button></div>`;

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("fetch", (event) => {
  if (event.request.mode !== "navigate") return;
  event.respondWith(
    fetch(event.request).catch(() =>
      new Response(OFFLINE_HTML, { headers: { "content-type": "text/html; charset=utf-8" } })
    )
  );
});
