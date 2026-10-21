# Comercial semanal MailMask — semana 42 (8 → 15 oct 2026) · borrador para aprobar

Vertical 1080×1920, ~30 s, voz em_santa, paleta del sitio público (crema `#faf6ee`, tinta `#1c1917`,
rojo máscara `#d7263d`, dorado `#f2b705` sólo en la máscara). Composición distinta a `short-buzones`
(aquel: tarjetas de personas y recibos; éste: un solo objeto —el navegador con la barra de dirección— que se transforma).

## Lo mejor de la semana (de `git log`, sólo lo que el cliente ve)
1. **Pestaña «Sitio web»** (88a83c6, 38ab06b): ve a dónde apunta tu dominio y conéctalo a Vercel,
   Netlify, Render o EasyBits con vista previa antes de escribir nada. ← protagonista
2. **Deshacer al borrar** en la Bandeja (cb6bb54).
3. **Recibo imprimible** de cada pago (7928dcd).
Fuera: MCP para directorios de Claude/ChatGPT (aún en revisión, no se promete) y «Mask navega solo»
(Mask no es público: `ASSISTANT_PUBLIC` sin confirmar).

## Tres renglones
- **Abre:** «Tu correo ya vive en tu dominio. ¿Y tu página web?»
- **Cierra:** «Correo y sitio, en el mismo dominio, sin tocar un solo registro. Conéctalo en mailmask.studio.»
- **Se lleva:** MailMask ya no sólo es el correo de tu dominio: también lo conecta a tu web, y te enseña el cambio antes de hacerlo.

Circular: abre con una barra de navegador `tunegocio.com` que da «No se puede acceder a este sitio»
(icono de enchufe desconectado). Cierra con la misma barra, candado HTTPS y la página cargada, y un sobre
`hola@tunegocio.com` al lado.

## Beats
| t | Se ve | Voz literal | SFX |
|---|---|---|---|
| 0–4 s | Frame 0 completo: navegador con `tunegocio.com` y enchufe desconectado; el enchufe tiembla | «Tu correo ya vive en tu dominio. ¿Y tu página web?» | crac corto |
| 4–5 s | **Cortinilla WebGPU** (ver abajo), glifo enorme `www` sella | — | whoosh + golpe en 1/(s+1) |
| 5–13 s | Pestaña «Sitio web»: tres filas (raíz, www, blog) con su destino; tocas «Vercel», aparece la vista previa con los registros en rojo/verde; botón «Aplicar» | «Ahora MailMask te enseña a dónde apunta cada parte de tu dominio, y lo conecta a Vercel, Netlify o EasyBits. Antes de cambiar nada, ves el cambio.» | pops escalonados por fila, clic, ding |
| 13–14 s | Cortinilla: rebanadas sesgadas `back.out`, glifo `↶` | — | whoosh distinto |
| 14–20 s | Dos mini-escenas: una conversación se borra y regresa con «Deshacer»; un recibo sale de una impresora con sello «Pagado» | «Y de paso: borrar en la Bandeja ya se deshace, y cada pago trae su recibo.» | caída + rebote, impresora + sello |
| 20–21 s | Cortinilla WebGPU de vuelta, glifo de la máscara | — | golpe grave |
| 21–30 s | Vuelve el navegador: el enchufe se conecta, candado, la página carga; sale el sobre `hola@` al lado. CTA | «Correo y sitio, en el mismo dominio, sin tocar un solo registro. Conéctalo en mailmask punto studio.» | enchufe, sello final |

## WebGPU (lo nuevo de la semana en video)
- Adapter `typegpu` de HyperFrames: GSAP se registra síncrono, el shader se pinta en `hf-seek` con
  `waitUntil(device.queue.onSubmittedWorkDone())`, `data-requires-webgpu` en la raíz, sin `performance.now()`.
- Respeta la caricatura plana: el WGSL **no** hace gradientes ni glow. Celdas de Voronoi con `step()`
  (bordes duros) en rojo/crema/tinta que crecen desde el centro, contorno grueso de 8 px y sombra dura
  como desplazamiento sólido. Tapa las cuatro esquinas antes del corte (se verifica por cuadro).
- Sin html-in-canvas, así que corre en el headless-shell normal (no hace falta Brave).

## Reglas de fixter2025 que aplican (factory-dos, 15-oct)
- Style frames de **todas** las escenas antes de renderizar.
- Glifos con significado (`www`, `↶`, máscara), nunca una letra suelta; la última rebanada nunca oscura sin glifo.
- Karaoke: una línea, sin encimar (entra cuando se apaga la anterior), partición pareja sin huérfanas.
- Cama: medir envolvente RMS y que suene desde el inicio; −21 LUFS con sidechain 3:1 (no −26/6:1).
- `mix.sh` falla si el render no mide lo de la partitura.
- Precios, si aparecen, en MXN.

## Pendiente de decidir
- ¿Aprobado el guion? ¿«Deshacer» y «Recibo» entran o el comercial va sólo con Sitio web?
