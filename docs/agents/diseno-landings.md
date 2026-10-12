# Diseño de las landings públicas (`public/*.html`)

**Qué:** la identidad visual del sitio público —paleta, tema, fuentes, piezas, ilustraciones y
tono—, que hoy vive sólo en `public/css/input.css` y repartida entre las landings. Lee esto
antes de hacer una página pública nueva (`/dominios`, PR #75, es lo que la motivó) para no
reconstruirla a ojo. El SEO va aparte: `seo-paginas-publicas.md`.

## Paleta

Manda `public/css/input.css` (bloque `:root`); aquí sólo se nombra, no se copian los RGB.

- **Fondo y líneas:** `--bg` (crema cálido), `--bg-elev`, `--bg-inset`, `--line`.
- **Tinta:** `--fg`, `--fg-muted`, `--fg-subtle`.
- **Rojo de máscara:** `--accent` (botón, titular, puntos) y `--accent-text` (texto y links;
  es el que da los 5.6:1 sobre `--bg`). `--mascara` y `--mascara-sombra` son el relleno de la
  máscara en las ilustraciones.
- **Oro:** `--gold`, sólo detalles de la máscara y una línea (el guion del `.eyebrow`).
- **Verde de marca:** `--mask-50…900`, fijo en ambos temas y sólo para estados OK (`.chip-ok`).
  No es el color de acento del sitio.
- **Oscuro:** el mismo juego de tokens con otro valor (fondo café muy oscuro, tinta crema, rojo
  aclarado para que el contraste aguante).

Se usan por las clases de `tailwind.config.ts` —`bg-bg`, `bg-bg-elev`, `bg-bg-inset`, `text-fg`,
`text-fg-muted`, `text-fg-subtle`, `border-line`, `bg-accent`, `text-accent-text`, `mask-*`,
`gold-*`—, nunca hex sueltos.

**Regla:** nada de hex a mano ni de `zinc-*` en el sitio público. `zinc-*` y el verde son de la
app: `/app` y `/bandeja` viven con sus propias clases y, dentro de `@layer components`,
`.app-shell` reescribe `--accent` al verde `mask-600`.

## Tema

Claro por default (`:root`); el oscuro entra por `data-theme="dark"` o por
`prefers-color-scheme: dark` cuando no hay elección guardada. `public/js/theme.js` va en el
`<head>` **sin `defer`** (así no hay parpadeo), guarda la elección en
`localStorage.mailmask_theme`, pone `data-theme` y pinta los botones `[data-theme-toggle]`
(`aria-label`/`aria-pressed`). El botón va en el header de cada landing con la misma clase
`theme-toggle inline-flex h-9 w-9 …`.

## Tipografía

El `<link>` de Google Fonts es el mismo en las tres landings, con sus dos `preconnect`
(`fonts.googleapis.com` y `fonts.gstatic.com`): Bricolage Grotesque 700;800, Inter
400;500;600;700 y JetBrains Mono 400;500. **Cópialo tal cual.**

- **Bricolage Grotesque** 800 en `h1`/`h2`, vía la clase `.site`: `text-wrap: balance`,
  `letter-spacing: -0.03em` y `font-variation-settings: "wdth" 96, "opsz" 48`.
- **Inter** de cuerpo (`.site`), con `font-feature-settings: "cv11", "ss01"`.
- **JetBrains Mono** en `.eyebrow` (11px, mayúsculas, `tracking .14em`, color `--fg-subtle`) y
  en código.

El `<body>` del sitio público es `<body class="site bg-bg text-fg antialiased">` (los del blog
añaden `min-h-screen`). `/app` y `/bandeja` son otra cosa: `.app-shell` usa Sora + IBM Plex Sans.

## Piezas

Viven en el `@layer components` de `input.css`. **Reutilízalas antes de inventar clases:**
`.btn-primary`, `.btn-secondary`, `.card`, `.mock` (con `.mock-bar` y `.mock-dot`),
`.chip`/`.chip-ok`, `.faq` (`details`/`summary`/`p`), `.eyebrow`, `.icon-draw` (iconos que se
dibujan solos; `prefers-reduced-motion` los apaga) y `.anim-delay-100…1100`.

En el mismo `@layer` están las `.app-*`, `.dom*` y `.plan-card`: son del dashboard, no de las
landings.

## Compilar el CSS

```sh
npm run build:css   # npx tailwindcss -c tailwind.config.ts -i public/css/input.css -o public/css/styles.css --minify
```

`public/css/styles.css` **se versiona**, y ése es el detalle que muerde: el `Dockerfile` hace
`npm ci --omit=dev` (sin `tailwindcss`) y no corre `build:css`, y el CI corre `npm run build`
—que sí lo incluye— pero **no compara el diff** (fuente: `Dockerfile` y
`.github/workflows/ci.yml`). Un `styles.css` viejo pasa verde y en prod faltan clases. **Toda
clase nueva en un HTML obliga a recompilar y a subir `styles.css` en el mismo PR.**

Tailwind se queda en 3.x: Dependabot ignora el major hasta migrar por el issue #54
(`dependencias-ci.md`).

## Ilustraciones

Dibujo plano de **línea negra gruesa** con rellenos negros sólidos, fondo crema (`--bg`), el
rojo de máscara como **único** color fuerte y un toque de oro (la estrella). Personas y objetos
sencillos; sin degradados ni 3D. La máscara de luchador aparece en sobres y personajes.

- Formato y peso: **JPEG 1200×800, < 200 KB** (las que corren hoy van de 87 a 142 KB).
- Nombres: `public/img/<slug>-il.jpg` y `public/blog/img/<slug>-il.jpg`.
- `alt` describe la escena («un luchador enmascarado con lupa busca entre cajones de sobres»),
  no «imagen de…».
- Las `-og.jpg` (1200×630) son **otra cosa**: tarjetas sociales renderizadas desde
  `scripts/og-*.html` con Chromium, no ilustraciones (ver `seo-paginas-publicas.md`).
- Se suben como binario (`contentBase64` o `fromUrl`), **nunca** como `content`.
- En el HTML la caja reservada es 16:9 (`width="1200" height="675"` en el hero del blog,
  `640×360` en las tarjetas de la landing) y el archivo es 3:2: con `object-cover` se recorta.
  No es un error que se arregle aquí, pero al hacer una nueva decide si igualas la caja o
  asumes el recorte.

## Historia y tono

MailMask es un **luchador enmascarado justiciero**; los villanos son los monstruos del
marketing y del correo: el spam, el cobro por usuario, el helpdesk pesado, el correo que
rebota, el Gmail personal. La máscara protege la identidad —eso son los alias del producto— y
cada ilustración es una escena de esa lucha. El copy puede guiñarla, pero el texto sigue
siendo claro y útil: el ejemplo canónico es la 404, el luchador con lupa buscando el sobre.

*Decisión del equipo, 12-oct-2026.*

## Antes de cualquier UI

1. Lee la skill `dev-frontend` y esta ficha.
2. El SEO no se toca aquí: `seo-paginas-publicas.md` (un solo bloque de metas, OG propia, y la
   página nueva en los DOS lados del sitemap).
3. Si agregas clases, recompila `styles.css` en el mismo PR.

## Notas

- `public/404.html` trae su propio `<style>` con copias a mano de `.btn-primary`, `.eyebrow` y
  el resto, aunque carga `/css/styles.css`: si cambia una pieza, la 404 no la sigue.
- El PR #75 (`/dominios`) traerá `docs/agents/landing-dominios.md` para la regla de cero cifras
  por TLD: enlázala desde aquí cuando exista en `main`, en vez de repetirla.
