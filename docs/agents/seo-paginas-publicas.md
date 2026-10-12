# SEO de las páginas públicas (`public/*.html`, `public/llms.txt`)

**Qué:** convenciones que vigilan las páginas públicas. Las reglas viven en `seo-checks.ts`
(una sola copia) y las corren `public-seo.test.ts` (todas las páginas del sitemap, contra su lista de
`PENDIENTES`) y una suite por página con reglas propias: `docs-seo.test.ts` (`/docs`, `@graph`
completo y `hasPart`), `pricing-seo.test.ts` (`/pricing`, ofertas atadas a `plans.ts` e imagen
social), `dominios-seo.test.ts` (`/dominios`, sin cifras por TLD) y
`alternativa-google-workspace.test.ts` (la comparativa con Google: precios de MailMask atados a
`plans.ts`, la tabla completa sólo ahí y los precios de Google citados con enlace y fecha).

- **Un solo bloque de metas** arriba del `<style>`: title (≤ 60), description (140–160),
  canonical, hreflang `es-MX` + `x-default`, OG y Twitter. Nada de metas sueltas más abajo.
- **JSON-LD en un único `@graph`** con `#org` (Organization) y `#website` (WebSite) como
  nodos compartidos; el resto los referencia por `@id` en vez de repetir nombre y logo.
- **`dateModified` = la fecha visible** («Actualizado: <fecha>», con `<time datetime>`).
  Al editar la página, se cambian las dos y el `lastmod` del sitemap. En los legales
  (`/terms`, `/privacy`) `public-seo.test.ts` amarra las tres: la visible, el `dateModified` y el `lastmod`.
- **`hasPart` apunta a anclas que existen**; los `id` de los `<h2>` no se renombran
  (rompe enlaces y el ranking por sección).
- **Imagen social propia** (1200×630 JPEG, < 200 KB), renderizada con Chromium desde HTML
  (`scripts/og-docs.html`, `og-pricing.html`, `og-blog.html`, `og-terms.html`,
  `og-privacy.html` y `og-alternativa-google-workspace.html`), no con IA. La genérica del sitio (`img/og-image.png`, PNG) sirve
  de respaldo, pero cada página del sitemap trae la suya. Tras el deploy hay que refrescarla
  a mano en el Post Inspector de LinkedIn: tiene la anterior en caché. En las plantillas el panel
  derecho es de una sola línea: una línea larga estira la tarjeta más allá del lienzo de 1200 px.
- **`llms.txt` es un contrato con agentes:** no puede contradecir `/docs` ni anunciar
  instalaciones que no existen (hoy la CLI no está en npm). Lo vigila `llms.test.ts`.
- **Sitemap:** una página pública nueva va en DOS lados o el generador la borra en silencio: la
  fila de `paginas` en `scripts/gen-sitemap.ts` (ruta, archivo, freq, prio) y su `<url>` en
  `public/sitemap.xml`.
- **Sitemap:** `npx tsx scripts/gen-sitemap.ts` toma el `lastmod` del último commit con
  `git log`; en un checkout sin `.git` (tarball) cae al mtime y deja todas las fechas
  iguales — córrelo en un clon con historia, o edita a mano sólo el `<lastmod>` que cambió.
- **Trampa:** `github_push_files` sube texto; un binario (la imagen OG) va con
  `contentBase64` o `fromUrl`, nunca como `content`.

## Qué vigila `public-seo.test.ts` y cómo se vacía `PENDIENTES`

Las páginas salen de `public/sitemap.xml` —todas menos las entradas `/blog/<slug>`, que se
revisan con su artículo—, así que una página nueva del sitemap entra a la suite sola.
Ruta→archivo lo resuelve `archivoDe()`: `/` es `public/landing.html`, `/blog` es
`public/blog/index.html` y el resto `public/<ruta>.html`.

Cada página debe salir limpia de estas reglas. Lo que hoy no lo hace está apuntado en la
lista `PENDIENTES` de `public-seo.test.ts` (página → reglas), que vacían los tickets B–D del
sprint #9. **Un hueco que no esté apuntado, o un pendiente que ya se arregló y sigue
listado, hacen fallar la prueba** — al arreglar una página se quita su renglón.

| Regla | Qué exige |
|---|---|
| `title`, `title-largo` | un `<title>`, de 60 caracteres o menos |
| `description`, `description-medida` | una `description`, de 140 a 160 caracteres |
| `canonical` | `rel="canonical"` a la URL de la página |
| `hreflang` | `es-MX` y `x-default`, a la misma URL |
| `og`, `og-coincide` | las metas OG/Twitter, con `og:title`, `og:description`, `twitter:title` y `twitter:description` iguales al title y a la description, `og:url` a la página y `twitter:card` en `summary_large_image` |
| `jsonld-unico`, `jsonld-graph` | un solo `<script>` de JSON-LD, y con `@graph` |
| `softwareapplication` | ni `SoftwareApplication`, ni `MobileApplication`, ni `WebApplication` (ver la trampa) |
| `og-imagen`, `og-medidas`, `og-propia` | la imagen existe en `public/`, mide 1200×630 igual que sus metas, y no es la tarjeta genérica `img/og-image.png` |
| `fecha-visible` | «Actualizado: <time datetime>» en `/` (landing, junto al ©), `/docs`, `/pricing`, `/terms` y `/privacy` |

La regla es una función pura (`huecos(ruta, html)` en `seo-checks.ts`), así que la suite la
prueba también sobre una página de muestra a la que le va quitando piezas: si quitar un
`canonical` dejara de reportar `canonical`, la prueba falla.

## Precios de terceros: una sola tabla, con fuente y fecha

La comparativa con Google Workspace vive **sólo** en `/alternativa-google-workspace`: `/pricing` y
la portada dejan un resumen y enlazan. Cada cifra de Google lleva **enlace a su página oficial de
precios y fecha de consulta** (el bloque `#fuente-precios`), y `/alternativa-google-workspace` y
`/pricing` comparten la MISMA cita: repetir el número sin la fuente es justo lo que desfasa una
página de la otra. Google factura por usuario al mes y en la moneda de cada país, así que la
conversión a pesos no se publica: se enlaza. Lo vigila `alternativa-google-workspace.test.ts`.

## Trampa: no uses `SoftwareApplication` sin ratings

Google exige `aggregateRating` o `review` en `SoftwareApplication` y el Rich Results Test marca el nodo como inválido si faltan; no se inventan ratings. El SDK va como `SoftwareSourceCode` (sin rich result que validar) y las dos suites fallan si reaparece `SoftwareApplication`.

## Precios: manda `plans.ts`

Lo que se cobra vive en `plans.ts` (`ADDONS.*.price` y `DOMAIN_ANNUAL_PRICE`). `/pricing` lo
repite en tres lados: las ofertas del `@graph`, los `data-monthly`/`data-yearly`/`data-price`
de las tarjetas —que el toggle de `landing.js` usa para cambiar el número a la vista— y el
`+$99` de los bloques de add-on. `pricing-seo.test.ts` amarra los tres al catálogo: cambiar
un precio en `plans.ts` sin tocar la página hace fallar la suite, y al revés también. Ese
mismo archivo vigila que el «Actualizado» visible sea el `dateModified` y el `<lastmod>` del
sitemap, como en `/`.

El anual ($999) no es un add-on: va como quinta `Offer` con su `UnitPriceSpecification` de
`billingDuration: P1Y`, para que no se lea como otro cobro mensual de $999.
