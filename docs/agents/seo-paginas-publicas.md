# SEO de las páginas públicas (`public/*.html`, `public/llms.txt`)

**Qué:** convenciones que `/docs` ya cumple y `docs-seo.test.ts` vigila; aplican igual a
la landing, pricing y el blog cuando se les haga su pase.

- **Un solo bloque de metas** arriba del `<style>`: title (≤ 60), description (140–160),
  canonical, hreflang `es-MX` + `x-default`, OG y Twitter. Nada de metas sueltas más abajo.
- **JSON-LD en un único `@graph`** con `#org` (Organization) y `#website` (WebSite) como
  nodos compartidos; el resto los referencia por `@id` en vez de repetir nombre y logo.
- **`dateModified` = la fecha visible** («Actualizado: <fecha>», con `<time datetime>`).
  Al editar la página, se cambian las dos y el `lastmod` del sitemap.
- **`hasPart` apunta a anclas que existen**; los `id` de los `<h2>` no se renombran
  (rompe enlaces y el ranking por sección).
- **Imagen social propia** (1200×630 JPEG, < 200 KB), renderizada con Chromium desde HTML
  (`scripts/og-docs.html`), no con IA. Tras el deploy hay que refrescarla a mano en el Post
  Inspector de LinkedIn: tiene la anterior en caché.
- **`llms.txt` es un contrato con agentes:** no puede contradecir `/docs` ni anunciar
  instalaciones que no existen (hoy la CLI no está en npm). Lo vigila `llms.test.ts`.
- **Sitemap:** `npx tsx scripts/gen-sitemap.ts` toma el `lastmod` del último commit con
  `git log`; en un checkout sin `.git` (tarball) cae al mtime y deja todas las fechas
  iguales — córrelo en un clon con historia, o edita a mano sólo el `<lastmod>` que cambió.
- **Trampa:** `github_push_files` sube texto; un binario (la imagen OG) va con
  `contentBase64` o `fromUrl`, nunca como `content`.
