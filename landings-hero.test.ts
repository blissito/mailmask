// El hero ilustrado de las cuatro landings de venta: MISMO layout en las cuatro y una
// ilustración propia por página (3:2, 1200×800, sin recorte). Ficha:
// docs/agents/diseno-landings.md · Reglas comunes de lo público: seo-checks.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, statSync } from "node:fs";

import { medidasJpeg } from "./seo-checks.ts";

const local = (ruta: string) => new URL(`./${ruta}`, import.meta.url);
const leer = (ruta: string) => readFileSync(local(ruta), "utf8");

/** Las cuatro landings con hero ilustrado. */
const PAGINAS = [
  { ruta: "/bandeja-compartida", archivo: "public/bandeja-compartida.html", slug: "bandeja-compartida" },
  { ruta: "/pricing", archivo: "public/pricing.html", slug: "pricing" },
  { ruta: "/dominios", archivo: "public/dominios.html", slug: "dominios" },
  { ruta: "/alternativa-google-workspace", archivo: "public/alternativa-google-workspace.html", slug: "alternativa-google-workspace" },
] as const;

/** El layout del hero, idéntico en las cuatro: es lo que las hace la misma familia. */
const GRID = "grid lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)] gap-10 items-center";
const FIGURA = '<figure class="hero-il">';

/** El hero de una página: de su comentario `<!-- Hero -->` al `</section>` que lo cierra. */
function bloqueHero(archivo: string): string {
  const html = leer(archivo);
  const abre = html.indexOf("<!-- Hero -->");
  assert.ok(abre >= 0, `${archivo}: falta el comentario <!-- Hero -->`);
  const cierra = html.indexOf("</section>", abre);
  assert.ok(cierra > abre, `${archivo}: el hero no cierra con </section>`);
  return html.slice(abre, cierra);
}

for (const { ruta, archivo, slug } of PAGINAS) {
  test(`${ruta}: hero de dos columnas, con el texto antes de la ilustración`, () => {
    const hero = bloqueHero(archivo);
    assert.ok(hero.includes(GRID), `el hero no usa el grid de las cuatro landings: ${GRID}`);
    assert.ok(hero.includes(FIGURA), `el hero no trae ${FIGURA}`);
    // El orden en el DOM es lo que en móvil deja la ilustración debajo del texto.
    const grid = hero.indexOf(GRID);
    const h1 = hero.indexOf("<h1");
    const figura = hero.indexOf(FIGURA);
    assert.ok(grid >= 0 && h1 > grid, "el h1 no va dentro del grid, después de abrirlo");
    assert.ok(figura > h1, "la ilustración va antes que el h1 en el DOM (en móvil quedaría encima)");
  });

  test(`${ruta}: la ilustración es ${slug}-il.jpg, 1200×800, con alt de la escena`, () => {
    const hero = bloqueHero(archivo);
    const [img] = hero.match(/<img[^>]*>/) ?? [];
    assert.ok(img, "el hero no trae <img>");
    assert.match(img, new RegExp(`src="/img/${slug}-il\\.jpg"`), "no es su propia ilustración");
    assert.match(img, /width="1200"/);
    assert.match(img, /height="800"/);
    assert.match(img, /alt="[^"]{30,}"/, "el alt tiene que describir la escena");
    assert.doesNotMatch(img, /alt="(imagen|foto|ilustración) de/i, "el alt describe la escena, no el archivo");
    // Sin `lazy` entra en el primer pintado y no salta al cargar.
    assert.doesNotMatch(img, /loading="lazy"/);
    assert.match(img, /fetchpriority="high"/);
    // El archivo es 3:2 igual que la caja, así que `object-cover` no recorta.
    const bytes = readFileSync(local(`public/img/${slug}-il.jpg`));
    const { w, h } = medidasJpeg(bytes);
    assert.equal(`${w}×${h}`, "1200×800");
    assert.ok(statSync(local(`public/img/${slug}-il.jpg`)).size < 200 * 1024, "la ilustración pesa más de 200 KB");
  });
}

test("la pieza .hero-il está en input.css y en el styles.css que se versiona", () => {
  assert.match(leer("public/css/input.css"), /\.hero-il\s*\{/, "falta la pieza en el CSS fuente");
  // Sin recompilar, en prod faltan clases y el CI pasa verde igual (diseno-landings.md).
  assert.match(leer("public/css/styles.css"), /\.hero-il\s*\{/, "falta recompilar styles.css");
});

test("las cuatro páginas usan el MISMO hero: sólo cambian copy e ilustración", () => {
  // Se tira el texto de la columna izquierda (ahí sí cambia el copy, y /pricing no lleva
  // CTAs a propósito) y se deja sólo el andamiaje: grid, columna, figure e img.
  const andamiaje = (hero: string) =>
    hero
      .replace(/(<div>\s*)<p class="eyebrow[\s\S]*?(<\/div>\s*<figure)/, "$1<texto></texto>$2")
      .replace(/<img[^>]*>/, "<img>")
      .replace(/\s+/g, " ")
      .trim();
  const [bandeja, ...resto] = PAGINAS.map(({ ruta, archivo }) => ({ ruta, hero: andamiaje(bloqueHero(archivo)) }));
  for (const { ruta, hero } of resto) assert.equal(hero, bandeja.hero, `${ruta} diverge del hero común`);
});
