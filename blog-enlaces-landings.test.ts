// Enlaces internos del blog a las landings: cada artículo manda a la suya UNA vez, desde el
// texto y con un ancla que dice a dónde va.
//
// El blog es lo que más tráfico orgánico trae y las landings no recibían ni un enlace desde
// ahí. Los dos artículos de Google Workspace ya enlazaban `/alternativa-google-workspace`;
// aquí entran los tres que faltaban y los cinco quedan amarrados: uno por artículo, ni cero
// ni dos, porque el enlace repetido se lee como relleno y diluye el que importa.
// Reglas de la familia: `seo-checks.ts` · Ficha: `docs/agents/seo-paginas-publicas.md`
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const leer = (ruta: string) => readFileSync(new URL(`./${ruta}`, import.meta.url), "utf8");

/** Artículo del blog → su landing. Un artículo sin par aquí no lleva enlace a ninguna. */
const PARES: Array<[articulo: string, landing: string]> = [
  ["public/blog/bandeja-compartida-tutorial.html", "/bandeja-compartida"],
  ["public/blog/bandeja-compartida-vs-helpdesk.html", "/bandeja-compartida"],
  ["public/blog/iniciar-negocio-email-profesional.html", "/dominios"],
  ["public/blog/migrar-google-workspace-a-mailmask.html", "/alternativa-google-workspace"],
  ["public/blog/email-profesional-sin-google-workspace.html", "/alternativa-google-workspace"],
];

/** «Aquí» o «ver más» no describen la página destino: el ancla tiene que nombrarla. */
const GENERICA = /^(aquí|acá|clic|click|este enlace|ver más|más información|más detalles)[\s.!]*$/i;

const escapar = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** El `href` es EXACTAMENTE la landing: `/bandeja-compartida` no se confunde con `/bandeja-compartida-tutorial`. */
const enlacesA = (html: string, landing: string) =>
  [...html.matchAll(new RegExp(`<a\\s[^>]*href=["']${escapar(landing)}["'][^>]*>([\\s\\S]*?)</a>`, "gi"))];

/** El cuerpo: fuera el `<head>`, que trae sus propios `href` (canonical, fuentes) y el `@graph`. */
const cuerpo = (html: string) => html.slice(html.indexOf("</head>"));
const head = (html: string) => html.slice(0, html.indexOf("</head>"));
const texto = (ancla: string) => ancla.replace(/<[^>]*>/g, "").replace(/\s+/g, " ").trim();

test("cada artículo enlaza su landing una sola vez, desde el cuerpo", () => {
  for (const [articulo, landing] of PARES) {
    const html = leer(articulo);
    const encontrados = enlacesA(cuerpo(html), landing);
    assert.equal(encontrados.length, 1, `${articulo} lleva ${encontrados.length} enlaces a ${landing} en el texto (debe ser exactamente uno)`);
    assert.equal(enlacesA(head(html), landing).length, 0, `${articulo} metió el enlace a ${landing} en el <head>`);
  }
});

test("el ancla describe la página destino y no es genérica", () => {
  for (const [articulo, landing] of PARES) {
    const [enlace] = enlacesA(cuerpo(leer(articulo)), landing);
    assert.ok(enlace, `${articulo} no tiene enlace a ${landing}`);
    const ancla = texto(enlace[1]);
    assert.ok(ancla.length >= 8, `${articulo}: el ancla «${ancla}» es demasiado corta para decir a dónde va`);
    assert.doesNotMatch(ancla, GENERICA, `${articulo}: el ancla «${ancla}» no describe ${landing}`);
  }
});
