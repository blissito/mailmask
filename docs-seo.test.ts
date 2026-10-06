// SEO de /docs: un solo bloque de metas, JSON-LD en un @graph y una imagen social propia que
// existe y mide lo que dicen sus metas. Ficha: docs/agents/seo-paginas-publicas.md
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";

const HOST = "https://www.mailmask.studio";
const html = readFileSync(new URL("./public/docs.html", import.meta.url), "utf8");
const head = html.slice(0, html.indexOf("</head>"));

const metas = [...head.matchAll(/<meta\s+(name|property)="([^"]+)"\s+content="([^"]*)"\s*\/?>/g)].map((m) => ({ clave: m[2], valor: m[3] }));
const meta = (clave: string) => metas.find((m) => m.clave === clave)?.valor;

function grafo(): any[] {
  const scripts = [...head.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)];
  assert.equal(scripts.length, 1, "el JSON-LD va en un solo <script>");
  const json = JSON.parse(scripts[0][1]);
  assert.ok(Array.isArray(json["@graph"]), "falta @graph");
  return json["@graph"];
}

/** Ancho y alto de un JPEG leyendo su marcador SOF. */
function medidasJpeg(buf: Buffer): { w: number; h: number } {
  assert.equal(buf.readUInt16BE(0), 0xffd8, "no es un JPEG");
  let i = 2;
  while (i < buf.length) {
    assert.equal(buf[i], 0xff);
    const marcador = buf[i + 1];
    const largo = buf.readUInt16BE(i + 2);
    if (marcador >= 0xc0 && marcador <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marcador)) {
      return { h: buf.readUInt16BE(i + 5), w: buf.readUInt16BE(i + 7) };
    }
    i += 2 + largo;
  }
  throw new Error("JPEG sin SOF");
}

test("un title, una description, un canonical y un H1", () => {
  assert.equal((head.match(/<title>/g) ?? []).length, 1);
  assert.equal(metas.filter((m) => m.clave === "description").length, 1);
  assert.equal((head.match(/rel="canonical"/g) ?? []).length, 1);
  assert.equal((html.match(/<h1[\s>]/g) ?? []).length, 1);
  assert.match(html, /<h1[^>]*>Documentaci(ó|&oacute;)n de MailMask<\/h1>/);
  assert.match(head, new RegExp(`rel="canonical" href="${HOST}/docs"`));
});

test("title ≤ 60 y description entre 140 y 160 caracteres", () => {
  const title = head.match(/<title>([^<]*)<\/title>/)![1];
  assert.ok(title.length <= 60, `title de ${title.length}`);
  const d = meta("description")!.length;
  assert.ok(d >= 140 && d <= 160, `description de ${d}`);
});

test("las metas no se repiten y hay hreflang es-MX y x-default", () => {
  const claves = metas.map((m) => m.clave);
  assert.deepEqual(claves.filter((c, i) => claves.indexOf(c) !== i), []);
  assert.match(head, /hreflang="es-MX" href="https:\/\/www\.mailmask\.studio\/docs"/);
  assert.match(head, /hreflang="x-default" href="https:\/\/www\.mailmask\.studio\/docs"/);
});

test("OG y Twitter apuntan a la imagen propia de /docs y repiten title y description", () => {
  const img = `${HOST}/img/og-docs.jpg`;
  assert.equal(meta("og:image"), img);
  assert.equal(meta("twitter:image"), img);
  assert.equal(meta("twitter:card"), "summary_large_image");
  assert.equal(meta("og:title"), head.match(/<title>([^<]*)<\/title>/)![1]);
  assert.equal(meta("og:description"), meta("description"));
  assert.equal(meta("twitter:description"), meta("description"));
});

test("og-docs.jpg existe, mide lo que dicen las metas y pesa menos de 200 KB", () => {
  const ruta = new URL("./public/img/og-docs.jpg", import.meta.url);
  assert.ok(existsSync(ruta), "falta public/img/og-docs.jpg");
  const buf = readFileSync(ruta);
  assert.ok(buf.length < 200 * 1024, `pesa ${buf.length} bytes`);
  const { w, h } = medidasJpeg(buf);
  assert.equal(String(w), meta("og:image:width"));
  assert.equal(String(h), meta("og:image:height"));
  assert.deepEqual([w, h], [1200, 630]);
  assert.ok(existsSync(new URL("./scripts/og-docs.html", import.meta.url)), "falta la plantilla scripts/og-docs.html");
});

test("JSON-LD: un @graph con Organization, WebSite, TechArticle, SoftwareSourceCode (SDK) y BreadcrumbList", () => {
  const nodos = grafo();
  const tipos = nodos.map((n) => n["@type"]).sort();
  assert.deepEqual(tipos, ["BreadcrumbList", "Organization", "SoftwareSourceCode", "TechArticle", "WebSite"]);
  const ids = new Set(nodos.map((n) => n["@id"]));
  assert.ok(ids.has(`${HOST}/#org`) && ids.has(`${HOST}/#website`));
  // Toda referencia {"@id"} apunta a un nodo del grafo.
  for (const m of JSON.stringify(nodos).matchAll(/\{"@id":"([^"]+)"\}/g)) assert.ok(ids.has(m[1]), `@id colgante ${m[1]}`);
});

test("JSON-LD: la CLI no aparece como software descargable mientras no esté en npm", () => {
  const apps = grafo().filter((n) => n["@type"] === "SoftwareSourceCode");
  for (const a of apps) assert.doesNotMatch(JSON.stringify(a), /mailmask-cli|"name":"MailMask CLI"/i);
  assert.doesNotMatch(JSON.stringify(grafo()), /mailmask-cli/);
});

test("dateModified coincide con la fecha visible y datePublished no la supera", () => {
  const art = grafo().find((n) => n["@type"] === "TechArticle");
  assert.match(art.dateModified, /^\d{4}-\d{2}-\d{2}$/);
  const visible = html.match(/Actualizado:\s*<time datetime="(\d{4}-\d{2}-\d{2})">/);
  assert.ok(visible, "falta «Actualizado: <time datetime=…>» a la vista");
  assert.equal(visible[1], art.dateModified);
  assert.ok(art.datePublished <= art.dateModified);
});

test("las anclas de hasPart existen en la página", () => {
  const art = grafo().find((n) => n["@type"] === "TechArticle");
  assert.ok(art.hasPart.length >= 10);
  for (const p of art.hasPart) {
    assert.ok(p.url.startsWith(`${HOST}/docs#`), p.url);
    const id = p.url.split("#")[1];
    assert.ok(html.includes(`id="${id}"`), `no existe id="${id}"`);
  }
});

test("el JSON-LD no declara SoftwareApplication sin aggregateRating/review (Google lo marca inválido y no inventamos ratings)", () => {
  assert.doesNotMatch(JSON.stringify(grafo()), /SoftwareApplication|MobileApplication|WebApplication/);
});
