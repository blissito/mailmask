// llms.txt es un contrato con los agentes: lo que anuncia tiene que existir y no puede
// contradecir a /docs. Ficha: docs/agents/seo-paginas-publicas.md
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { HOST } from "./seo-checks.ts";

const llms = readFileSync(new URL("./public/llms.txt", import.meta.url), "utf8");
const docs = readFileSync(new URL("./public/docs.html", import.meta.url), "utf8").replace(/<[^>]+>/g, "");

// Cambiar a `true` el día que `mailmask-cli` exista en npm — y entonces cambiar la instalación
// en cli/README.md, public/docs.html#cli y public/llms.txt en el mismo PR.
const CLI_PUBLICADO_EN_NPM = false;

// Rutas del sitemap que llms.txt no tiene por qué anunciar: los artículos del blog se vigilan
// aparte (uno por artículo) y el resto son pantallas de la app, no páginas públicas.
const EXCLUIDAS = ["/login", "/register", "/terms", "/privacy"];

/** URLs del sitemap que sí son páginas públicas: todas menos los artículos `/blog/<slug>` y EXCLUIDAS. */
function paginasPublicas(sitemap: string): string[] {
  return [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)]
    .map((m) => m[1])
    .filter((url) => {
      if (!url.startsWith(`${HOST}/`)) return false;
      const ruta = url.slice(HOST.length);
      return !ruta.startsWith("/blog/") && !EXCLUIDAS.includes(ruta);
    });
}

const escaparRegex = (texto: string) => texto.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

test("llms.txt abre con un título `# ` y un blockquote de resumen", () => {
  assert.match(llms, /^# \S/);
  const lineas = llms.split("\n");
  assert.match(lineas[2], /^> /, "la tercera línea debe abrir el blockquote de resumen");
});

test("el número de capacidades anunciado coincide con la lista numerada", () => {
  const numeros: Record<string, number> = { tres: 3, cuatro: 4, cinco: 5, seis: 6, siete: 7 };
  const anuncio = llms.match(/\b(tres|cuatro|cinco|seis|siete)\s+capacidades/i);
  assert.ok(anuncio, "llms.txt no anuncia 'N capacidades'");
  const seccion = llms.split("## Qué hace exactamente")[1]?.split(/\n## /)[0] ?? "";
  const items = seccion.split("\n").filter((l) => /^\d+\.\s/.test(l));
  assert.equal(items.length, numeros[anuncio[1].toLowerCase()]);
});

test("no instruye `npm i mailmask-cli` mientras el paquete no esté publicado", { skip: CLI_PUBLICADO_EN_NPM }, () => {
  assert.doesNotMatch(llms, /npm\s+(i|install)\b[^\n]*mailmask-cli/);
  assert.doesNotMatch(llms, /npx\s+mailmask-cli/);
  assert.match(llms, /a[uú]n no (est[aá] )?publicad[oa] en npm/i, "debe decir que aún no está en npm");
});

test("llms.txt no niega la compra de dominios que /docs documenta", () => {
  if (/registrations\.register/.test(docs)) {
    assert.doesNotMatch(llms, /No es un registrador de dominios/i);
    assert.match(llms, /comprar? (el|un) dominio|compra de dominios/i);
  }
});

test("la línea de Enlaces cubre lo que documenta /docs", () => {
  const linea = llms.split("\n").find((l) => l.includes("https://www.mailmask.studio/docs") && l.startsWith("- "));
  assert.ok(linea, "no hay renglón de Documentación en Enlaces");
  for (const tema of ["Skills", "SDK", "CLI", "API REST", "SMTP", "MCP"]) {
    assert.ok(linea.includes(tema), `Enlaces → Documentación no menciona ${tema}`);
  }
});

test("Enlaces incluye las landings públicas, cada una con su descripción", () => {
  const enlaces = llms.split("## Enlaces")[1]?.split(/\n## /)[0] ?? "";
  const lineas = enlaces.split("\n");
  const landings: Array<[string, string]> = [
    ["Bandeja compartida", "https://www.mailmask.studio/bandeja-compartida"],
    ["Dominios (registrar o transferir)", "https://www.mailmask.studio/dominios"],
    ["Alternativa a Google Workspace", "https://www.mailmask.studio/alternativa-google-workspace"],
    ["Correo en el dominio que ya tienes", "https://www.mailmask.studio/correo-en-tu-dominio"],
  ];
  for (const [etiqueta, url] of landings) {
    const i = lineas.indexOf(`- ${etiqueta}: ${url}`);
    assert.ok(i >= 0, `Enlaces no trae «- ${etiqueta}: ${url}»`);
    assert.match(lineas[i + 1] ?? "", /^ {2}\S/, `«${etiqueta}» no lleva su descripción sangrada debajo`);
  }
});

test("la descripción de cada landing en Enlaces es la de su página", () => {
  const enlaces = llms.split("## Enlaces")[1]?.split(/\n## /)[0] ?? "";
  const lineas = enlaces.split("\n");
  for (const slug of ["bandeja-compartida", "dominios", "alternativa-google-workspace", "correo-en-tu-dominio"]) {
    const html = readFileSync(new URL(`./public/${slug}.html`, import.meta.url), "utf8");
    const meta = html.match(/<meta\s+name="description"\s+content="([^"]+)"/);
    assert.ok(meta, `public/${slug}.html no trae meta description`);
    assert.ok(lineas.includes("  " + meta[1]), `Enlaces no repite la description de /${slug}`);
  }
});

// El sitemap es la fuente: una página pública nueva entra a la vigilancia sola, sin tocar esta
// lista a mano (por eso no se usa `paginasDelSitemap` de seo-checks.ts: su filtro es otro).
test("toda landing del sitemap aparece en llms.txt", () => {
  const sitemap = readFileSync(new URL("./public/sitemap.xml", import.meta.url), "utf8");
  const urls = paginasPublicas(sitemap);
  assert.ok(urls.length > 0, "no se extrajo ninguna URL del sitemap: revisa el patrón de <loc>");
  for (const url of urls) {
    // Token completo: `/dominios` no puede darse por presente por el `/dominios-x` de otra línea.
    const enLlms = new RegExp(`${escaparRegex(url)}(?=$|\\s|\\)|\\.(?:\\s|$))`);
    assert.match(llms, enLlms, `llms.txt no menciona ${url}`);
  }
});
