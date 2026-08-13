/**
 * Genera public/sitemap.xml desde el sistema de archivos.
 *
 * Antes era estático: cada post nuevo había que agregarlo a mano (y tarde o temprano se
 * olvida uno), y los 32 `lastmod` eran idénticos y viejos, que es la forma más rápida de
 * que Google ignore el sitemap entero.
 *
 *   npx tsx scripts/gen-sitemap.ts
 */
import { readdirSync, writeFileSync, statSync } from "fs";
import { execSync } from "child_process";
import { join } from "path";

const HOST = "https://www.mailmask.studio";
const PUBLIC = new URL("../public", import.meta.url).pathname;

// Fecha del último commit que tocó el archivo. Es la señal honesta de frescura; el mtime
// del disco cambia con cualquier checkout.
function lastmod(file: string): string {
  try {
    const out = execSync(`git log -1 --format=%cs -- "${file}"`, { encoding: "utf8" }).trim();
    if (out) return out;
  } catch { /* sin git o archivo sin commits */ }
  return statSync(file).mtime.toISOString().slice(0, 10);
}

const paginas: { ruta: string; archivo: string; freq: string; prio: string }[] = [
  { ruta: "/", archivo: "landing.html", freq: "weekly", prio: "1.0" },
  { ruta: "/pricing", archivo: "pricing.html", freq: "weekly", prio: "0.9" },
  { ruta: "/docs", archivo: "docs.html", freq: "weekly", prio: "0.9" },
  { ruta: "/blog", archivo: "blog/index.html", freq: "weekly", prio: "0.8" },
  { ruta: "/register", archivo: "register.html", freq: "monthly", prio: "0.6" },
  { ruta: "/login", archivo: "login.html", freq: "monthly", prio: "0.4" },
  { ruta: "/terms", archivo: "terms.html", freq: "yearly", prio: "0.3" },
  { ruta: "/privacy", archivo: "privacy.html", freq: "yearly", prio: "0.3" },
];

const posts = readdirSync(join(PUBLIC, "blog"))
  .filter((f) => f.endsWith(".html") && f !== "index.html")
  .sort();

const urls = [
  ...paginas.map((p) => ({
    loc: HOST + p.ruta,
    lastmod: lastmod(join(PUBLIC, p.archivo)),
    changefreq: p.freq,
    priority: p.prio,
  })),
  ...posts.map((f) => ({
    loc: `${HOST}/blog/${f.replace(/\.html$/, "")}`,
    lastmod: lastmod(join(PUBLIC, "blog", f)),
    changefreq: "monthly",
    priority: "0.7",
  })),
];

const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map((u) =>
  `  <url><loc>${u.loc}</loc><lastmod>${u.lastmod}</lastmod><changefreq>${u.changefreq}</changefreq><priority>${u.priority}</priority></url>`,
).join("\n")}
</urlset>
`;

writeFileSync(join(PUBLIC, "sitemap.xml"), xml);
console.log(`sitemap.xml generado: ${urls.length} URLs (${posts.length} posts)`);
