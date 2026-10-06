// llms.txt es un contrato con los agentes: lo que anuncia tiene que existir y no puede
// contradecir a /docs. Ficha: docs/agents/seo-paginas-publicas.md
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const llms = readFileSync(new URL("./public/llms.txt", import.meta.url), "utf8");
const docs = readFileSync(new URL("./public/docs.html", import.meta.url), "utf8").replace(/<[^>]+>/g, "");

// Cambiar a `true` el día que `mailmask-cli` exista en npm — y entonces cambiar la instalación
// en cli/README.md, public/docs.html#cli y public/llms.txt en el mismo PR.
const CLI_PUBLICADO_EN_NPM = false;

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
