/**
 * Renderiza todas las plantillas de correo a archivos para poder verlas.
 *
 * Existe porque el HTML de correo no se puede firmar desde un navegador: el motor Word
 * de Outlook es el que rompe las tablas y nada más lo reproduce. Esto genera los
 * archivos; la revisión de verdad es arrastrarlos a un Gmail, un Outlook.com y un
 * iCloud reales antes de desplegar.
 *
 *   npx tsx scripts/preview-emails.ts                 # escribe a ./preview
 *   npx tsx scripts/preview-emails.ts --out /tmp/x    # otra carpeta
 *   npx tsx scripts/preview-emails.ts --send a@b.com  # manda todas de verdad
 */
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { TEMPLATE_FIXTURES, sendTemplate } from "../emails.js";

function flag(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  if (i !== -1 && process.argv[i + 1]) return process.argv[i + 1];
  const inline = process.argv.find((a) => a.startsWith(`--${name}=`));
  return inline?.split("=").slice(1).join("=");
}

const outDir = path.resolve(flag("out") ?? "preview");
const sendTo = flag("send");

const names = Object.keys(TEMPLATE_FIXTURES);
await mkdir(outDir, { recursive: true });

const index: string[] = [];

for (const name of names) {
  const email = TEMPLATE_FIXTURES[name]();
  await writeFile(path.join(outDir, `${name}.html`), email.html, "utf8");
  await writeFile(path.join(outDir, `${name}.txt`), `Asunto: ${email.subject}\n\n${email.text}`, "utf8");
  index.push(`<li><a href="./${name}.html">${name}</a> — ${email.subject} (<a href="./${name}.txt">texto</a>)</li>`);
  console.log(`✓ ${name}`);
}

await writeFile(
  path.join(outDir, "index.html"),
  `<!doctype html><meta charset="utf-8"><title>Plantillas de MailMask</title>
<body style="font-family:sans-serif;max-width:640px;margin:40px auto;line-height:1.7">
<h1>Plantillas de correo</h1><ul>${index.join("")}</ul></body>`,
  "utf8",
);

console.log(`\n${names.length} plantillas en ${outDir}`);
console.log(`Abre: file://${path.join(outDir, "index.html")}`);

if (sendTo) {
  if (!process.env.AWS_ACCESS_KEY_ID) {
    console.error("\nFalta AWS_ACCESS_KEY_ID para poder enviar.");
    process.exit(1);
  }
  console.log(`\nEnviando ${names.length} correos a ${sendTo}…`);
  for (const name of names) {
    const email = TEMPLATE_FIXTURES[name]();
    try {
      await sendTemplate(sendTo, { ...email, subject: `[PRUEBA ${name}] ${email.subject}` });
      console.log(`  ✓ ${name}`);
    } catch (err) {
      console.error(`  ✗ ${name}: ${String(err)}`);
    }
  }
}
