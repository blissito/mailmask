/**
 * Upload MailMask documentation as RAG documents to the Formmy agent.
 *
 * Usage:
 *   FORMMY_SECRET_KEY=sk_live_xxx npx tsx scripts/upload-docs.ts
 */

import { Formmy } from "@formmy.app/chat";
import { readFileSync } from "fs";

const AGENT_ID = "6962a45fbe5361f571b8369e";

/** Strip HTML tags and decode common entities */
function stripHtml(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<[^>]+>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&mdash;/g, "—")
    .replace(/&oacute;/g, "ó")
    .replace(/&aacute;/g, "á")
    .replace(/&iacute;/g, "í")
    .replace(/&uacute;/g, "ú")
    .replace(/&eacute;/g, "é")
    .replace(/&Uacute;/g, "Ú")
    .replace(/&nbsp;/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

/** Extract sections from docs.html by splitting on <h2> */
function extractSections(html: string): { title: string; content: string }[] {
  const mainMatch = html.match(/<main[\s\S]*?<\/main>/i);
  if (!mainMatch) return [];

  const main = mainMatch[0];
  // Split by h2 tags
  const parts = main.split(/<h2[^>]*>/i);
  const sections: { title: string; content: string }[] = [];

  // First part is the intro (before first h2)
  const introText = stripHtml(parts[0]);
  if (introText.length > 50) {
    sections.push({ title: "Introducción - SDK de MailMask", content: introText });
  }

  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    // Title is text before closing </h2>
    const titleMatch = part.match(/^[^<]*(?=<\/h2>)/i);
    const title = titleMatch ? stripHtml(titleMatch[0]) : `Sección ${i}`;
    const content = stripHtml(part.replace(/^[^<]*<\/h2>/i, ""));
    if (content.length > 20) {
      sections.push({ title, content });
    }
  }

  return sections;
}

/** Additional knowledge docs not in docs.html */
const EXTRA_DOCS = [
  {
    title: "Planes y Precios de MailMask",
    content: `MailMask ofrece 3 planes:

- Básico (gratis): 1 dominio, 5 aliases, forwarding básico, bandeja de entrada
- Freelancer ($5 USD/mes): 3 dominios, 25 aliases, envío de emails, reglas avanzadas
- Developer ($15 USD/mes): 10 dominios, aliases ilimitados, SMTP relay, API keys, SDK access, soporte prioritario

Los planes legacy (Pro y Agencia) ya no están disponibles para nuevos usuarios.

SMTP relay solo está disponible en plan Developer.
API keys y acceso al SDK requieren plan Developer o superior.
El paquete npm del SDK es @easybits.cloud/mailmask.
El dominio del servicio es mailmask.studio.`,
  },
  {
    title: "Configuración de Dominio Propio",
    content: `Para usar un dominio propio con MailMask:

1. Agregar el dominio desde el Dashboard o via API (mm.domains.create("example.com"))
2. Configurar registros DNS:
   - MX record: apuntando a inbound-smtp.us-east-1.amazonaws.com (prioridad 10)
   - TXT record de verificación: proporcionado por MailMask al agregar el dominio
   - CNAMEs de DKIM: 3 registros CNAME para firma DKIM (proporcionados por MailMask)
3. Verificar el dominio desde el Dashboard o via API (mm.domains.verify("domain-id"))
4. Consultar estado de salud DNS: mm.domains.health("domain-id")

La verificación puede tomar unos minutos mientras se propagan los registros DNS.
MailMask usa AWS SES para envío y recepción de email.`,
  },
  {
    title: "Configuración SMTP Relay",
    content: `SMTP relay permite enviar emails desde código o aplicaciones SaaS usando credenciales SMTP estándar.

Solo disponible en plan Developer.

Crear credencial:
const cred = await mm.smtp.create("domain-id", "Mi app");
// cred.smtpPassword solo se muestra una vez

Configuración SMTP:
- Host: email-smtp.us-east-1.amazonaws.com
- Puerto: 587 (STARTTLS) o 465 (TLS)
- Usuario: el accessKeyId de la credencial
- Contraseña: el smtpPassword generado

Cada credencial SMTP tiene un IAM user con policy scoped al dominio específico.

Listar credenciales: mm.smtp.list("domain-id")
Revocar credencial: mm.smtp.revoke("domain-id", "cred-id")`,
  },
];

async function main() {
  const secretKey = process.env.FORMMY_SECRET_KEY;
  if (!secretKey) {
    console.error("Error: FORMMY_SECRET_KEY env var required");
    process.exit(1);
  }

  const formmy = new Formmy({ secretKey, baseUrl: "https://formmy.app" });

  // 1. Delete existing documents for idempotency
  console.log("Listing existing documents...");
  const { documents: existing } = await formmy.documents.list(AGENT_ID);
  if (existing.length > 0) {
    console.log(`Deleting ${existing.length} existing documents...`);
    for (const doc of existing) {
      await formmy.documents.delete(AGENT_ID, doc.id);
    }
    console.log("Deleted.");
  }

  // 2. Extract sections from docs.html
  const docsHtml = readFileSync("public/docs.html", "utf-8");
  const sections = extractSections(docsHtml);
  console.log(`Extracted ${sections.length} sections from docs.html`);

  // 3. Combine all documents
  const allDocs = [
    ...sections.map((s) => ({
      title: s.title,
      content: s.content,
      metadata: { source: "docs.html" },
    })),
    ...EXTRA_DOCS.map((d) => ({
      title: d.title,
      content: d.content,
      metadata: { source: "manual" },
    })),
  ];

  console.log(`Uploading ${allDocs.length} documents...`);
  const result = await formmy.documents.bulkCreate(AGENT_ID, allDocs);
  console.log(`Created ${result.documents.length} documents:`);
  for (const doc of result.documents) {
    console.log(`  - ${doc.title} (${doc.chunkCount} chunks)`);
  }

  console.log("\nDone! The agent now has access to the documentation.");
}

main().catch((err) => {
  console.error("Failed:", err);
  process.exit(1);
});
