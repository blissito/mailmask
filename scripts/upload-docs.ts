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
  {
    title: "Servidor MCP (Model Context Protocol)",
    content: `MailMask planea ofrecer un servidor MCP (Model Context Protocol) para integrar con asistentes de IA como Claude Desktop, Cursor, y otros clientes MCP.

MCP es un protocolo abierto que permite a los modelos de IA interactuar con servicios externos de forma segura y estructurada. Con el servidor MCP de MailMask, podrás gestionar tu email directamente desde tu asistente de IA.

Paquete planificado: @easybits.cloud/mailmask-mcp

Ejemplo de configuración para Claude Desktop (claude_desktop_config.json):
{
  "mcpServers": {
    "mailmask": {
      "command": "npx",
      "args": ["-y", "@easybits.cloud/mailmask-mcp"],
      "env": {
        "MAILMASK_API_KEY": "tu-api-key"
      }
    }
  }
}

Herramientas planificadas:
- Crear y gestionar aliases de email
- Gestionar reglas de forwarding
- Enviar emails desde dominios verificados
- Listar dominios y su estado de verificación
- Consultar bandeja de entrada

Estado: próximamente. El paquete aún no está publicado en npm. Se requiere plan Developer para usar el servidor MCP (necesita API key).`,
  },
  {
    title: "Bandeja de Entrada (Inbox)",
    content: `La Bandeja de Entrada es una interfaz de inbox colaborativa para gestionar emails recibidos en tus dominios. Disponible desde el plan Freelancer.

Endpoints de la API:

Listar conversaciones:
GET /api/bandeja/conversations?domainId=xxx&status=open&page=1&limit=20
Parámetros opcionales: status (open, snoozed, closed, deleted), search, assignedTo, tag, priority

Detalle de conversación:
GET /api/bandeja/conversations/:id

Responder a conversación:
POST /api/bandeja/conversations/:id/reply
Body: { "html": "<p>Respuesta</p>", "fromAlias": "alias@tudominio.com" }

Asignar conversación a un agente:
POST /api/bandeja/conversations/:id/assign
Body: { "agentId": "id-del-agente" }

Agregar nota interna (no visible al remitente):
POST /api/bandeja/conversations/:id/note
Body: { "content": "Nota interna para el equipo" }

Actualizar conversación (estado, tags, prioridad):
PATCH /api/bandeja/conversations/:id
Body: { "status": "closed", "tags": ["soporte"], "priority": "urgent" }

Eliminar conversación (soft delete):
DELETE /api/bandeja/conversations/:id

Restaurar conversación eliminada:
POST /api/bandeja/conversations/:id/restore

Descargar adjuntos:
GET /api/bandeja/conversations/:id/attachments/:msgIdx/:attIdx

Actualizaciones en tiempo real via SSE:
GET /api/bandeja/sse?domainId=xxx
Se envían eventos cuando llegan nuevos emails o se actualizan conversaciones.

Estados de conversación: open, snoozed, closed, deleted
Prioridades: normal, urgent

Permisos: el owner del dominio tiene acceso completo. Los agentes invitados tienen acceso limitado según su rol.`,
  },
  {
    title: "Envío Masivo (Bulk Send)",
    content: `El envío masivo permite enviar un email a múltiples destinatarios en una sola operación. Requiere dominio verificado y plan Freelancer o superior.

Endpoint para crear envío masivo:
POST /api/domains/:id/send-bulk
Body: {
  "recipients": ["user1@example.com", "user2@example.com"],
  "subject": "Asunto del email",
  "html": "<p>Contenido HTML</p>",
  "fromAlias": "noreply@tudominio.com"
}
Máximo 10,000 destinatarios por envío.
Retorna un jobId para consultar el estado.

Consultar estado del envío:
GET /api/domains/:id/bulk/:jobId
Retorna: estado del job, total de destinatarios, enviados, fallidos.

Estados del job: queued, processing, completed, failed

Usando el SDK:
const job = await mm.send.bulkSend("domain-id", {
  recipients: ["user1@example.com", "user2@example.com"],
  subject: "Asunto",
  html: "<p>Contenido</p>",
  fromAlias: "noreply@tudominio.com"
});

const status = await mm.send.bulkStatus("domain-id", job.id);
console.log(status.sent, status.failed, status.status);

Nota: el SDK usa mm.send.bulkSend() y mm.send.bulkStatus() para estas operaciones.`,
  },
  {
    title: "Miembros y Roles (RBAC)",
    content: `MailMask permite invitar miembros (agentes) a un dominio con diferentes roles y permisos. Esto facilita la colaboración en equipo para gestionar emails.

Roles disponibles:
- owner: acceso completo — gestionar dominio, aliases, reglas, miembros, bandeja, envío
- admin: lectura, escritura y gestión de miembros (no puede eliminar dominio ni transferir ownership)
- agent: solo lectura — puede ver bandeja y responder conversaciones asignadas

Invitar un agente:
POST /api/domains/:id/agents/invite
Body: { "email": "agente@email.com", "name": "Nombre", "role": "agent" }
Envía un email de invitación con un link de aceptación.

Aceptar invitación:
GET /api/agents/accept?token=xxx
El agente hace click en el link del email para unirse al dominio.

Listar agentes de un dominio:
GET /api/domains/:id/agents
Retorna la lista de agentes con su nombre, email, rol y estado.

Eliminar un agente:
DELETE /api/domains/:id/agents/:agentId
Solo el owner o admin puede eliminar agentes.

Los planes tienen límites en el número de agentes por dominio. El plan Developer permite más agentes que Freelancer.

Todos los endpoints de dominio verifican permisos usando el sistema RBAC interno (checkDomainAccess). Si un usuario no tiene el rol necesario, recibe un error 403.`,
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

  console.log(`Uploading ${allDocs.length} documents one by one...`);
  let created = 0;
  for (const doc of allDocs) {
    try {
      const { document } = await formmy.documents.create(AGENT_ID, doc);
      console.log(`  ✓ ${document.title} (${document.chunkCount} chunks)`);
      created++;
    } catch (err: any) {
      console.error(`  ✗ ${doc.title}: ${err.message}`);
    }
  }
  console.log(`\n${created}/${allDocs.length} documents uploaded.`);

  console.log("\nDone! The agent now has access to the documentation.");
}

main().catch((err) => {
  console.error("Failed:", err);
  process.exit(1);
});
