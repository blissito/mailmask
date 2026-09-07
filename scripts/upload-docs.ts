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
    title: "Precios de MailMask: gratis, y $99 MXN por dominio activado",
    content: `Desde el 7 de septiembre de 2026 MailMask no tiene planes. Todas las cuentas son gratis y
lo único que se paga es "activar" un dominio. Todos los precios están en pesos mexicanos (MXN).

Cuenta gratis ($0, sin tarjeta):
- 1 dominio por cuenta (el más antiguo sin activar; un segundo dominio sin activar queda
  bloqueado: guarda el correo en la Bandeja pero no lo reenvía).
- 5 máscaras (alias) que reenvían al buzón que elijas.
- Reenvío hasta 1,000 correos al mes.
- Bandeja para una persona: leer y responder desde tu dominio. Muestra los últimos 7 días y
  guarda 30 por si activas; después se borra.
- No envía correo nuevo (API, Redactar, SMTP). Sí responde desde la Bandeja.
- DKIM + SPF automáticos, API REST y SDK.
- Sin reglas, webhooks, SMTP relay ni buzones IMAP.

Dominio activado — $99 MXN/mes por dominio, o $999 al año (ahorras $189):
- Personas ilimitadas en la Bandeja compartida (asignar, notas, historial completo).
- Buzones IMAP ilimitados con 10 GB compartidos por dominio (Apple Mail, Outlook, Thunderbird).
- Envía como tu@dominio: 50 correos nuevos al día por dominio (API, Redactar, SMTP relay).
  Responder desde la Bandeja nunca gasta de aquí.
- Máscaras ilimitadas; reenvío hasta 10,000 correos al mes por dominio.
- Reglas de enrutamiento, webhooks y SMTP relay.
- Registro de reenvíos 90 días, soporte por email.
- Al cancelar: 30 días de solo lectura y descarga .mbox de los buzones.

Un dominio más son $99 más: no hay planes ni escaleras. 5 dominios = $495 MXN/mes.
Más de 10 dominios: escribir a hola@mailmask.studio.

Bloques (sobre un dominio activado, mes a mes, cancelables):
- +50 GB de buzón: +$99 MXN/mes por bloque, acumulable.
- Si alguien necesita más de 50 envíos al día, que escriba a hola@mailmask.studio.

Los límites se cuentan por dominio, no por cuenta. Hay dos límites distintos: "envíos"
(correo nuevo que el usuario origina, por día) y "reenvío" (correo que llega a una máscara
y se reenvía, por mes). Quien solo reenvía nunca toca el límite de envíos. Al 80% del tope
mensual de reenvíos se avisa por correo; al 100% el correo sigue guardándose en la Bandeja
pero deja de reenviarse hasta el mes siguiente.

Los planes viejos (Básico, Equipo, Freelancer, Developer, Pro, Agencia) ya no existen; quien
pagaba uno conserva lo que tenía sin pagar más.

Comparación: Google Workspace cobra $140 MXN por persona al mes; Help Scout unos $450 MXN
por persona. MailMask cobra por dominio con personas ilimitadas.

Pago con MercadoPago, mes a mes, se cancela cuando quieras.
El paquete npm del SDK es @easybits.cloud/mailmask. El dominio del servicio es mailmask.studio.`,
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
    title: "Registrar, renovar y transferir dominios con MailMask",
    content: `MailMask puede registrar tu dominio, o traer el que ya tienes, y llevarte el DNS. Todo desde el panel; no hace falta cuenta de AWS.

REGISTRAR UNO NUEVO
Se busca desde el panel y se paga una vez por año. El precio depende de la extensión: .com ~$329 MXN, .com.mx ~$589, .mx ~$1,359, .io ~$1,439. Al completarse, MailMask configura solo el DNS (MX, verificación, DKIM, SPF) y el dominio queda listo para recibir correo.

RENOVACIÓN
Se activa desde el panel y se cobra una vez al año, unos 60 días antes del vencimiento, para que el dominio nunca quede en riesgo. Se puede cancelar cuando se quiera.

SI UN COBRO FALLA, EL DOMINIO NO SE PIERDE. MailMask lo mantiene activo e intenta cobrar de nuevo durante los días siguientes, avisando por correo. Nunca se deja expirar un dominio por falta de pago sin haber contactado al cliente. Esta es la duda más común y la respuesta es tranquilizadora: el dominio no está en riesgo inmediato.

TRAER UN DOMINIO (TRANSFERENCIA ENTRANTE)
Tarda de 5 a 7 días. Requisitos: que el dominio tenga más de 60 días, que el candado de transferencia esté desactivado, que la privacidad WHOIS esté apagada temporalmente (si no, no llega el correo de aprobación), y el código de autorización EPP que da el registrador actual. El cliente debe aprobar un correo que le manda su registrador; si no lo contesta, la transferencia se cancela sola.

Antes de mover nada, MailMask copia los registros DNS actuales y se los muestra al cliente para que los revise y apruebe. Es importante decirle que revise esa lista: lo que no esté ahí dejará de funcionar cuando el dominio se mueva. Nada se mueve hasta que apruebe.

Se aceptan todas las extensiones que AWS puede transferir (más de 400), no sólo las que se venden para registro nuevo. Por ejemplo .design, .app, .dev, .studio, .shop y .cloud sí se pueden transferir. La transferencia incluye un año más de registro.

Si la transferencia falla por causas ajenas a MailMask (no se aprobó a tiempo, el candado seguía puesto, el código ya no era válido), se devuelve lo pagado.

LLEVARSE EL DOMINIO (TRANSFERENCIA SALIENTE)
Se pide desde el panel, sin costo y sin necesidad de estar al corriente de la suscripción. El código de autorización llega por correo, no se muestra en pantalla, porque ese código entrega el dominio a quien lo tenga. MailMask no retiene dominios.

EDITOR DE DNS
Si MailMask lleva el DNS, se pueden editar los registros desde el panel, el SDK o hablando con un agente por MCP. También funciona para un dominio registrado en otro lado: se crea la zona, se copian los registros actuales y el cliente cambia los nameservers en su registrador. Hay plantillas para apuntar el dominio a Vercel, Netlify, GitHub Pages, Cloudflare Pages, Render o Fly sin saber qué registros hacen falta.

Los registros que MailMask necesita para el correo (MX, TXT de verificación, SPF y los CNAME de DKIM) están protegidos y no se pueden borrar: quitarlos deja al cliente sin correo.

NO CONTROLAMOS: los precios, reglas y plazos los fijan el registro de cada extensión y el ICANN. Un dominio recién registrado o transferido no se puede volver a transferir durante 60 días.`,
  },
  {
    title: "Configuración SMTP Relay",
    content: `SMTP relay permite enviar emails desde código o aplicaciones SaaS usando credenciales SMTP estándar.

Disponible en dominio activado ($99 MXN/mes por dominio). Cuenta contra los 50 envíos al día del dominio.

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
    content: `MailMask tiene un servidor MCP (Model Context Protocol) en https://www.mailmask.studio/mcp, transporte Streamable HTTP, sin sesiones. Sirve para que un agente de IA (Claude Code, Claude Desktop, Cursor o cualquier cliente MCP) haga las altas por ti: dominios, máscaras, buzones IMAP, reglas, webhooks y envío de correo. Se autentica con la misma API key de la cuenta (prefijo mk_), en el encabezado Authorization: Bearer mk_...

Conectar desde Claude Code:
claude mcp add --transport http mailmask https://www.mailmask.studio/mcp --header "Authorization: Bearer mk_..."

Configuración para Claude Desktop, Cursor y otros (mcp.json):
{
  "mcpServers": {
    "mailmask": {
      "type": "http",
      "url": "https://www.mailmask.studio/mcp",
      "headers": { "Authorization": "Bearer mk_..." }
    }
  }
}

Herramientas (cada una es un método del SDK, con las mismas reglas y límites):
- Dominios: list_domains, get_domain, create_domain (devuelve los registros DNS: MX, TXT de verificación, CNAME de DKIM, SPF), verify_domain, domain_health, delete_domain.
- Máscaras y buzones: list_aliases, create_alias (con mailbox: true crea también el buzón IMAP y devuelve la contraseña una sola vez), update_alias, delete_alias, create_mailbox, delete_mailbox.
- Reglas: list_rules, create_rule, update_rule, delete_rule.
- Webhooks: list_webhooks, create_webhook, update_webhook, delete_webhook, test_webhook, webhook_deliveries.
- DNS: list_dns_records, create_dns_zone, dns_delegation_status, set_dns_record, delete_dns_record, import_dns_records, point_domain_to (apunta el dominio a Vercel, Netlify, GitHub Pages, Cloudflare Pages, Render o Fly sin saber qué registros hacen falta).
- Envío: send_email (acepta idempotencyKey), bulk_send, bulk_status.
- Operación: list_logs, list_suppressions, add_suppression, remove_suppression, list_smtp_credentials, create_smtp_credential, revoke_smtp_credential.
- search_tools: busca herramientas por palabra clave.

Sobre el DNS: set_dns_record REEMPLAZA el conjunto de valores de ese nombre y tipo, así que para añadir un valor hay que leer primero con list_dns_records e incluir también los que ya estaban. Los registros que MailMask necesita para el correo (MX, TXT de verificación, SPF y CNAME de DKIM) vienen marcados con managed y no se pueden borrar: el agente recibe un 409 explicando por qué. create_dns_zone importa lo que encuentre del proveedor anterior y devuelve los nameservers que hay que cambiar en el registrador; hasta que se cambien, nada de lo que se edite tiene efecto.

Un error del servidor (por ejemplo, un dominio gratis pidiendo un buzón, que requiere dominio activado a $99 MXN/mes) llega al agente como resultado con isError y el mensaje tal cual. Las API keys no se crean ni revocan por MCP. Límite: 60 peticiones por minuto por llave. No hay Bandeja ni facturación por MCP. No existe un paquete npm de MCP: el servidor es la URL.`,
  },
  {
    title: "Bandeja de Entrada (Inbox)",
    content: `La Bandeja de Entrada es una interfaz de inbox colaborativa para gestionar emails recibidos en tus dominios. Incluida en la cuenta gratis para una persona (muestra 7 días, guarda 30); responder desde la Bandeja nunca cuenta como envío. Con el dominio activado ($99 MXN/mes) la Bandeja es compartida con personas ilimitadas y guarda el historial completo.

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
    content: `El envío masivo permite enviar un email a múltiples destinatarios en una sola operación. Requiere dominio verificado y activado ($99 MXN/mes): 50 envíos al día por dominio.

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

La cuenta gratis no admite agentes adicionales; el dominio activado admite personas ilimitadas.

Todos los endpoints de dominio verifican permisos usando el sistema RBAC interno (checkDomainAccess). Si un usuario no tiene el rol necesario, recibe un error 403.`,
  },
];

async function main() {
  const secretKey = process.env.FORMMY_SECRET_KEY;
  if (!secretKey) {
    console.error("Error: FORMMY_SECRET_KEY env var required");
    process.exit(1);
  }

  const formmy = new Formmy({ secretKey, baseUrl: "https://www.formmy.app" });

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
