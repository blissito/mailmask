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
    .replace(/&ntilde;/g, "ñ")
    .replace(/&iexcl;/g, "¡")
    .replace(/&ordm;/g, "º")
    .replace(/&middot;/g, "·")
    .replace(/&hellip;/g, "…")
    .replace(/&laquo;/g, "«")
    .replace(/&raquo;/g, "»")
    .replace(/&rarr;/g, "→")
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
- 5 direcciones (máscaras; antes "alias") que reenvían al buzón que elijas.
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
4. Consultar estado de salud DNS: mm.domains.health("domain-id"). Es la fuente de verdad del MX y la verificación; mm.domains.list() sólo da la última revisión guardada (checkedAt) y la marca unknown si tiene más de 24 h.

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
    content: `MailMask tiene un servidor MCP (Model Context Protocol) en https://www.mailmask.studio/mcp, transporte Streamable HTTP, sin sesiones. Sirve para que un agente de IA (Claude, ChatGPT, Ghosty Studio, Claude Code, Cursor o cualquier cliente MCP) haga las altas por ti: dominios, máscaras, buzones IMAP, reglas, webhooks y envío de correo.

Hay dos formas de conectarlo. La recomendada es OAuth: sólo se pega la URL, sin copiar ninguna llave. La alternativa es una API key mk_ en el encabezado Authorization.

Forma 1 (recomendada) — OAuth, sólo con la URL:
- Ghosty Studio: Conectores → Mailmask → Conectar.
- Claude.ai y Claude Desktop: Settings → Connectors → Add custom connector, con la URL https://www.mailmask.studio/mcp, y luego Connect.
- ChatGPT: Settings → Apps & Connectors → Create (con el modo desarrollador), la URL y autenticación OAuth.
- Claude Code: claude mcp add --transport http mailmask https://www.mailmask.studio/mcp y luego /mcp → mailmask → Authenticate.
- Cualquier cliente que implemente la autorización del spec MCP: sólo la URL.
Qué pasa: el cliente abre MailMask en el navegador; si no hay sesión pide entrar (correo o Google) y luego muestra una pantalla con el nombre del cliente y los botones Permitir y Cancelar. Al permitir, queda conectado.
Qué puede hacer la conexión OAuth: lo mismo que una API key mk_ (las 95 herramientas, 60 peticiones por minuto), salvo crear o listar API keys, entrar al admin y crear o listar credenciales SMTP.
Tokens: acceso mo_ de 1 hora y renovación mr_ de 60 días que rota en cada uso; el cliente los renueva solo. Para dejar de usarla se desconecta desde el cliente (los que implementan revocación llaman a POST /oauth/revoke); para cortar todas las conexiones al instante, se cambia la contraseña de MailMask.
Detalles técnicos: /mcp sin credencial responde 401 con WWW-Authenticate: Bearer resource_metadata="https://www.mailmask.studio/.well-known/oauth-protected-resource". Metadata en /.well-known/oauth-authorization-server, registro dinámico público en POST /oauth/register, /oauth/authorize con PKCE S256, POST /oauth/token (code y refresh_token) y POST /oauth/revoke.

Forma 2 (alternativa) — API key mk_, para clientes sin OAuth, scripts o servidores. La llave se crea en mailmask.studio/app → API Keys y va en Authorization: Bearer mk_...

Conectar desde Claude Code con llave:
claude mcp add --transport http mailmask https://www.mailmask.studio/mcp --header "Authorization: Bearer mk_..."

Configuración con llave para Cursor y otros (mcp.json):
{
  "mcpServers": {
    "mailmask": {
      "type": "http",
      "url": "https://www.mailmask.studio/mcp",
      "headers": { "Authorization": "Bearer mk_..." }
    }
  }
}

Son 95 herramientas que cubren lo mismo que el panel (cada una es un método del SDK, con las mismas reglas y límites). Al conectarse, el cliente recibe además una guía con el orden para conectar un dominio, qué significa gratis/activado/bloqueado y cómo funcionan los pagos.
- Dominios: list_domains, get_domain, create_domain (devuelve los registros DNS: MX, TXT de verificación, CNAME de DKIM, SPF), domain_dns_setup (los registros exactos para pegar en el registrador, cuáles ya se ven en el DNS público y en qué panel van: Hostinger, GoDaddy, Cloudflare, Namecheap, Route 53), verify_domain, domain_health, delete_domain. El estado de un dominio (MX, verificación) se confirma con domain_health, que revisa en vivo el DNS y SES; list_domains es inventario: sus banderas mxConfigured y verified traen la fecha de la última revisión (checkedAt) y, si tiene más de 24 horas o nunca se hizo, salen como unknown (null en el MCP). Un agente no debe decir que el MX o la verificación fallan sin haber llamado domain_health.
- Direcciones (máscaras) y buzones: list_aliases, create_alias (con mailbox: true crea también el buzón IMAP y devuelve la contraseña una sola vez), update_alias, delete_alias, create_mailbox, delete_mailbox, reset_mailbox_password (genera una contraseña nueva para el buzón y la devuelve una sola vez), apple_profile_link (liga al perfil que configura el buzón en iPhone, iPad o Mac), mailbox_export_link (liga para descargar el buzón en .mbox).
- Activación y cobro: activation_link (liga de MercadoPago para activar un dominio a $99 MXN/mes, o sumarle +50 GB o +100 envíos/día), list_addons, billing_status.
- Comprar y renovar dominios: search_domains, domain_prices, register_domain (devuelve la liga de pago), list_registrations, renewal_status, renewal_link.
- Transferencias: transfer_check (requisitos y precio, no cobra), transfer_start (devuelve la liga al formulario seguro de la app donde se pega el código EPP y se paga; el código EPP NUNCA se da en el chat), transfer_status, transfer_dns, update_transfer_dns, approve_transfer_dns, resend_transfer_email, transfer_out (el código EPP llega por correo al dueño).
- Equipo: list_members, invite_member, remove_member, cancel_invite.
- Bandeja (el agente atiende el correo de su máscara): inbox_list (conversaciones por máscara, estado, no leídas, búsqueda q, paginación), inbox_read (mensajes en texto, notas internas y adjuntos; la marca leída), inbox_attachment (contenido de un adjunto de texto o imagen), inbox_reply (contesta en el hilo desde la máscara del hilo; no gasta envíos), inbox_send (correo nuevo que abre hilo; dominio activado y verificado, gasta un envío del día), inbox_mark (leída, cerrada, reabierta, pospuesta, prioridad, etiquetas), inbox_assign, inbox_note (nota interna que el contacto no ve), inbox_delete, inbox_restore, inbox_metrics, upload_attachment.
- Firma y respuestas guardadas: get_signature, set_signature, set_domain_logo, delete_domain_logo, list_canned_replies, create_canned_reply, delete_canned_reply.
- Cuenta: delete_profile_photo, list_orders (historial de cobros), cancel_addon, cancel_renewal, referral_status, set_referral_slug, set_referral_name, export_link.
- Perfil de la cuenta (el usuario de MailMask, no una máscara ni lo que ve quien recibe el correo): get_profile, update_profile (nombre visible, máx. 60 caracteres), set_profile_photo (sólo con una imagen que el usuario adjuntó en el chat del asistente; PNG, JPG o WebP de hasta 2 MB). En la app se edita desde "Tu perfil", haciendo clic en tu nombre arriba a la derecha.
- Reglas: list_rules, create_rule, update_rule, delete_rule.
- Webhooks: list_webhooks, create_webhook, update_webhook, delete_webhook, test_webhook, webhook_deliveries.
- DNS: list_dns_records, create_dns_zone, dns_delegation_status, set_dns_record, delete_dns_record, import_dns_records, point_domain_to (apunta el dominio a Vercel, Netlify, GitHub Pages, Cloudflare Pages, Render o Fly sin saber qué registros hacen falta).
- Envío: send_email (acepta idempotencyKey), bulk_send, bulk_status.
- Operación: list_logs, list_suppressions, add_suppression, remove_suppression, list_smtp_credentials, create_smtp_credential, revoke_smtp_credential.
- search_tools: busca herramientas por palabra clave (sin acentos: "renovacion" encuentra renewal_link).

Pagos por MCP: activation_link, register_domain y renewal_link devuelven una liga de MercadoPago que abre y paga una persona; nada queda pagado ni activado por dar la liga (paid: false). Se confirma después con list_addons, list_registrations o domain_health.

Sobre el DNS: set_dns_record REEMPLAZA el conjunto de valores de ese nombre y tipo, así que para añadir un valor hay que leer primero con list_dns_records e incluir también los que ya estaban. Los registros que MailMask necesita para el correo (MX, TXT de verificación, SPF y CNAME de DKIM) vienen marcados con managed y no se pueden borrar: el agente recibe un 409 explicando por qué. create_dns_zone importa lo que encuentre del proveedor anterior y devuelve los nameservers que hay que cambiar en el registrador; hasta que se cambien, nada de lo que se edite tiene efecto.

Un error del servidor (por ejemplo, un dominio gratis pidiendo un buzón, que requiere dominio activado a $99 MXN/mes) llega al agente como resultado con isError y el mensaje tal cual. Las API keys no se crean ni revocan por MCP. Límite: 60 peticiones por minuto por llave o por conexión OAuth. Desde el 4 de octubre de 2026 la Bandeja sí se trabaja por MCP, con los mismos permisos por dominio que la app: así un agente (por ejemplo de Ghosty Studio) puede tener su propio correo, una máscara como agente@tudominio.com, en vez de pedir acceso a tu Gmail. inbox_reply e inbox_send le piden al agente confirmar el texto contigo antes de enviar. No existe un paquete npm de MCP: el servidor es la URL.

Con una API key mk_ las acciones irreversibles se ejecutan directo. Con el token de turno del asistente de la app (mt_, dura 5 minutos), borrar un dominio, una máscara, un buzón o un registro DNS, sacar a un miembro, transferir un dominio fuera o cancelar un add-on o la renovación de un dominio NO se ejecuta: la ruta responde 409 needs_confirmation y el usuario lo aprueba en una tarjeta de la app.`,
  },
  {
    title: "Mask, el asistente dentro de la app",
    content: `Mask es el asistente de MailMask dentro de la app (mailmask.studio/app): un chat en la esquina de la pantalla que HACE las cosas por ti en lugar de explicarte cómo hacerlas. Habla español, corto y claro, y pensado para quien no es técnico.

Qué puede hacer Mask:
- Dar de alta un dominio y dictarte los registros DNS exactos para pegar en tu registrador (Hostinger, GoDaddy, Cloudflare, Namecheap, Route 53), con el menú donde van. Después verifica y diagnostica la salud del dominio (MX, SPF, DKIM).
- Crear, cambiar y borrar máscaras; crear buzones IMAP, regenerar su contraseña y darte la liga para configurarlos en iPhone o Mac, o para descargar el buzón en .mbox.
- Explicar por qué un dominio está "bloqueado" (el 2.º dominio sin activar guarda el correo pero no lo reenvía) y darte la liga de pago para activarlo.
- Buscar y comprar dominios, renovarlos y transferirlos a MailMask (o fuera de MailMask).
- Editar el DNS cuando MailMask lleva tu zona y apuntar tu dominio a Vercel, Netlify, GitHub Pages y similares.
- Reglas, webhooks, credenciales SMTP, equipo de la Bandeja (invitar y quitar personas), firma y respuestas guardadas.
- Llevarte a la pantalla correcta de la app con un enlace.
- Recibir imágenes, PDF o texto que le adjuntes (por ejemplo, una captura del panel de tu registrador), hasta 10 MB.

Lo que Mask NUNCA hace:
- Pagar: todo cobro es una liga de MercadoPago que tú abres y pagas. Mask no dice que algo quedó pagado hasta confirmarlo.
- Pedirte el código EPP de una transferencia ni contraseñas en el chat: para eso te manda a un formulario seguro de la app. Si se lo pegas, te dirá que no lo compartas.
- Ejecutar una acción irreversible sin tu permiso. Borrar un dominio, una máscara, un buzón o un registro DNS, sacar a alguien del equipo o transferir un dominio fuera te muestra una tarjeta con lo que va a pasar, armada con los datos reales de tu cuenta; la acción sólo corre cuando tú la apruebas. Si no la apruebas en 15 minutos, caduca.

Mask actúa con tu cuenta, con los mismos permisos que tienes en la app, mediante una credencial temporal que dura 5 minutos por mensaje; nunca usa ni ve tus API keys. Por ahora está disponible para un grupo de cuentas en prueba; después se abrirá a todas.`,
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
- owner: acceso completo — gestionar dominio, direcciones, reglas, miembros, bandeja, envío
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

  // 1. Borrar TODO lo existente. documents.list devuelve 20 por página (con hasMore),
  //    así que se repite hasta que la lista quede vacía; si no, quedan copias viejas
  //    y Formmy rechaza los nuevos como «duplicados».
  let deleted = 0;
  for (let round = 0; round < 50; round++) {
    const { documents: page } = await formmy.documents.list(AGENT_ID);
    if (page.length === 0) break;
    for (const doc of page) {
      await formmy.documents.delete(AGENT_ID, doc.id);
      deleted++;
    }
  }
  const { documents: left } = await formmy.documents.list(AGENT_ID);
  if (left.length > 0) throw new Error(`Quedaron ${left.length} documentos sin borrar`);
  console.log(`Deleted ${deleted} existing documents.`);

  // 2. Extract sections from docs.html
  const docsHtml = readFileSync("public/docs.html", "utf-8");
  const sections = extractSections(docsHtml);
  console.log(`Extracted ${sections.length} sections from docs.html`);

  // 3. Combine all documents
  // Los curados van primero: Formmy rechaza lo que se parece demasiado a algo ya
  // subido, y preferimos que el repetido que se caiga sea la sección de docs.html.
  const allDocs = [
    ...EXTRA_DOCS.map((d) => ({
      title: d.title,
      content: d.content,
      metadata: { source: "manual" },
    })),
    ...sections.map((s) => ({
      title: s.title,
      content: s.content,
      metadata: { source: "docs.html" },
    })),
  ];

  console.log(`Uploading ${allDocs.length} documents one by one...`);
  let created = 0;
  let skipped = 0;
  let failed = 0;
  for (const doc of allDocs) {
    try {
      const { document } = await formmy.documents.create(AGENT_ID, doc);
      console.log(`  ✓ ${document.title} (${document.chunkCount} chunks)`);
      created++;
    } catch (err: any) {
      // Formmy rechaza lo casi idéntico a un doc ya subido: ese contenido ya está.
      if (/duplicado/i.test(err.message)) {
        console.log(`  · ${doc.title}: omitido (ya lo cubre otro doc)`);
        skipped++;
      } else {
        console.error(`  ✗ ${doc.title}: ${err.message}`);
        failed++;
      }
    }
  }
  console.log(`\n${created}/${allDocs.length} uploaded, ${skipped} omitidos por duplicado, ${failed} fallidos.`);
  if (failed > 0) process.exit(1);

  console.log("\nDone! The agent now has access to the documentation.");
}

main().catch((err) => {
  console.error("Failed:", err);
  process.exit(1);
});
