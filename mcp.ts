// Servidor MCP (Model Context Protocol) de MailMask: `POST /mcp`, Streamable HTTP sin
// sesiones. Cada herramienta es un método del SDK real (`sdk/src`) hablando con la app
// en proceso, así que no puede desalinearse de una ruta sin que `sdk.test.ts` lo cace.
// Para añadir una herramienta: método en el SDK → caso en `sdk.test.ts` → `tool()` aquí.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "node:fs";
import { MailMask, MailMaskError } from "./sdk/src/index.js";

export const MCP_VERSION = "1.0.0";

type Salida = CallToolResult;

function ok(valor: unknown): Salida {
  // inbox_attachment devuelve una imagen: va como bloque `image`, no como base64 en el JSON.
  if (valor && typeof valor === "object" && "__image" in valor) {
    const { __image, ...meta } = valor as { __image: { data: string; mimeType: string } };
    return { content: [{ type: "image", data: __image.data, mimeType: __image.mimeType }, { type: "text", text: JSON.stringify(meta) }], structuredContent: meta };
  }
  const structured = valor && typeof valor === "object" && !Array.isArray(valor)
    ? (valor as Record<string, unknown>)
    : { result: valor };
  return { content: [{ type: "text", text: JSON.stringify(valor, null, 2) }], structuredContent: structured };
}

// El 400/403 del servidor es la información útil para el agente ("actívalo por $99"),
// no una excepción JSON-RPC.
function fallo(e: unknown): Salida {
  if (e instanceof MailMaskError) {
    return { isError: true, content: [{ type: "text", text: `HTTP ${e.status}: ${e.message}` }], structuredContent: { status: e.status, error: e.message } };
  }
  return { isError: true, content: [{ type: "text", text: String((e as Error)?.message ?? e) }] };
}

// Guía que el cliente MCP recibe en `initialize`. Los agentes partner (Ghosty) no cargan
// skills, así que esto es TODO lo que saben del producto antes de la primera herramienta.
// Tope de 6 000 caracteres (lo fija `mcp.test.ts`).
export const MCP_INSTRUCTIONS = `MailMask: correo con tu dominio (máscaras que reenvían, Bandeja compartida, buzones IMAP) y DNS. Hablas con el dueño de la cuenta, casi siempre no técnico: responde en español, corto, y dicta valores exactos.
Al usuario llámale «dirección» (o máscara) a lo que las tools llaman alias; no le digas «alias». Los nombres *_alias y el campo \`alias\` se quedan así.

## Conectar un dominio (en este orden)
1. create_domain (o list_domains si ya existe).
2. domain_dns_setup: los registros exactos (MX, TXT _amazonses, 3 CNAME de DKIM, SPF y DMARC opcional), si ya se ven en el DNS público (ok) y en qué panel pegarlos (registrarHint, deducido de los nameservers). Díctalos uno por uno con tipo, nombre y valor; si hay registrarHint, di en qué menú.
3. El usuario los pega en su registrador. Tú no puedes, salvo que la zona sea de MailMask (list_dns_records con zone.status "active").
4. verify_domain cuando diga que ya los puso. Propagar tarda de minutos a horas: si sale false, vuelve a domain_dns_setup y dile sólo qué registro falta.
5. domain_health para confirmar MX, SPF, DKIM, máscaras y plan.
6. Si el plan sale bloqueado: activation_link.
7. create_alias para que el correo llegue a algún lado: sin máscaras activas no se reenvía nada.

## Estado de un dominio
El MX y la verificación se confirman con domain_health (revisa en vivo). list_domains es inventario: sus banderas pueden ser viejas (si salen null o "unknown", no sabes). Nunca le digas al usuario que algo falla sin domain_health.

## Gratis, activado y bloqueado
- El dominio más antiguo de la cuenta es gratis: reenvía, 5 máscaras, Bandeja de 1 persona, sin envío de correo nuevo.
- Activado ($99 MXN/mes por dominio): máscaras ilimitadas, equipo, 50 envíos/día, buzones IMAP, reglas, webhooks, SMTP.
- Bloqueado = el 2.º dominio en adelante sin activar: el correo se GUARDA en la Bandeja pero NO se reenvía. No es una falla técnica; se arregla activándolo.
- Un 403 que menciona $99 significa "eso pide dominio activado": ofrece activation_link.

## Pagos
Todo cobro es una liga de MercadoPago que el USUARIO abre y paga (activation_link, register_domain, renewal_link, el formulario de transferencia). No digas que quedó pagado por dar la liga: confírmalo con list_addons, list_registrations o domain_health.

## Transferir un dominio a MailMask
transfer_check (requisitos, precio, DNS actual) → transfer_start devuelve formUrl, un formulario de la app donde el usuario pega el código EPP y sus datos WHOIS, y paga. NUNCA pidas ni aceptes el código EPP (auth code) en el chat: si te lo pegan, dile que no lo comparta y que lo ponga en el formulario. Después, transfer_status. Cuando toque aprobar el DNS: transfer_dns para revisar el inventario con el usuario (lo que falte dejará de funcionar), update_transfer_dns si hay que corregir, y approve_transfer_dns sólo con su visto bueno. Si el registrador anterior no la suelta: resend_transfer_email, y que lo pida en el chat de su registrador. Que no pida otro EPP: invalida el que se mandó.

## Llevarse un dominio
transfer_out manda el código EPP por correo al dueño, nunca al chat. lock_domain_transfer pone el candado de transferencia; quitarlo sólo se puede en el panel, con confirmación por correo.

## Acciones delicadas
Borrar dominio, máscara, buzón o registro DNS, sacar a un miembro, transferir fuera o cancelar un add-on o una renovación (cancel_addon, cancel_renewal) son irreversibles: confírmalo con el usuario antes. Algunas responden que necesitan confirmación: el usuario la aprueba en la app; no reintentes ni busques otra vía.

## DNS administrado por MailMask
Con zona propia (create_dns_zone + nameservers en el registrador) puedes editar registros; enseña \`imported\` antes de que cambie los nameservers. list_dns_records antes de escribir; set_dns_record reemplaza el conjunto; point_domain_to para Vercel, Netlify y similares (website_status: a dónde apunta hoy). EasyBits: easybits_site_status → publish_easybits_site (dryRun primero); unpublish_easybits_site lo revierte. Los registros de correo están protegidos.

## Bandeja: el correo de la máscara
Cada máscara recibe en la Bandeja del dominio; desde ahí se lee y se contesta como esa máscara.
- Lo nuevo: inbox_list con status "unread" (y alias para una máscara) → inbox_read (texto de cada mensaje, notas y adjuntos; lo marca leído) → inbox_attachment si hace falta un adjunto.
- Contestar: inbox_reply en markdown (lleva firma y cita). Antes de cualquier envío (inbox_reply, inbox_send, send_email), enseña destinatario, asunto y texto al usuario y espera su visto bueno, salvo que te haya dado instrucciones permanentes.
- Escribir a alguien nuevo: inbox_send desde una máscara activa (dominio activado y verificado; gasta envíos del día). send_email no deja hilo.
- Ordenar: inbox_mark (read, closed = resuelta, snoozed, urgent, tags), inbox_assign, inbox_note (interna, el contacto no la ve), inbox_delete / inbox_restore, inbox_metrics.
- Adjuntar: upload_attachment y pasa lo que devuelve en attachments.

## Otros
- Equipo: list_members, invite_member, remove_member.
- Firma: get_signature y set_signature (markdown), set_domain_logo; respuestas guardadas (list/create/delete_canned_reply).
- Cuenta: list_orders (cobros), cancel_addon, cancel_renewal, referral_status, export_link.
- Perfil de la cuenta (el usuario, no una máscara): get_profile, update_profile (nombre) y set_profile_photo. Para la foto, pide que la adjunte en el chat y pasa la URL de ese adjunto.
- Buzones IMAP: create_alias con mailbox, o create_mailbox. apple_profile_link configura iPhone y Mac; mailbox_export_link descarga el .mbox.
- Contraseñas, secretos de webhook y credenciales SMTP salen una sola vez: entrégalas tal cual y avisa que no se pueden volver a ver.
- Comprar: search_domains antes de register_domain. Los ids de miembros, add-ons, registraciones y conversaciones salen de su list_* (list_members, list_addons, list_registrations, inbox_list).
- Si no encuentras una herramienta, usa search_tools.`;

// Cómo se ve cada estado de una registración, con las palabras de la app.
const REGISTRATION_STATUS: Record<string, string> = {
  pending_payment: "Esperando el pago del registro",
  paid: "Pagado — esperando registro",
  registering: "Registrando el dominio",
  registered: "Registrado a nombre del usuario",
  failed: "El registro falló; hay que escribir a soporte",
  transfer_pending_payment: "Transferencia: esperando pago",
  transfer_paid: "Pagada — falta el código EPP (el usuario lo pega en la app)",
  transfer_submitted: "Transferencia enviada — revisar el correo",
  transfer_awaiting_approval: "Esperando que el registrador actual la suelte (hasta 10 días)",
  transfer_failed: "La transferencia falló",
  transfer_cancelled: "Transferencia cancelada",
  transferred_out: "Se fue a otro registrador",
};

function registrationStatusText(r: { kind: string; status: string; dnsImportStatus: string }): string {
  if (r.kind === "transfer" && r.status === "registering" && r.dnsImportStatus !== "approved") {
    return "Transferido — falta aprobar el DNS (transfer_dns y luego approve_transfer_dns)";
  }
  return REGISTRATION_STATUS[r.status] ?? r.status;
}

function appUrl(path: string): string {
  // Igual que getMainDomainUrl() de main.ts, que no se puede importar desde aquí (ciclo).
  const bare = (process.env.MAIN_DOMAIN ?? "www.mailmask.studio").replace(/^https?:\/\//, "").replace(/\/+$/, "");
  return `https://${bare}${path}`;
}

// Palabras con las que un usuario (o un agente) busca estas herramientas y que no salen en
// su descripción. search_tools las compara sin acentos.
const KEYWORDS: Record<string, string> = {
  domain_dns_setup: "registros pegar registrador hostinger godaddy cloudflare namecheap route53 mx txt cname dkim spf dmarc configurar conectar",
  activation_link: "activar pagar pago cobro mercadopago bloqueado addon suscripción",
  billing_status: "plan suscripción pago cobro",
  list_addons: "activado pagos suscripciones envíos almacenamiento",
  search_domains: "comprar disponible buscar registrar",
  domain_prices: "precio tld extensión costo",
  register_domain: "comprar registrar pagar",
  list_registrations: "comprados registrados vencimiento",
  transfer_check: "transferir traer mover requisitos epp",
  transfer_start: "transferir traer epp auth code whois formulario",
  transfer_status: "transferencia estado avance",
  transfer_dns: "inventario transferencia revisar",
  update_transfer_dns: "inventario transferencia corregir editar",
  approve_transfer_dns: "aprobar inventario transferencia",
  resend_transfer_email: "correo aprobación registrador reenviar transferencia",
  transfer_out: "llevarme sacar otro registrador epp",
  lock_domain_transfer: "candado bloqueo proteger robo secuestro transferencia",
  renewal_status: "renovación vencimiento expira",
  renewal_link: "renovar renovación pagar anual",
  list_members: "equipo miembros agentes personas usuarios",
  invite_member: "invitar equipo agente persona usuario",
  remove_member: "quitar sacar equipo agente persona",
  cancel_invite: "invitación cancelar equipo",
  get_signature: "firma correo",
  set_signature: "firma correo cambiar",
  list_canned_replies: "respuestas guardadas plantillas bandeja",
  create_canned_reply: "respuesta guardada plantilla bandeja",
  delete_canned_reply: "respuesta guardada plantilla borrar",
  apple_profile_link: "iphone mac apple mail configurar buzón imap perfil",
  mailbox_export_link: "exportar descargar respaldo buzón mbox",
  get_profile: "perfil nombre foto avatar cuenta usuario",
  update_profile: "perfil nombre cambiar cuenta usuario",
  set_profile_photo: "perfil foto avatar imagen cambiar cuenta",
  delete_profile_photo: "perfil foto avatar quitar borrar",
  inbox_list: "bandeja correos recibidos conversaciones hilos leer buscar mensajes nuevos pendientes no leídos",
  inbox_read: "bandeja abrir leer correo mensaje hilo conversación",
  inbox_attachment: "adjunto archivo descargar leer bandeja",
  inbox_reply: "responder contestar correo bandeja hilo",
  inbox_send: "redactar escribir enviar correo nuevo bandeja",
  inbox_mark: "leído cerrar archivar resolver reabrir posponer prioridad etiquetas bandeja",
  inbox_assign: "asignar repartir bandeja equipo",
  inbox_note: "nota interna comentario bandeja equipo",
  inbox_delete: "borrar eliminar papelera bandeja conversación",
  inbox_restore: "restaurar recuperar papelera bandeja",
  inbox_metrics: "métricas estadísticas tiempos respuesta bandeja",
  upload_attachment: "adjuntar archivo subir adjunto",
  set_domain_logo: "logo firma imagen marca",
  delete_domain_logo: "logo firma quitar",
  list_orders: "pagos cobros historial facturas recibos cfdi",
  cancel_addon: "cancelar suscripción desactivar dominio pago addon",
  cancel_renewal: "cancelar renovación dominio",
  publish_easybits_site: "sitio web página publicar easybits hosting dominio",
  unpublish_easybits_site: "sitio web quitar despublicar easybits restaurar dns",
  easybits_site_status: "sitio web easybits publicado estado conectar",
  referral_status: "referidos invitar liga créditos recomendar",
  set_referral_slug: "referidos liga slug",
  set_referral_name: "referidos nombre",
  export_link: "exportar descargar datos respaldo json",
};

// Anotaciones que exige el directorio de conectores de Claude: `title` legible y
// `readOnlyHint`/`destructiveHint` en todas. Lectura = no cambia nada del usuario (las
// ligas de pago sí crean un cobro pendiente, por eso no entran). Destructiva = borra,
// revoca, cancela o reemplaza algo sin vuelta atrás desde aquí. `mcp.test.ts` exige que
// toda herramienta caiga en una de las dos listas o sea escritura no destructiva a propósito.
export const READ_ONLY_TOOLS = new Set([
  "list_domains", "get_domain", "domain_health", "list_aliases", "list_dns_records", "dns_delegation_status", "website_status",
  "easybits_site_status",
  "import_dns_records", "list_rules", "list_webhooks", "webhook_deliveries", "bulk_status", "list_logs",
  "list_suppressions", "list_smtp_credentials", "domain_dns_setup", "billing_status", "list_addons",
  "search_domains", "domain_prices", "list_registrations", "transfer_check", "transfer_status", "transfer_dns",
  "renewal_status", "list_members", "get_signature", "list_canned_replies", "inbox_list", "inbox_attachment",
  "inbox_metrics", "list_orders", "referral_status", "export_link", "get_profile", "apple_profile_link",
  "mailbox_export_link", "search_tools",
]);
export const DESTRUCTIVE_TOOLS = new Set([
  "delete_domain", "delete_alias", "delete_mailbox", "reset_mailbox_password", "set_dns_record", "delete_dns_record",
  "delete_rule", "delete_webhook", "remove_suppression", "revoke_smtp_credential", "approve_transfer_dns",
  "transfer_out", "remove_member", "cancel_invite", "delete_canned_reply", "inbox_delete", "delete_domain_logo",
  "cancel_addon", "cancel_renewal", "delete_profile_photo", "unpublish_easybits_site",
]);
// Las que tocan el mundo fuera de la cuenta: mandan correo, publican DNS o llaman a un webhook.
const OPEN_WORLD_TOOLS = new Set([
  "send_email", "bulk_send", "inbox_reply", "inbox_send", "invite_member", "test_webhook", "set_dns_record",
  "delete_dns_record", "point_domain_to", "transfer_out", "transfer_start", "register_domain", "approve_transfer_dns",
  "publish_easybits_site", "unpublish_easybits_site",
]);
// Título legible que el directorio muestra junto a cada herramienta.
export const TOOL_TITLES: Record<string, string> = {
  list_domains: "List domains",
  get_domain: "Get domain",
  create_domain: "Add domain",
  verify_domain: "Verify domain",
  domain_health: "Check domain health",
  delete_domain: "Delete domain",
  list_aliases: "List addresses",
  create_alias: "Create address",
  update_alias: "Update address",
  delete_alias: "Delete address",
  create_mailbox: "Create IMAP mailbox",
  delete_mailbox: "Delete IMAP mailbox",
  reset_mailbox_password: "Reset mailbox password",
  list_dns_records: "List DNS records",
  create_dns_zone: "Create DNS zone",
  dns_delegation_status: "Check nameserver delegation",
  set_dns_record: "Set DNS record",
  delete_dns_record: "Delete DNS record",
  import_dns_records: "Read public DNS",
  point_domain_to: "Point domain to hosting",
  website_status: "Check website status",
  publish_easybits_site: "Publish EasyBits site",
  unpublish_easybits_site: "Remove EasyBits site",
  easybits_site_status: "Check EasyBits site",
  list_rules: "List routing rules",
  create_rule: "Create routing rule",
  update_rule: "Update routing rule",
  delete_rule: "Delete routing rule",
  list_webhooks: "List webhooks",
  create_webhook: "Create webhook",
  update_webhook: "Update webhook",
  delete_webhook: "Delete webhook",
  test_webhook: "Send test webhook",
  webhook_deliveries: "List webhook deliveries",
  send_email: "Send email",
  bulk_send: "Send bulk email",
  bulk_status: "Get bulk send status",
  list_logs: "List email logs",
  list_suppressions: "List suppressed recipients",
  add_suppression: "Suppress recipient",
  remove_suppression: "Unsuppress recipient",
  list_smtp_credentials: "List SMTP credentials",
  create_smtp_credential: "Create SMTP credential",
  revoke_smtp_credential: "Revoke SMTP credential",
  domain_dns_setup: "Get DNS setup records",
  activation_link: "Get activation payment link",
  billing_status: "Get legacy subscription",
  list_addons: "List add-ons",
  search_domains: "Search domain availability",
  domain_prices: "List domain prices",
  register_domain: "Buy domain",
  list_registrations: "List registered domains",
  transfer_check: "Check transfer eligibility",
  transfer_start: "Start domain transfer",
  transfer_status: "Get transfer status",
  transfer_dns: "Get transfer DNS inventory",
  update_transfer_dns: "Update transfer DNS inventory",
  approve_transfer_dns: "Approve transfer DNS",
  resend_transfer_email: "Resend transfer approval email",
  transfer_out: "Transfer domain out",
  lock_domain_transfer: "Lock domain transfer",
  renewal_status: "Get renewal status",
  renewal_link: "Get renewal payment link",
  list_members: "List team members",
  invite_member: "Invite team member",
  remove_member: "Remove team member",
  cancel_invite: "Cancel invitation",
  get_signature: "Get email signature",
  set_signature: "Set email signature",
  list_canned_replies: "List saved replies",
  create_canned_reply: "Create saved reply",
  delete_canned_reply: "Delete saved reply",
  inbox_list: "List inbox conversations",
  inbox_read: "Read inbox conversation",
  inbox_attachment: "Read attachment",
  inbox_reply: "Reply in conversation",
  inbox_send: "Send new email from inbox",
  inbox_mark: "Update conversation state",
  inbox_assign: "Assign conversation",
  inbox_note: "Add internal note",
  inbox_delete: "Move conversations to trash",
  inbox_restore: "Restore conversation",
  inbox_metrics: "Get inbox metrics",
  upload_attachment: "Upload attachment",
  set_domain_logo: "Set signature logo",
  delete_domain_logo: "Remove signature logo",
  list_orders: "List orders",
  cancel_addon: "Cancel add-on",
  cancel_renewal: "Cancel domain renewal",
  referral_status: "Get referral program",
  set_referral_slug: "Set referral link",
  set_referral_name: "Set referral name",
  export_link: "Get account export link",
  get_profile: "Get profile",
  update_profile: "Update profile name",
  set_profile_photo: "Set profile photo",
  delete_profile_photo: "Remove profile photo",
  apple_profile_link: "Get Apple Mail setup link",
  mailbox_export_link: "Get mailbox export link",
  search_tools: "Search tools",
};

// --- Endpoint de directorios (`/mcp/directory`, 13-oct-2026) ---
//
// Los directorios de Claude y ChatGPT no dejan cobrar dentro de la app ni entregar
// credenciales. `/mcp/directory` es ESTE mismo servidor filtrado por una lista blanca
// estricta: lo que no está aquí no se registra, así que tampoco sale en tools/list ni en
// search_tools. Fuera: todo lo que cobra, compra, activa o devuelve una liga de pago
// (activación, registro, transferencia y renovación de dominios, add-ons, pedidos,
// referidos) y todo lo que devuelve un secreto (contraseña de buzón, secreto de webhook,
// credenciales SMTP, exportación completa de la cuenta). Agregar algo aquí = revisarlo
// contra la política de los dos directorios. `mcp.test.ts` lo fija.
export const DIRECTORY_ALLOWLIST = new Set([
  // Dominios
  "list_domains", "get_domain", "create_domain", "verify_domain", "domain_health", "delete_domain",
  // Direcciones (sin crear buzones: devuelven su contraseña)
  "list_aliases", "create_alias", "update_alias", "delete_alias", "delete_mailbox",
  "apple_profile_link", "mailbox_export_link",
  // DNS
  "domain_dns_setup", "list_dns_records", "website_status", "create_dns_zone", "dns_delegation_status", "set_dns_record",
  "delete_dns_record", "import_dns_records", "point_domain_to",
  // Reglas y webhooks (sin crear webhooks: devuelven su secreto de firma)
  "list_rules", "create_rule", "update_rule", "delete_rule",
  "list_webhooks", "update_webhook", "delete_webhook", "test_webhook", "webhook_deliveries",
  // Envío y registro
  "send_email", "list_logs", "list_suppressions", "add_suppression", "remove_suppression",
  // Equipo, firma y respuestas guardadas
  "list_members", "invite_member", "remove_member", "cancel_invite",
  "get_signature", "set_signature", "set_domain_logo", "delete_domain_logo",
  "list_canned_replies", "create_canned_reply", "delete_canned_reply",
  // Bandeja
  "inbox_list", "inbox_read", "inbox_attachment", "inbox_reply", "inbox_send", "inbox_mark", "inbox_assign",
  "inbox_note", "inbox_delete", "inbox_restore", "inbox_metrics", "upload_attachment",
  // Perfil
  "get_profile", "update_profile", "set_profile_photo", "delete_profile_photo",
  "search_tools",
]);

// Parámetros que el directorio no ve aunque la herramienta sí esté: `mailbox` de
// create_alias crea un buzón IMAP y devuelve su contraseña.
const DIRECTORY_OMIT_PARAMS: Record<string, string[]> = { create_alias: ["mailbox"] };
// Misma idea para la descripción: se quita la frase del parámetro que no existe aquí.
const DIRECTORY_DESCRIPTION_EDITS: Record<string, Array<[string, string]>> = {
  create_alias: [[" With `mailbox: true` it also stores mail in an IMAP mailbox (activated domains only) and returns its credentials once.", ""]],
};

// Las instrucciones del directorio: las del servidor completo sin pagos, compras,
// transferencias ni credenciales, y sin nombrar herramientas que aquí no existen.
export const MCP_DIRECTORY_INSTRUCTIONS = `MailMask: correo con tu dominio (máscaras que reenvían, Bandeja compartida, buzones IMAP) y DNS. Hablas con el dueño de la cuenta, casi siempre no técnico: responde en su idioma, corto, y dicta valores exactos.
Al usuario llámale «dirección» (o máscara) a lo que las tools llaman alias; no le digas «alias». Los nombres *_alias y el campo \`alias\` se quedan así.

## Conectar un dominio (en este orden)
1. create_domain (o list_domains si ya existe).
2. domain_dns_setup: los registros exactos (MX, TXT _amazonses, 3 CNAME de DKIM, SPF y DMARC opcional), si ya se ven en el DNS público (ok) y en qué panel pegarlos (registrarHint). Díctalos uno por uno con tipo, nombre y valor.
3. El usuario los pega en su registrador. Tú no puedes, salvo que la zona sea de MailMask (list_dns_records con zone.status "active").
4. verify_domain cuando diga que ya los puso. Propagar tarda de minutos a horas: si sale false, vuelve a domain_dns_setup y dile sólo qué registro falta.
5. domain_health para confirmar MX, SPF, DKIM, máscaras y plan.
6. create_alias para que el correo llegue a algún lado: sin máscaras activas no se reenvía nada.

## Estado de un dominio
El MX y la verificación se confirman con domain_health (revisa en vivo). list_domains es inventario: sus banderas pueden ser viejas (si salen null o "unknown", no sabes). Nunca le digas al usuario que algo falla sin domain_health.

## Plan del dominio
Algunas funciones (máscaras ilimitadas, equipo, envío, reglas, webhooks) piden un dominio activado. Un dominio bloqueado guarda el correo en la Bandeja pero no lo reenvía; no es una falla técnica. Si una herramienta responde que hace falta activar el dominio, dile al usuario que eso se gestiona en su panel de mailmask.studio; no ofrezcas cobros ni ligas de pago.

## Acciones delicadas
Borrar dominio, máscara, buzón o registro DNS y sacar a un miembro son irreversibles: confírmalo con el usuario antes. Algunas responden que necesitan confirmación: el usuario la aprueba en la app; no reintentes ni busques otra vía.

## DNS administrado por MailMask
Con zona propia (create_dns_zone y cambiar los nameservers en el registrador) puedes editar registros; enseña la lista \`imported\` antes de que cambie los nameservers: list_dns_records antes de escribir; set_dns_record reemplaza el conjunto completo; point_domain_to para Vercel, Netlify y similares (website_status dice a dónde apunta hoy). Los registros de correo están protegidos.

## Bandeja: el correo de la máscara
Cada máscara recibe en la Bandeja del dominio; desde ahí se lee y se contesta como esa máscara.
- Lo nuevo: inbox_list con status "unread" (y alias para una máscara) → inbox_read (texto de cada mensaje, notas y adjuntos; lo marca leído) → inbox_attachment si hace falta un adjunto.
- Contestar: inbox_reply en markdown (lleva firma y cita). Antes de cualquier envío (inbox_reply, inbox_send, send_email), enseña destinatario, asunto y texto al usuario y espera su visto bueno.
- Escribir a alguien nuevo: inbox_send desde una máscara activa (dominio activado y verificado). send_email no deja hilo.
- Ordenar: inbox_mark (read, closed = resuelta, snoozed, urgent, tags), inbox_assign, inbox_note (interna, el contacto no la ve), inbox_delete / inbox_restore, inbox_metrics.
- Adjuntar: upload_attachment y pasa lo que devuelve en attachments.

## Otros
- Equipo: list_members, invite_member, remove_member.
- Firma: get_signature y set_signature (markdown), set_domain_logo; respuestas guardadas (list/create/delete_canned_reply).
- Perfil de la cuenta: get_profile, update_profile (nombre) y set_profile_photo.
- Buzones IMAP existentes: apple_profile_link configura iPhone y Mac; mailbox_export_link descarga el .mbox. Las contraseñas de buzón, las llaves de API y las credenciales SMTP se gestionan sólo en el panel de mailmask.studio.
- Los ids de miembros y conversaciones salen de su list_* (list_members, inbox_list).
- Si no encuentras una herramienta, usa search_tools.`;

export type McpProfile = "full" | "directory";

const domainId = z.string().describe("Domain ID");
const attachmentsShape = z.array(z.object({ key: z.string(), filename: z.string(), contentType: z.string().optional() }))
  .max(10).optional().describe("Attachment objects returned by the upload tool");
const aliasName = z.string().describe("Local part of the address, without the domain: 'hello' for hello@yourdomain.com");

// Con el turn token del asistente (`mt_`), lo destructivo contesta 409 `needs_confirmation`:
// al usuario le aparece una tarjeta para aprobarlo. No es un error para el modelo, y si
// lo pareciera, reintentaría.
function pideConfirmacion(titulo: string): Salida {
  return { content: [{ type: "text", text: `Necesita confirmación del usuario: le apareció una tarjeta en el asistente para aprobar «${titulo}». No reintentes; espera a que confirme.` }], structuredContent: { needsConfirmation: true, title: titulo } };
}

// --- Pantallas MCP Apps (ChatGPT, Claude) ---
//
// Estándar abierto de MCP Apps (`@modelcontextprotocol/ext-apps`, el mismo en ChatGPT y
// Claude) más las llaves `openai/*` que ChatGPT todavía lee. El HTML viaja dentro de
// `resources/read`, así que la CSP y el X-Frame-Options de main.ts no le aplican; la del
// iframe la arma el host con `csp` (vacía = sin red: todo pasa por tools).
export const BANDEJA_UI_URI = "ui://mailmask/bandeja.html";
const MCP_APP_MIME = "text/html;profile=mcp-app";
const BANDEJA_RESOURCE_META = {
  ui: { csp: { connectDomains: [], resourceDomains: [] }, prefersBorder: true },
  "openai/widgetDescription": "La Bandeja compartida del dominio: conversaciones recientes, no leídas y urgentes.",
  "openai/widgetPrefersBorder": true,
  "openai/widgetCSP": { connect_domains: [], resource_domains: [] },
};
// inbox_list abre la pantalla; las tres las puede llamar la pantalla (visibility por defecto
// = modelo y app). `widgetAccessible` es el equivalente de ChatGPT.
const BANDEJA_LIST_META = {
  ui: { resourceUri: BANDEJA_UI_URI },
  "ui/resourceUri": BANDEJA_UI_URI,
  "openai/outputTemplate": BANDEJA_UI_URI,
  "openai/widgetAccessible": true,
  "openai/toolInvocation/invoking": "Abriendo la Bandeja…",
  "openai/toolInvocation/invoked": "Bandeja",
};
const BANDEJA_CALLABLE_META = { "openai/widgetAccessible": true };

// widgets/bandeja.{js,css} los compila `npm run build:widgets` y van commiteados, igual que
// public/js/*.js. Se arma una vez por proceso.
let bandejaCache: string | null = null;
function bandejaHtml(): string {
  if (bandejaCache) return bandejaCache;
  const leer = (f: string) => readFileSync(new URL(`./widgets/${f}`, import.meta.url), "utf8");
  // `</script` dentro del bundle cerraría la etiqueta antes de tiempo.
  const js = leer("bandeja.js").replace(/<\/script/gi, "<\\/script");
  bandejaCache = `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Bandeja · MailMask</title><style>${leer("bandeja.css")}</style></head><body><div id="app"></div><script>${js}</script></body></html>`;
  return bandejaCache;
}

export function crearServidorMcp(o: { apiKey: string; fetchLocal: typeof fetch; profile?: McpProfile }): McpServer {
  const directory = o.profile === "directory";
  // El SDK sólo conserva `error` del cuerpo; el título de la tarjeta se lee aquí.
  let confirmacion: string | null = null;
  const fetchLocal = (async (input: string | URL | Request, init?: RequestInit) => {
    const res = await o.fetchLocal(input, init);
    if (res.status === 409) {
      const b = await res.clone().json().catch(() => null) as { error?: string; summary?: { title?: string } } | null;
      if (b?.error === "needs_confirmation") confirmacion = b.summary?.title ?? "la acción";
    }
    return res;
  }) as typeof fetch;
  const sdk = new MailMask({ apiKey: o.apiKey, baseUrl: "http://mcp.local", fetch: fetchLocal });
  const server = new McpServer({ name: "mailmask", version: MCP_VERSION }, { instructions: directory ? MCP_DIRECTORY_INSTRUCTIONS : MCP_INSTRUCTIONS });
  const catalogo: { name: string; description: string }[] = [];

  // Al agente no se le entrega un `false` viejo: si la revisión pasó de 24 h, las
  // banderas salen null y `statusNote` le dice que confirme con domain_health.
  // La API REST conserva los booleanos porque el panel los pinta (7-oct-2026).
  const staleFlagsAsNull = <D extends { verified: boolean; mxConfigured: boolean; mxStatus?: string; verifiedStatus?: string }>(d: D) => ({
    ...d,
    verified: d.verifiedStatus === "unknown" ? null : d.verified,
    mxConfigured: d.mxStatus === "unknown" ? null : d.mxConfigured,
  });

  const tool = <S extends z.ZodRawShape>(name: string, description: string, shape: S, run: (args: z.infer<z.ZodObject<S>>) => Promise<unknown>, _meta?: Record<string, unknown>) => {
    // Directorio: lo que no está en la lista blanca ni se registra (ni tools/list, ni
    // search_tools, ni tools/call); los parámetros omitidos ni se ven ni llegan al SDK.
    if (directory) {
      if (!DIRECTORY_ALLOWLIST.has(name)) return;
      const omit = DIRECTORY_OMIT_PARAMS[name] ?? [];
      if (omit.length) shape = Object.fromEntries(Object.entries(shape).filter(([k]) => !omit.includes(k))) as S;
      for (const [from, to] of DIRECTORY_DESCRIPTION_EDITS[name] ?? []) description = description.replace(from, to);
      const runFull = run;
      run = (args) => runFull(Object.fromEntries(Object.entries(args as Record<string, unknown>).filter(([k]) => !omit.includes(k))) as typeof args);
    }
    catalogo.push({ name, description });
    // El genérico de registerTool no infiere bien con un shape genérico; el tipado real
    // de `args` lo garantiza la firma de `run`.
    const cb = async (args: z.infer<z.ZodObject<S>>) => {
      try { return ok(await run(args)); } catch (e) {
        if (e instanceof MailMaskError && e.status === 409 && e.message === "needs_confirmation") return pideConfirmacion(confirmacion ?? "la acción");
        return fallo(e);
      }
    };
    const readOnly = READ_ONLY_TOOLS.has(name);
    const annotations = {
      title: TOOL_TITLES[name] ?? name,
      readOnlyHint: readOnly,
      destructiveHint: readOnly ? false : DESTRUCTIVE_TOOLS.has(name),
      openWorldHint: OPEN_WORLD_TOOLS.has(name),
    };
    server.registerTool(name, { title: annotations.title, description, inputSchema: shape, annotations, ...(_meta ? { _meta } : {}) }, cb as unknown as Parameters<typeof server.registerTool>[2]);
  };

  // --- Dominios ---
  tool("list_domains",
    "Lists the domains on the account with id, plan, forwards this month, and the last stored MX and verification status with the time it was checked (checkedAt). A mxStatus or verifiedStatus of \"unknown\" means the stored value is older than 24 hours and the flag is returned as null.",
    {}, async () => (await sdk.domains.list()).map(staleFlagsAsNull));
  tool("get_domain", "Returns one domain with its plan and the last stored MX and verification status (not a live check).", { domainId }, async (a) => staleFlagsAsNull(await sdk.domains.get(a.domainId)));
  tool("create_domain",
    "Adds a domain to the account and returns the DNS records to configure at the registrar (MX, verification TXT, 3 DKIM CNAMEs, SPF). The account's first domain is free; additional domains start blocked until activated ($99 MXN/month per domain).",
    { domain: z.string().describe("Domain, e.g. yourdomain.com") }, (a) => sdk.domains.create(a.domain));
  tool("verify_domain", "Re-checks with Amazon SES whether the domain's DNS is verified (identity and DKIM) and whether its MX points to MailMask, stores the result and returns it.", { domainId }, (a) => sdk.domains.verify(a.domainId));
  tool("domain_health", "Checks the domain live: SES verification, MX, SPF, DKIM, active addresses and plan. Returns the measured status and stores it.", { domainId }, (a) => sdk.domains.health(a.domainId));
  tool("delete_domain", "Permanently deletes the domain with all its addresses, rules and mailboxes.", { domainId }, (a) => sdk.domains.delete(a.domainId));

  // --- Máscaras ---
  tool("list_aliases", "Lists the addresses (aliases) of a domain with their destinations, status and whether they have an IMAP mailbox.", { domainId }, (a) => sdk.aliases.list(a.domainId));
  tool("create_alias",
    "Creates an address (alias) on the domain. `destinations` are the inboxes it forwards to; '*' as alias is a catch-all. With `mailbox: true` it also stores mail in an IMAP mailbox (activated domains only) and returns its credentials once. Free domains allow 5 addresses.",
    { domainId, alias: aliasName, destinations: z.array(z.string()).optional().describe("Destination emails; may be omitted when mailbox is true"), mailbox: z.boolean().optional() },
    (a) => sdk.aliases.create(a.domainId, { alias: a.alias, destinations: a.destinations, mailbox: a.mailbox }));
  tool("update_alias", "Enables or disables an address, or replaces its forwarding destinations.", { domainId, alias: aliasName, enabled: z.boolean().optional(), destinations: z.array(z.string()).optional() },
    (a) => sdk.aliases.update(a.domainId, a.alias, { enabled: a.enabled, destinations: a.destinations }));
  tool("delete_alias", "Permanently deletes an address and its IMAP mailbox, if it has one.", { domainId, alias: aliasName }, (a) => sdk.aliases.delete(a.domainId, a.alias));
  tool("create_mailbox", "Creates an IMAP mailbox for an existing address (activated domains only). Returns the email, the password (shown once) and the IMAP/SMTP settings.", { domainId, alias: aliasName }, (a) => sdk.aliases.createMailbox(a.domainId, a.alias));
  tool("delete_mailbox", "Permanently deletes an address's IMAP mailbox and all the mail stored in it. The address must keep at least one forwarding destination.", { domainId, alias: aliasName }, (a) => sdk.aliases.deleteMailbox(a.domainId, a.alias));
  tool("reset_mailbox_password", "Generates a new password for an address's IMAP mailbox, invalidating the old one, and returns it once; it is not stored anywhere.", { domainId, alias: aliasName }, (a) => sdk.aliases.resetMailboxPassword(a.domainId, a.alias));

  // --- DNS ---
  //
  // Las descripciones están escritas para que las lea un LLM: dicen qué hace la herramienta,
  // qué NO puede hacer y qué hacer después. La trampa de `set_dns_record` es que reemplaza
  // el conjunto, así que se dice explícitamente cómo se añade un valor sin borrar los otros.

  tool("list_dns_records",
    "Lists the DNS records of a domain whose zone MailMask manages, plus the zone status. Records with `managed: true` are created by MailMask for email and cannot be deleted.",
    { domainId }, (a) => sdk.dns.list(a.domainId));

  tool("create_dns_zone",
    "Creates a MailMask-managed DNS zone for a domain registered elsewhere. Copies the records it finds at the current provider (returned as `imported`) and returns the nameservers to set at the registrar; edits take effect only after the nameservers change.",
    { domainId }, (a) => sdk.dns.createZone(a.domainId));

  tool("dns_delegation_status",
    "Checks whether the domain already uses MailMask's nameservers. Returns the nameservers observed now and the expected ones. Nameserver changes take 1 to 48 hours.",
    { domainId }, (a) => sdk.dns.delegation(a.domainId));

  tool("set_dns_record",
    "Creates or replaces a DNS record set in a MailMask-managed zone. `values` fully replaces whatever existed for that name and type. `name` is '@' for the root or a subdomain ('www'). For MX the priority goes inside the value: '10 mail.example.com'. Default TTL 300.",
    {
      domainId,
      name: z.string().describe("'@' for the root, or the subdomain ('www')"),
      type: z.enum(["A", "AAAA", "CNAME", "TXT", "MX", "NS", "CAA", "SRV"]),
      values: z.array(z.string()).describe("The complete list of values the record must have"),
      ttl: z.number().optional().describe("Seconds, between 60 and 172800. Default 300."),
    },
    (a) => sdk.dns.upsert(a.domainId, { name: a.name, type: a.type, values: a.values, ttl: a.ttl }));

  tool("delete_dns_record",
    "Deletes a whole DNS record set (all its values) from a MailMask-managed zone. MailMask's email records are protected and return an error.",
    { domainId, name: z.string(), type: z.enum(["A", "AAAA", "CNAME", "TXT", "MX", "NS", "CAA", "SRV"]) },
    (a) => sdk.dns.delete(a.domainId, a.name, a.type));

  tool("import_dns_records",
    "Queries the domain's current public DNS and returns the records found, without writing anything. Not guaranteed to be exhaustive.",
    { domainId }, (a) => sdk.dns.import(a.domainId));

  tool("point_domain_to",
    "Points the domain (or a subdomain) to a hosting provider by writing the needed records in the MailMask-managed zone. For 'vercel' the `target` is the Vercel domain ('my-project.vercel.app'); for 'github-pages' it is 'user.github.io'; for 'dmarc' it is the email that receives reports. 'easybits' publishes a site of the user's connected EasyBits account and needs `websiteId` (without it, the error lists the sites; without a connected account, it returns the link to connect it). Without `subdomain` it points the root and www. With `dryRun` it returns the records it would write and the current ones, without writing.",
    {
      domainId,
      provider: z.enum(["vercel", "netlify", "github-pages", "cloudflare-pages", "render", "fly", "easybits", "redirect-a-www", "dmarc"]),
      target: z.string().optional().describe("The target given by the hosting provider"),
      subdomain: z.string().optional().describe("To point only a subdomain, e.g. 'app'"),
      websiteId: z.string().optional().describe("Only for 'easybits': the EasyBits site to publish"),
      placement: z.enum(["apex", "subdomain"]).optional().describe("Only for 'easybits': 'apex' (root and www) or 'subdomain' (<site slug>.<domain>)"),
      dryRun: z.boolean().optional().describe("Preview only: return what would change"),
    },
    (a) => {
      const opts = a.provider === "easybits" ? { websiteId: a.websiteId, placement: a.placement } : undefined;
      return a.dryRun
        ? sdk.dns.presetPreview(a.domainId, a.provider, a.target, a.subdomain, opts)
        : sdk.dns.preset(a.domainId, a.provider, a.target, a.subdomain, opts);
    });

  tool("publish_easybits_site",
    "Publishes a site of the user's connected EasyBits account on the domain: registers the domain in EasyBits, writes its records in the MailMask-managed zone (email records untouched), verifies it and, for 'apex', assigns the root. Returns the URL, the records and whether EasyBits already verified it. With `dryRun` it returns the records it would write and the current ones, without writing. Without a connected EasyBits account it returns the link to connect it in the browser.",
    {
      domainId,
      websiteId: z.string().describe("The EasyBits site id"),
      placement: z.enum(["apex", "subdomain"]).describe("'apex' = root and www; 'subdomain' = <site slug>.<domain>"),
      dryRun: z.boolean().optional().describe("Preview only: return what would change"),
    },
    (a) => sdk.domains.publishEasyBitsSite(a.domainId, { websiteId: a.websiteId, placement: a.placement, dryRun: a.dryRun }));

  tool("unpublish_easybits_site",
    "Removes the EasyBits site published on the domain: restores the DNS records that existed before publishing, in one change (records the user edited afterwards are left as they are and returned as `skipped`), and cleans up EasyBits. Returns `restored`, `skipped` and the EasyBits cleanup; `nothing: true` if no site was published.",
    { domainId }, (a) => sdk.domains.unpublishEasyBitsSite(a.domainId));

  tool("easybits_site_status",
    "Returns whether an EasyBits site is published on the domain (URL, placement and the records written), whether the user's EasyBits account is connected, and the sites of that account.",
    { domainId }, (a) => sdk.domains.easyBitsSiteStatus(a.domainId));

  tool("website_status",
    "Returns where the domain's website points: for the root, www and each web subdomain, its A/AAAA/CNAME records, the detected hosting platform, configuration issues and an HTTPS check (status code, redirect and certificate expiry).",
    { domainId }, (a) => sdk.dns.website(a.domainId));

  // --- Reglas ---
  const ruleShape = {
    field: z.enum(["to", "from", "subject"]),
    match: z.enum(["contains", "equals", "regex"]).describe("A dangerous regex (ReDoS) is rejected with 400"),
    value: z.string(),
    action: z.enum(["forward", "webhook", "discard"]),
    target: z.string().optional().describe("Destination email for forward, or URL for webhook"),
    priority: z.number().int().optional(),
    enabled: z.boolean().optional(),
  };
  tool("list_rules", "Lists the domain's routing rules.", { domainId }, (a) => sdk.rules.list(a.domainId));
  tool("create_rule", "Creates a routing rule that matches incoming mail by to, from or subject and forwards, posts to a webhook or discards it (activated domains only).", { domainId, ...ruleShape }, ({ domainId: d, ...r }) => sdk.rules.create(d, r));
  tool("update_rule", "Updates fields of a routing rule.", { domainId, ruleId: z.string(), ...Object.fromEntries(Object.entries(ruleShape).map(([k, v]) => [k, v.optional()])) as { [K in keyof typeof ruleShape]: z.ZodOptional<(typeof ruleShape)[K]> } },
    ({ domainId: d, ruleId, ...r }) => sdk.rules.update(d, ruleId, r));
  tool("delete_rule", "Deletes a routing rule.", { domainId, ruleId: z.string() }, (a) => sdk.rules.delete(a.domainId, a.ruleId));

  // --- Webhooks ---
  const events = z.array(z.enum(["email.received", "email.sent", "email.delivered", "email.bounced", "email.complained"]));
  tool("list_webhooks", "Lists the domain's webhooks.", { domainId }, (a) => sdk.webhooks.list(a.domainId));
  tool("create_webhook", "Creates a webhook for email events (activated domains only, public https URL, max 10 per domain). The signing secret is returned once.", { domainId, url: z.string().url(), events },
    (a) => sdk.webhooks.create(a.domainId, { url: a.url, events: a.events }));
  tool("update_webhook", "Changes a webhook's URL, events or enabled state.", { domainId, webhookId: z.string(), url: z.string().url().optional(), events: events.optional(), enabled: z.boolean().optional() },
    ({ domainId: d, webhookId, ...r }) => sdk.webhooks.update(d, webhookId, r));
  tool("delete_webhook", "Deletes a webhook.", { domainId, webhookId: z.string() }, (a) => sdk.webhooks.delete(a.domainId, a.webhookId));
  tool("test_webhook", "Queues a test `ping` event for a webhook; it is delivered within the next minute.", { domainId, webhookId: z.string() }, (a) => sdk.webhooks.test(a.domainId, a.webhookId));
  tool("webhook_deliveries", "Returns a webhook's latest deliveries with HTTP status, attempts and error.", { domainId, webhookId: z.string() }, (a) => sdk.webhooks.deliveries(a.domainId, a.webhookId));

  // --- Envío ---
  tool("send_email",
    "Sends a one-off email from the domain (activated domains: 50 per day) without creating a conversation in the shared Inbox. `from` is the local part of an active address; without it the email is sent from noreply@. Body: `markdown` (adds the domain signature), `html` or `body` (plain text). Returns the message id.",
    {
      domainId, to: z.string(), subject: z.string(),
      markdown: z.string().optional(), html: z.string().optional(), body: z.string().optional(),
      from: z.string().optional(), fromName: z.string().optional(), replyTo: z.string().optional(),
      cc: z.array(z.string()).max(20).optional(), bcc: z.array(z.string()).max(20).optional(),
      inReplyTo: z.string().optional(), references: z.string().optional(),
      attachments: attachmentsShape,
      idempotencyKey: z.string().max(128).optional().describe("Retrying with the same key does not resend or use quota (24 h)"),
    },
    ({ domainId: d, idempotencyKey, ...input }) => sdk.send.send(d, input, { idempotencyKey }));
  tool("bulk_send", "Starts an asynchronous bulk send to several recipients and returns a jobId.", { domainId, recipients: z.array(z.string()), subject: z.string(), html: z.string(), from: z.string().optional() },
    ({ domainId: d, ...input }) => sdk.send.bulkSend(d, input));
  tool("bulk_status", "Returns the status of a bulk send job.", { domainId, jobId: z.string() }, (a) => sdk.send.bulkStatus(a.domainId, a.jobId));

  // --- Operación ---
  tool("list_logs", "Returns the domain's log of forwarded and sent emails.", { domainId, limit: z.number().int().min(1).max(100).optional() }, (a) => sdk.logs.list(a.domainId, { limit: a.limit }));
  tool("list_suppressions", "Lists the addresses the domain no longer sends to (hard bounce, complaint or manual).", { domainId }, (a) => sdk.suppressions.list(a.domainId));
  tool("add_suppression", "Stops sending from the domain to an email address.", { domainId, email: z.string() }, (a) => sdk.suppressions.add(a.domainId, a.email));
  tool("remove_suppression", "Allows sending to a previously suppressed email address again.", { domainId, email: z.string() }, (a) => sdk.suppressions.remove(a.domainId, a.email));
  tool("list_smtp_credentials", "Lists the domain's SMTP relay credentials (without passwords).", { domainId }, (a) => sdk.smtp.list(a.domainId));
  tool("create_smtp_credential", "Creates an SMTP relay credential (activated domains only). The password is returned once.", { domainId, label: z.string() }, (a) => sdk.smtp.create(a.domainId, a.label));
  tool("revoke_smtp_credential", "Revokes an SMTP relay credential.", { domainId, credentialId: z.string() }, (a) => sdk.smtp.revoke(a.domainId, a.credentialId));

  // --- Conectar, activar y cobrar ---
  //
  // Lo que antes necesitaba a una persona por WhatsApp: dictar los registros, explicar el
  // "bloqueado" y mandar la liga de pago. Un pago SIEMPRE lo hace el usuario en MercadoPago.

  tool("domain_dns_setup",
    "Returns the exact records to paste at the registrar to connect the domain (MX, TXT _amazonses, 3 DKIM CNAMEs, recommended SPF, optional DMARC), with relative `name` and `fqdn`. With `live` (default) it marks which are already visible in public DNS (`ok`), suggests a merged SPF if one exists and, in `registrarHint`, names the registrar panel and menu (Hostinger, GoDaddy, Cloudflare, Namecheap, Route 53).",
    { domainId, live: z.boolean().optional().describe("Compare with public DNS (default true)") },
    (a) => sdk.domains.dnsSetup(a.domainId, { live: a.live ?? true }));

  tool("activation_link",
    "Returns a MercadoPago checkout link to activate a domain ($99 MXN/month or $999/year): unblocks it and enables unlimited addresses, team, sending and mailboxes. With `kind` it buys an extra block for an already activated domain. Nothing is charged until the user pays at the link; the response has `paid: false`.",
    {
      domainId,
      kind: z.enum(["domain", "storage50", "sends100"]).optional().describe("domain = activate (default); storage50 = +50 GB mailbox storage; sends100 = +100 sends/day"),
      payerEmail: z.string().optional().describe("Payer's MercadoPago account email, if different from the MailMask one"),
      period: z.enum(["monthly", "annual"]).optional().describe("Activation only: monthly ($99/month, default) or annual ($999/year)"),
    },
    async (a) => {
      const r = await sdk.billing.checkout(a.domainId, a.kind ?? "domain", { payerEmail: a.payerEmail, period: a.period });
      return { paymentUrl: r.init_point, addonId: r.addonId, paid: false, note: "Liga de pago para el usuario. No está pagado hasta que MercadoPago lo confirme." };
    });

  tool("billing_status", "Returns the account's legacy plan subscription, if any. Current billing is per domain add-on.", {}, () => sdk.billing.status());
  tool("list_addons", "Returns the add-on catalog with prices (MXN cents) and the user's add-ons with status and domain. An active `domain` add-on on a domainId means that domain is activated.", {}, () => sdk.billing.addons());

  // --- Comprar y transferir dominios ---

  tool("search_domains", "Checks whether a domain is available to buy and its yearly price (MXN cents). Include the extension: 'mycompany.com'.", { domain: z.string() }, (a) => sdk.registrations.search(a.domain));
  tool("domain_prices", "Lists the extensions available to buy with registration, renewal and transfer prices (MXN cents per year).", {}, () => sdk.registrations.tlds());
  tool("register_domain",
    "Creates a pending domain registration and returns the MercadoPago checkout link (one year). Registration and email DNS are configured automatically once the user pays.",
    { domain: z.string() },
    async (a) => {
      const r = await sdk.registrations.register(a.domain);
      return { paymentUrl: r.initPoint, registrationId: r.registrationId, paid: false, note: "El usuario abre la liga y paga; sigue el avance con list_registrations." };
    });
  tool("list_registrations", "Lists domains bought or transferred through MailMask with their status (`statusText`), expiration and renewal.", {},
    async () => (await sdk.registrations.list()).map((r) => ({ ...r, statusText: registrationStatusText(r) })));

  tool("transfer_check",
    "Before transferring a domain to MailMask: returns requirements (age, lock, privacy), price (includes 1 year) and the domain's current DNS records. Charges and creates nothing.",
    { domain: z.string() }, (a) => sdk.transfers.check(a.domain));
  tool("transfer_start",
    "Prepares a domain transfer to MailMask and returns `formUrl`, a secure form in the MailMask app where the user enters the EPP code and WHOIS data and pays. The EPP code is never part of this tool's input or output.",
    { domain: z.string() },
    async (a) => {
      const c = await sdk.transfers.check(a.domain);
      const blockers = c.requisitos.filter((r) => r.ok === false);
      return {
        domain: c.domain,
        price: c.price,
        currency: c.currency,
        ready: blockers.length === 0,
        blockers,
        requisitos: c.requisitos,
        dnsRecordsFound: c.dns.found.length,
        formUrl: appUrl(`/app#transfer=${encodeURIComponent(c.domain)}`),
        note: blockers.length
          ? "Primero hay que resolver lo de `blockers` en el registrador actual."
          : "Manda al usuario a formUrl: ahí pega el código EPP y sus datos WHOIS y paga. No le pidas el código aquí.",
      };
    });
  tool("transfer_status", "Returns the status of the user's domain transfers (or one of them), described in words (`statusText`).",
    { domain: z.string().optional() },
    async (a) => (await sdk.registrations.list())
      .filter((r) => r.kind === "transfer" && (!a.domain || r.domainName === a.domain.toLowerCase().trim()))
      .map((r) => ({
        registrationId: r.id, domain: r.domainName, status: r.status, statusText: registrationStatusText(r),
        dnsImportStatus: r.dnsImportStatus, eppHint: r.transferAuthCodeHint, createdAt: r.createdAt, lastError: r.lastError,
      })));
  const registrationId = z.string().describe("Registration ID");
  tool("transfer_dns", "Returns the DNS inventory the domain will use once the transfer completes. Records not in it will stop working.", { registrationId }, (a) => sdk.transfers.dns(a.registrationId));
  tool("update_transfer_dns",
    "Replaces a transfer's DNS inventory with the complete list provided. The inventory goes back to pending approval.",
    { registrationId, records: z.array(z.object({ name: z.string(), type: z.string(), ttl: z.number().optional(), values: z.array(z.string()) })) },
    (a) => sdk.transfers.setDns(a.registrationId, a.records));
  tool("approve_transfer_dns", "Approves the transfer's DNS inventory; DNS is moved only after this approval.", { registrationId }, (a) => sdk.transfers.approveDns(a.registrationId));
  tool("resend_transfer_email", "Asks the registrar to resend the transfer approval email.", { registrationId }, (a) => sdk.transfers.resendEmail(a.registrationId));

  tool("transfer_out",
    "Starts moving a domain bought through MailMask to another registrar. The owner receives an email to confirm, and the EPP code is sent there, never in this response.",
    { registrationId }, (a) => sdk.registrations.transferOut(a.registrationId));
  tool("lock_domain_transfer",
    "Turns on the transfer lock of a domain bought through MailMask so it cannot be moved to another registrar. Unlocking is only possible from the MailMask dashboard with email confirmation.",
    { registrationId }, (a) => sdk.registrations.lock(a.registrationId));
  tool("renewal_status", "Returns expiration and yearly renewal details of domains bought through MailMask.",
    { registrationId: registrationId.optional() },
    async (a) => (await sdk.registrations.list())
      .filter((r) => !a.registrationId || r.id === a.registrationId)
      .map((r) => ({ registrationId: r.id, domain: r.domainName, status: r.status, expiresAt: r.expiresAt, renewalStatus: r.renewalStatus, renewalPriceCents: r.renewalPriceCents, nextChargeAt: r.nextChargeAt, transferLock: r.transferLock, transferUnlockedUntil: r.transferUnlockedUntil })));
  tool("renewal_link", "Returns a MercadoPago link to authorize automatic yearly renewal of a registered domain. Nothing is charged until the user authorizes it.",
    { registrationId, payerEmail: z.string().optional() },
    async (a) => {
      const r = await sdk.registrations.renewal(a.registrationId, { payerEmail: a.payerEmail });
      return { paymentUrl: r.init_point, nextChargeAt: r.nextChargeAt, paid: false };
    });

  // --- Equipo ---
  tool("list_members", "Lists the people with access to the domain's shared Inbox and pending invitations.", { domainId }, (a) => sdk.members.list(a.domainId));
  tool("invite_member", "Invites a person to the domain's shared Inbox (activated domains only); they receive an email with a link to accept. role: agent (answers) or admin.",
    { domainId, email: z.string(), name: z.string(), role: z.enum(["agent", "admin"]).optional() },
    (a) => sdk.members.invite(a.domainId, { email: a.email, name: a.name, role: a.role }));
  tool("remove_member", "Removes a person's access to the domain.", { domainId, memberId: z.string() }, (a) => sdk.members.remove(a.domainId, a.memberId));
  tool("cancel_invite", "Cancels a pending team invitation.", { domainId, token: z.string() }, (a) => sdk.members.cancelInvite(a.domainId, a.token));

  // --- Bandeja ---
  tool("get_signature", "Returns the domain's email signature (markdown) added to outgoing markdown emails.", { domainId }, (a) => sdk.signature.get(a.domainId));
  tool("set_signature", "Replaces the domain's email signature (markdown, max 2000 characters; empty removes it). Applies only to emails written in markdown.",
    { domainId, signature: z.string() }, (a) => sdk.signature.set(a.domainId, a.signature));
  tool("list_canned_replies", "Lists the saved replies of the domain's shared Inbox.", { domainId }, (a) => sdk.canned.list(a.domainId));
  tool("create_canned_reply", "Saves a reusable reply (title and markdown body; max 50 per domain).",
    { domainId, title: z.string(), body: z.string() }, (a) => sdk.canned.create(a.domainId, { title: a.title, body: a.body }));
  tool("delete_canned_reply", "Deletes a saved reply.", { domainId, cannedId: z.string() }, (a) => sdk.canned.delete(a.domainId, a.cannedId));

  // --- Bandeja: el agente atiende el correo de su máscara ---
  //
  // Son las rutas de la app tal cual (vía SDK): mismos permisos por dominio y rol
  // (`requireBandeja`), mismo recorte de 7 días del dominio gratis y mismos topes de envío.
  // Lo único que se hace aquí es darle al modelo texto en vez de HTML.
  const conversationId = z.string().describe("Conversation ID");
  const aDireccion = async (d: string, alias?: string) => {
    if (!alias) return undefined;
    if (alias.includes("@")) return alias.toLowerCase().trim();
    return `${alias.toLowerCase().trim()}@${(await sdk.domains.get(d)).domain}`;
  };
  // El texto de cada mensaje se acota: un hilo con boletines HTML enteros no cabe en un turno.
  const TOPE_TEXTO = 12_000;
  const recorta = (t: string | undefined) => !t ? "" : t.length > TOPE_TEXTO ? `${t.slice(0, TOPE_TEXTO)}\n[… recortado: ${t.length - TOPE_TEXTO} caracteres más]` : t;
  // "Dominio no verificado" sin pista deja al agente sin salida.
  const conPista = async <T>(p: Promise<T>): Promise<T> => {
    try { return await p; } catch (e) {
      if (e instanceof MailMaskError && /no verificado/i.test(e.message)) {
        throw new MailMaskError(e.status, `${e.message}. El DNS del dominio aún no está verificado: revisa domain_dns_setup y luego verify_domain.`);
      }
      throw e;
    }
  };

  tool("inbox_list",
    "Lists conversations in a domain's shared Inbox, newest first. Filters: `alias` (local part or full address), `status` (open, snoozed, closed, unread = unread by you, deleted = trash) and `assignedTo`. `q` searches subject, sender and body (max 50, no pagination). Pass `cursor` = nextCursor for the next page. Free domains show only the last 7 days.",
    {
      domainId,
      alias: z.string().optional().describe("Thread address: local part or full address"),
      status: z.enum(["open", "snoozed", "closed", "unread", "deleted"]).optional(),
      assignedTo: z.string().optional().describe("Email of the assigned person"),
      q: z.string().optional().describe("Text to search"),
      limit: z.number().int().min(1).max(100).optional().describe("Default 50"),
      cursor: z.string().optional(),
    },
    async (a) => {
      const r = await sdk.inbox.list(a.domainId, { status: a.status, to: await aDireccion(a.domainId, a.alias), assignedTo: a.assignedTo, q: a.q, limit: a.limit, cursor: a.cursor });
      return {
        conversations: r.items.map((c) => ({
          id: c.id, contact: c.from, alias: c.to, subject: c.subject, status: c.status, unread: c.unread ?? null,
          assignedTo: c.assignedTo ?? null, priority: c.priority, tags: c.tags, lastMessageAt: c.lastMessageAt,
          messageCount: c.messageCount, snoozedUntil: c.snoozedUntil ?? null, snippet: c.snippet,
        })),
        nextCursor: r.nextCursor,
        unreadCount: r.unreadCount,
        aliases: r.aliases,
      };
    }, BANDEJA_LIST_META);

  tool("inbox_read",
    "Opens a conversation and returns its messages as plain text (the 30 most recent; pass `before` = nextBefore for older ones), the team's internal notes and each message's attachments. Marks it as read for you. `direction` inbound = from the contact, outbound = sent from the domain.",
    { domainId, conversationId, before: z.string().optional().describe("nextBefore from a previous read") },
    async (a) => {
      const c = await sdk.inbox.get(a.domainId, a.conversationId, { before: a.before });
      return {
        id: c.id, contact: c.from, alias: c.to, subject: c.subject, status: c.status, priority: c.priority,
        assignedTo: c.assignedTo ?? null, tags: c.tags, snoozedUntil: c.snoozedUntil ?? null, deleted: !!c.deletedAt,
        messages: c.messages.map((m) => ({
          id: m.id, direction: m.direction, from: m.from, date: m.createdAt, text: recorta(m.body),
          ...(m.deliveryStatus ? { deliveryStatus: m.deliveryStatus } : {}),
          ...(m.bodyDegraded ? { bodyDegraded: m.bodyDegraded } : {}),
          attachments: (m.attachments ?? []).map((x) => ({ index: x.index, filename: x.filename, contentType: x.contentType, size: x.size })),
        })),
        notes: c.notes.map((n) => ({ author: n.author, body: n.body, date: n.createdAt })),
        totalMessages: c.totalMessages,
        nextBefore: c.hasMore && c.messages.length ? c.messages[0].createdAt : null,
      };
    }, BANDEJA_CALLABLE_META);

  tool("inbox_attachment",
    "Reads an attachment of a received message by messageId and index. Text, CSV, JSON and similar come back as text; images up to 2 MB as an image; other types (PDF, Office, zip) only with name and size.",
    { domainId, conversationId, messageId: z.string(), index: z.number().int().min(0) },
    async (a) => {
      const res = await sdk.inbox.attachment(a.domainId, a.conversationId, a.messageId, a.index);
      const tipo = (res.headers.get("content-type") ?? "application/octet-stream").split(";")[0].trim().toLowerCase();
      const nombre = /filename="([^"]*)"/.exec(res.headers.get("content-disposition") ?? "")?.[1] ?? "adjunto";
      const bytes = new Uint8Array(await res.arrayBuffer());
      const meta = { filename: nombre, contentType: tipo, size: bytes.length };
      if (/^text\/|json|xml|csv|calendar|yaml/.test(tipo)) return { ...meta, text: recorta(new TextDecoder().decode(bytes)) };
      if (tipo.startsWith("image/") && tipo !== "image/svg+xml" && bytes.length <= 2 * 1024 * 1024) {
        return { __image: { data: Buffer.from(bytes).toString("base64"), mimeType: tipo }, ...meta };
      }
      return { ...meta, note: "Este tipo de archivo no se puede leer aquí; el usuario lo abre desde la Bandeja en la app." };
    });

  tool("inbox_reply",
    "Sends a reply in the conversation thread, from the thread's address to the contact (Re: subject). Write it in `markdown`: it adds the domain signature and quotes the last received message (`quote: false` to skip). Does not use the daily send quota (limit 200 replies per hour per domain). Requires the domain's DNS to be verified.",
    {
      domainId, conversationId,
      markdown: z.string().optional().describe("Markdown body (recommended)"),
      body: z.string().optional().describe("Plain text, without signature"),
      html: z.string().optional(),
      cc: z.array(z.string()).max(20).optional(), bcc: z.array(z.string()).max(20).optional(),
      quote: z.boolean().optional(),
      attachments: attachmentsShape,
    },
    ({ domainId: d, conversationId: c, ...input }) => conPista(sdk.inbox.reply(d, c, input)));

  tool("inbox_send",
    "Sends a new email from an active address of the domain and opens a conversation in the shared Inbox, so the contact's reply lands in the same thread. Requires an activated and verified domain; uses 1 of the day's sends.",
    {
      domainId,
      fromAlias: z.string().describe("Local part of the sending address: 'sales'"),
      to: z.string(), subject: z.string(),
      markdown: z.string().optional().describe("Markdown body (recommended: adds the signature)"),
      body: z.string().optional(), html: z.string().optional(),
      cc: z.array(z.string()).max(20).optional(), bcc: z.array(z.string()).max(20).optional(),
      attachments: attachmentsShape,
    },
    ({ domainId: d, ...input }) => conPista(sdk.inbox.compose(d, input)));

  tool("inbox_mark",
    "Changes a conversation's state: `read` true marks it read for you; `status` closed = archive/resolve, open = reopen, snoozed = snooze until `snoozedUntil` (future ISO date, max 90 days; a new email wakes it earlier); `priority` normal or urgent; `tags` replaces the tags.",
    {
      domainId, conversationId,
      read: z.boolean().optional(),
      status: z.enum(["open", "snoozed", "closed"]).optional(),
      snoozedUntil: z.string().optional(),
      priority: z.enum(["normal", "urgent"]).optional(),
      tags: z.array(z.string()).optional().describe("The complete list of tags"),
    },
    async ({ domainId: d, conversationId: c, read, ...cambios }) => {
      const hayCambios = Object.values(cambios).some((v) => v !== undefined);
      if (!hayCambios && !read) throw new Error("Nada que cambiar: pasa read, status, priority o tags.");
      const conv = hayCambios ? await sdk.inbox.update(d, c, cambios) : undefined;
      const leida = read ? await sdk.inbox.markRead(d, c) : undefined;
      return { ok: true, ...(conv ? { status: conv.status, priority: conv.priority, tags: conv.tags, snoozedUntil: conv.snoozedUntil ?? null } : {}), ...(leida ? { unreadCount: leida.unreadCount } : {}) };
    }, BANDEJA_CALLABLE_META);

  tool("inbox_assign", "Assigns a conversation to a team member by email or, without `assignedTo`, unassigns it. Requires owner or admin.",
    { domainId, conversationId, assignedTo: z.string().optional() }, (a) => sdk.inbox.assign(a.domainId, a.conversationId, a.assignedTo));
  tool("inbox_note", "Adds an internal note to a conversation. The team sees it in the Inbox; the contact never does.",
    { domainId, conversationId, body: z.string() }, (a) => sdk.inbox.addNote(a.domainId, a.conversationId, a.body));
  tool("inbox_delete", "Moves up to 200 conversations to the trash (restorable for 15 days, then permanently deleted). Owner or admin only.",
    { domainId, conversationIds: z.array(z.string()).min(1).max(200) }, (a) => sdk.inbox.delete(a.domainId, a.conversationIds));
  tool("inbox_restore", "Takes a conversation out of the trash.",
    { domainId, conversationId }, (a) => sdk.inbox.restore(a.domainId, a.conversationId));
  tool("inbox_metrics", "Returns shared Inbox metrics: volume, first-response times, breakdown per person and per day.",
    { domainId, days: z.number().int().min(1).max(365).optional().describe("Default 30") }, (a) => sdk.inbox.metrics(a.domainId, { days: a.days }));

  tool("upload_attachment",
    "Uploads a file to attach to an outgoing email and returns the object that goes in `attachments`. Pass `url` (a file the user attached in the MailMask assistant chat) or `contentBase64` with `filename`. Max 5 MB; executables are blocked. Valid until sent.",
    {
      domainId,
      url: z.string().optional().describe("URL of the chat attachment (/api/asistente/files/...)"),
      contentBase64: z.string().optional(),
      filename: z.string().optional(),
      contentType: z.string().optional().describe("Default application/octet-stream"),
    },
    async (a) => {
      const r = a.url
        ? await sdk.attachments.uploadFromUrl(a.domainId, a.url, a.filename)
        : a.contentBase64
          ? await sdk.attachments.upload(a.domainId, { filename: a.filename || "archivo", contentType: a.contentType || "application/octet-stream", data: Buffer.from(a.contentBase64, "base64") })
          : (() => { throw new Error("Pasa url o contentBase64."); })();
      return { attachment: { key: r.key, filename: r.filename, ...(a.contentType ? { contentType: a.contentType } : {}) }, size: r.size };
    });

  tool("set_domain_logo",
    "Sets the logo shown with the domain's email signature (PNG, JPG or WebP; max 500 KB). Pass `url` of an image the user attached in the MailMask assistant chat, or `contentBase64` with `contentType`.",
    { domainId, url: z.string().optional(), contentBase64: z.string().optional(), contentType: z.enum(["image/png", "image/jpeg", "image/webp"]).optional() },
    async (a) => {
      if (a.url) return sdk.domains.setLogoFromUrl(a.domainId, a.url);
      if (!a.contentBase64 || !a.contentType) throw new Error("Pasa url, o contentBase64 con contentType.");
      return sdk.domains.setLogo(a.domainId, new Blob([Buffer.from(a.contentBase64, "base64")], { type: a.contentType }), "logo");
    });
  tool("delete_domain_logo", "Removes the logo from the domain's email signature.", { domainId }, (a) => sdk.domains.removeLogo(a.domainId));

  // --- Cuenta: cobros, cancelaciones y referidos ---
  tool("list_orders", "Returns the account's charges, courtesies and cancellations (folio, concept, amount in cents, period). For invoices (CFDI) the response says where to write.",
    { limit: z.number().int().min(1).max(200).optional(), before: z.string().optional().describe("nextCursor from the previous page") },
    (a) => sdk.billing.orders({ limit: a.limit, before: a.before }));
  tool("cancel_addon",
    "Cancels an add-on subscription (for example a domain activation). Billing stops and the included features last until the end of the paid period. Courtesy add-ons cannot be cancelled.",
    { addonId: z.string() }, (a) => sdk.billing.cancelAddon(a.addonId));
  tool("cancel_renewal",
    "Cancels the automatic yearly renewal of a domain bought through MailMask. The domain stays valid until it expires and may be lost afterwards.",
    { registrationId }, (a) => sdk.registrations.cancelRenewal(a.registrationId));
  tool("referral_status", "Returns the account's referral program: own link (slug), name shown to invitees, referrals and available credits.", {}, () => sdk.referrals.get());
  tool("set_referral_slug", "Changes the referral link slug (3-30 characters: lowercase letters, numbers and hyphens). Returns 409 if it is taken.",
    { slug: z.string() }, (a) => sdk.referrals.setSlug(a.slug));
  tool("set_referral_name", "Sets the name invitees see (\"Brenda invited you\"), 2-40 characters.",
    { name: z.string() }, (a) => sdk.referrals.setName(a.name));
  tool("export_link", "Returns a link to download a JSON with all the account's domains, addresses, rules and latest logs. It opens in a browser signed in to MailMask (5 per day).",
    {}, async () => ({ url: appUrl("/api/export"), note: "Abrir en el navegador con sesión iniciada en MailMask." }));

  // --- Perfil de la cuenta ---
  //
  // Es el perfil del usuario de MailMask (cabecera de /app, Bandeja, dock), no el de una
  // máscara ni lo que ve quien recibe el correo.
  tool("get_profile", "Returns the user's MailMask account profile: email, display name and photo (avatarUrl).", {}, () => sdk.account.getProfile());
  tool("update_profile", "Changes the account's display name (max 60 characters; empty removes it). It is the name the team sees in the Inbox; it does not change the email sender.",
    { displayName: z.string() }, (a) => sdk.account.updateProfile({ displayName: a.displayName }));
  tool("set_profile_photo", "Sets the account's profile photo from the URL of an image the user attached in the MailMask assistant chat (PNG, JPG or WebP, max 2 MB); any other URL is rejected.",
    { url: z.string().describe("URL of the chat attachment (/api/asistente/files/...)") }, (a) => sdk.account.setAvatarFromUrl(a.url));
  tool("delete_profile_photo", "Removes the account's profile photo.", {}, () => sdk.account.removeAvatar());

  // --- Buzones: ligas para el navegador del usuario ---
  //
  // Son archivos (un plist, un .mbox de GB): no tiene sentido pasarlos por el modelo. La liga
  // funciona en el navegador donde el usuario tiene la sesión de MailMask abierta.
  const requireMailbox = async (d: string, alias: string) => {
    const fila = (await sdk.aliases.list(d)).find((x) => x.alias === alias.toLowerCase());
    if (!fila?.mailboxEnabled) throw new Error(`La máscara ${alias} no tiene buzón IMAP. Primero hay que crearle un buzón.`);
  };
  tool("apple_profile_link",
    "Returns a link to the configuration profile that sets up an address's IMAP mailbox in Apple Mail (iPhone, iPad, Mac). It opens in Safari on the device, signed in to MailMask, and asks for the mailbox password when installed.",
    { domainId, alias: aliasName },
    async (a) => {
      await requireMailbox(a.domainId, a.alias);
      return { url: appUrl(`/api/domains/${a.domainId}/apple-profile?alias=${encodeURIComponent(a.alias.toLowerCase())}`), note: "Abrir en Safari del dispositivo, con sesión iniciada en MailMask." };
    });
  tool("mailbox_export_link",
    "Returns a link to download all the mail of an address's mailbox as .mbox (Thunderbird, Apple Mail). It opens in a browser signed in to MailMask; owner or admin only.",
    { domainId, alias: aliasName },
    async (a) => {
      await requireMailbox(a.domainId, a.alias);
      return { url: appUrl(`/api/domains/${a.domainId}/alias/${encodeURIComponent(a.alias.toLowerCase())}/mailbox/export`), note: "Abrir en el navegador con sesión iniciada en MailMask." };
    });

  // Catálogo por búsqueda: para clientes que prefieren cargar pocas herramientas.
  tool("search_tools", "Searches MailMask's tools by keyword (English or Spanish) and returns their names and descriptions.", { query: z.string() }, async (a) => {
    // Sin acentos de los dos lados: "renovacion" tiene que encontrar "renovación".
    const plain = (x: string) => x.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
    const q = plain(a.query).split(/\s+/).filter(Boolean);
    return catalogo.filter((t) => {
      const text = plain(`${t.name} ${t.description} ${KEYWORDS[t.name] ?? ""}`);
      return q.some((w) => text.includes(w));
    });
  });

  // Pantalla de la Bandeja (MCP Apps): el host la pide al ver `_meta.ui.resourceUri` en
  // inbox_list y la pinta en su iframe. Va en los dos perfiles: sus tools están en ambos.
  server.registerResource("Bandeja", BANDEJA_UI_URI, { title: "Bandeja de MailMask", description: "Lista y detalle de las conversaciones de la Bandeja compartida.", mimeType: MCP_APP_MIME, _meta: BANDEJA_RESOURCE_META }, (uri) => ({
    contents: [{ uri: uri.href, mimeType: MCP_APP_MIME, text: bandejaHtml(), _meta: BANDEJA_RESOURCE_META }],
  }));

  return server;
}

/** Atiende una petición HTTP de `/mcp` ya autenticada. Stateless: un servidor por petición. */
export async function atenderMcp(request: Request, o: { apiKey: string; fetchLocal: typeof fetch; profile?: McpProfile }): Promise<Response> {
  const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  const server = crearServidorMcp(o);
  await server.connect(transport);
  return transport.handleRequest(request);
}
