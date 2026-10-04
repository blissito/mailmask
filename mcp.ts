// Servidor MCP (Model Context Protocol) de MailMask: `POST /mcp`, Streamable HTTP sin
// sesiones. Cada herramienta es un método del SDK real (`sdk/src`) hablando con la app
// en proceso, así que no puede desalinearse de una ruta sin que `sdk.test.ts` lo cace.
// Para añadir una herramienta: método en el SDK → caso en `sdk.test.ts` → `tool()` aquí.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
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

## Conectar un dominio (en este orden)
1. create_domain (o list_domains si ya existe).
2. domain_dns_setup: los registros exactos (MX, TXT _amazonses, 3 CNAME de DKIM, SPF y DMARC opcional), si ya se ven en el DNS público (ok) y en qué panel pegarlos (registrarHint, deducido de los nameservers). Díctalos uno por uno con tipo, nombre y valor; si hay registrarHint, di en qué menú.
3. El usuario los pega en su registrador. Tú no puedes, salvo que la zona sea de MailMask (list_dns_records con zone.status "active").
4. verify_domain cuando diga que ya los puso. Propagar tarda de minutos a horas: si sale false, vuelve a domain_dns_setup y dile sólo qué registro falta.
5. domain_health para confirmar MX, SPF, DKIM, máscaras y plan.
6. Si el plan sale bloqueado: activation_link.
7. create_alias para que el correo llegue a algún lado: sin máscaras activas no se reenvía nada.

## Gratis, activado y bloqueado
- El dominio más antiguo de la cuenta es gratis: reenvía, 5 máscaras, Bandeja de 1 persona, sin envío de correo nuevo.
- Activado ($99 MXN/mes por dominio): máscaras ilimitadas, equipo, 50 envíos/día, buzones IMAP, reglas, webhooks, SMTP.
- Bloqueado = el 2.º dominio en adelante sin activar: el correo se GUARDA en la Bandeja pero NO se reenvía. No es una falla técnica; se arregla activándolo. Explícalo así, nunca como "error".
- Un 403 que menciona $99 significa "eso pide dominio activado": ofrece activation_link.

## Pagos
Todo cobro es una liga de MercadoPago que el USUARIO abre y paga (activation_link, register_domain, renewal_link, el formulario de transferencia). Nunca digas que algo quedó pagado o activado por haber dado la liga: confírmalo después con list_addons, list_registrations o domain_health.

## Transferir un dominio a MailMask
transfer_check (requisitos, precio, DNS actual) → transfer_start devuelve formUrl, un formulario de la app donde el usuario pega el código EPP y sus datos WHOIS, y paga. NUNCA pidas ni aceptes el código EPP (auth code) en el chat: si te lo pegan, dile que no lo comparta y que lo ponga en el formulario. Después, transfer_status. Cuando toque aprobar el DNS: transfer_dns para revisar el inventario con el usuario (lo que falte dejará de funcionar), update_transfer_dns si hay que corregir, y approve_transfer_dns sólo con su visto bueno. Si el registrador anterior no la suelta: resend_transfer_email, y que lo pida en el chat de su registrador. Que no pida otro EPP: invalida el que se mandó.

## Llevarse un dominio
transfer_out manda el código EPP por correo al dueño, nunca al chat.

## Acciones delicadas
Borrar dominio, máscara, buzón o registro DNS, sacar a un miembro, transferir fuera o cancelar un add-on o una renovación (cancel_addon, cancel_renewal) son irreversibles: confírmalo con el usuario antes. Algunas responden que necesitan confirmación: el usuario la aprueba en la app; no reintentes ni busques otra vía.

## DNS administrado por MailMask
Con zona propia (create_dns_zone y cambiar los nameservers en el registrador) puedes editar registros: list_dns_records antes de escribir; set_dns_record reemplaza el conjunto completo; point_domain_to para Vercel, Netlify y similares. Los registros de correo están protegidos.

## Bandeja: el correo de la máscara
Cada máscara recibe en la Bandeja del dominio; desde ahí se lee y se contesta como esa máscara.
- Lo nuevo: inbox_list con status "unread" (y alias para una máscara) → inbox_read (texto de cada mensaje, notas y adjuntos; lo marca leído) → inbox_attachment si hace falta un adjunto.
- Contestar: inbox_reply en markdown (lleva firma y cita). Antes de enviar, enseña el texto al usuario y espera su visto bueno, salvo que te haya dado instrucciones permanentes.
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
  referral_status: "referidos invitar liga créditos recomendar",
  set_referral_slug: "referidos liga slug",
  set_referral_name: "referidos nombre",
  export_link: "exportar descargar datos respaldo json",
};

const domainId = z.string().describe("ID del dominio (de list_domains)");
const attachmentsShape = z.array(z.object({ key: z.string(), filename: z.string(), contentType: z.string().optional() }))
  .max(10).optional().describe("Adjuntos devueltos por upload_attachment");
const aliasName = z.string().describe("Parte local de la máscara, sin el dominio: 'hola' para hola@tudominio.com");

// Con el turn token del asistente (`mt_`), lo destructivo contesta 409 `needs_confirmation`:
// al usuario le aparece una tarjeta para aprobarlo. No es un error para el modelo, y si
// lo pareciera, reintentaría.
function pideConfirmacion(titulo: string): Salida {
  return { content: [{ type: "text", text: `Necesita confirmación del usuario: le apareció una tarjeta en el asistente para aprobar «${titulo}». No reintentes; espera a que confirme.` }], structuredContent: { needsConfirmation: true, title: titulo } };
}

export function crearServidorMcp(o: { apiKey: string; fetchLocal: typeof fetch }): McpServer {
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
  const server = new McpServer({ name: "mailmask", version: MCP_VERSION }, { instructions: MCP_INSTRUCTIONS });
  const catalogo: { name: string; description: string }[] = [];

  const tool = <S extends z.ZodRawShape>(name: string, description: string, shape: S, run: (args: z.infer<z.ZodObject<S>>) => Promise<unknown>) => {
    catalogo.push({ name, description });
    // El genérico de registerTool no infiere bien con un shape genérico; el tipado real
    // de `args` lo garantiza la firma de `run`.
    const cb = async (args: z.infer<z.ZodObject<S>>) => {
      try { return ok(await run(args)); } catch (e) {
        if (e instanceof MailMaskError && e.status === 409 && e.message === "needs_confirmation") return pideConfirmacion(confirmacion ?? "la acción");
        return fallo(e);
      }
    };
    server.registerTool(name, { description, inputSchema: shape }, cb as unknown as Parameters<typeof server.registerTool>[2]);
  };

  // --- Dominios ---
  tool("list_domains", "Lista los dominios de la cuenta con su estado de verificación y reenvíos del mes.", {}, () => sdk.domains.list());
  tool("get_domain", "Detalle de un dominio.", { domainId }, (a) => sdk.domains.get(a.domainId));
  tool("create_domain",
    "Da de alta un dominio y devuelve los registros DNS que hay que configurar (MX, TXT de verificación, 3 CNAME de DKIM, SPF). El primer dominio de la cuenta es gratis; el segundo en adelante nace bloqueado hasta activarlo ($99 MXN/mes por dominio).",
    { domain: z.string().describe("Dominio, p. ej. tudominio.com") }, (a) => sdk.domains.create(a.domain));
  tool("verify_domain", "Vuelve a comprobar en SES si el DNS del dominio ya está verificado (identidad y DKIM).", { domainId }, (a) => sdk.domains.verify(a.domainId));
  tool("domain_health", "Diagnóstico del dominio: MX, DKIM, SPF y recursos de recepción.", { domainId }, (a) => sdk.domains.health(a.domainId));
  tool("delete_domain", "Borra el dominio con todas sus máscaras, reglas y buzones. Irreversible.", { domainId }, (a) => sdk.domains.delete(a.domainId));

  // --- Máscaras ---
  tool("list_aliases", "Lista las máscaras (alias) de un dominio.", { domainId }, (a) => sdk.aliases.list(a.domainId));
  tool("create_alias",
    "Crea una máscara. `destinations` son los correos a los que reenvía; '*' como alias es catch-all. Con `mailbox: true` además guarda el correo en un buzón IMAP (sólo dominio activado) y devuelve sus credenciales UNA sola vez. El dominio gratis permite 5 máscaras.",
    { domainId, alias: aliasName, destinations: z.array(z.string()).optional().describe("Correos destino; puede omitirse si mailbox es true"), mailbox: z.boolean().optional() },
    (a) => sdk.aliases.create(a.domainId, { alias: a.alias, destinations: a.destinations, mailbox: a.mailbox }));
  tool("update_alias", "Activa/desactiva una máscara o cambia sus destinos.", { domainId, alias: aliasName, enabled: z.boolean().optional(), destinations: z.array(z.string()).optional() },
    (a) => sdk.aliases.update(a.domainId, a.alias, { enabled: a.enabled, destinations: a.destinations }));
  tool("delete_alias", "Borra una máscara (y su buzón, si tiene).", { domainId, alias: aliasName }, (a) => sdk.aliases.delete(a.domainId, a.alias));
  tool("create_mailbox", "Crea un buzón IMAP para una máscara existente (dominio activado). Devuelve email, contraseña (una sola vez) y datos IMAP/SMTP.", { domainId, alias: aliasName }, (a) => sdk.aliases.createMailbox(a.domainId, a.alias));
  tool("delete_mailbox", "Borra el buzón IMAP de una máscara Y TODO SU CORREO. La máscara debe conservar al menos un destino.", { domainId, alias: aliasName }, (a) => sdk.aliases.deleteMailbox(a.domainId, a.alias));
  tool("reset_mailbox_password", "Genera una contraseña nueva para el buzón IMAP de una máscara y la devuelve UNA sola vez; no se guarda en ningún lado. Úsala cuando el cliente de correo la pide en bucle (p. ej. tras restaurar el servidor).", { domainId, alias: aliasName }, (a) => sdk.aliases.resetMailboxPassword(a.domainId, a.alias));

  // --- DNS ---
  //
  // Las descripciones están escritas para que las lea un LLM: dicen qué hace la herramienta,
  // qué NO puede hacer y qué hacer después. La trampa de `set_dns_record` es que reemplaza
  // el conjunto, así que se dice explícitamente cómo se añade un valor sin borrar los otros.

  tool("list_dns_records",
    "Lista los registros DNS del dominio y el estado de su zona. Los que traen `managed: true` los pone MailMask para que el correo funcione y no se pueden borrar. Llámala SIEMPRE antes de crear o cambiar un registro: te dice si ese nombre ya está ocupado y con qué valores.",
    { domainId }, (a) => sdk.dns.list(a.domainId));

  tool("create_dns_zone",
    "Crea la zona DNS de MailMask para un dominio registrado fuera. Copia los registros que encuentre de tu proveedor actual y devuelve los nameservers que el dueño tiene que poner en su registrador; hasta que los cambie, nada de lo que edites tiene efecto. Enseña la lista `imported` al usuario antes de que los cambie: lo que no aparezca ahí dejará de funcionar.",
    { domainId }, (a) => sdk.dns.createZone(a.domainId));

  tool("dns_delegation_status",
    "Comprueba si el dominio ya apunta a los nameservers de MailMask. Devuelve los que se observan hoy y los que se esperan. Un cambio de nameservers tarda de 1 a 48 horas.",
    { domainId }, (a) => sdk.dns.delegation(a.domainId));

  tool("set_dns_record",
    "Crea o reemplaza un registro DNS. Es idempotente: `values` sustituye por completo lo que hubiera en ese nombre y tipo, así que para AÑADIR un valor primero léelo con list_dns_records e incluye también los que ya estaban. `name` puede ser '@' para la raíz o un subdominio ('www'). En MX la prioridad va dentro del valor: '10 mail.ejemplo.com'. TTL por defecto 300.",
    {
      domainId,
      name: z.string().describe("'@' para la raíz, o el subdominio ('www')"),
      type: z.enum(["A", "AAAA", "CNAME", "TXT", "MX", "NS", "CAA", "SRV"]),
      values: z.array(z.string()).describe("La lista COMPLETA de valores que debe quedar"),
      ttl: z.number().optional().describe("Segundos, entre 60 y 172800. Por defecto 300."),
    },
    (a) => sdk.dns.upsert(a.domainId, { name: a.name, type: a.type, values: a.values, ttl: a.ttl }));

  tool("delete_dns_record",
    "Borra un registro DNS completo, con todos sus valores. Los registros de correo de MailMask están protegidos y devuelven un error: no insistas, la única forma de quitarlos es eliminar el dominio de MailMask.",
    { domainId, name: z.string(), type: z.enum(["A", "AAAA", "CNAME", "TXT", "MX", "NS", "CAA", "SRV"]) },
    (a) => sdk.dns.delete(a.domainId, a.name, a.type));

  tool("import_dns_records",
    "Consulta el DNS público actual del dominio y devuelve lo que encuentra, sin escribir nada. Sirve para revisar qué habría que copiar antes de delegar. No garantiza ser exhaustivo.",
    { domainId }, (a) => sdk.dns.import(a.domainId));

  tool("point_domain_to",
    "Apunta el dominio (o un subdominio) a un servicio de hosting sin tener que saber qué registros hacen falta. Para 'vercel' el `target` es el dominio que da Vercel ('mi-proyecto.vercel.app'); para 'github-pages' es 'usuario.github.io'; para 'dmarc' es el correo donde recibir los informes. Sin `subdomain` apunta la raíz y www.",
    {
      domainId,
      provider: z.enum(["vercel", "netlify", "github-pages", "cloudflare-pages", "render", "fly", "redirect-a-www", "dmarc"]),
      target: z.string().optional().describe("El destino que te dio el servicio"),
      subdomain: z.string().optional().describe("Para apuntar sólo un subdominio, p. ej. 'app'"),
    },
    (a) => sdk.dns.preset(a.domainId, a.provider, a.target, a.subdomain));

  // --- Reglas ---
  const ruleShape = {
    field: z.enum(["to", "from", "subject"]),
    match: z.enum(["contains", "equals", "regex"]).describe("Un regex peligroso (ReDoS) se rechaza con 400"),
    value: z.string(),
    action: z.enum(["forward", "webhook", "discard"]),
    target: z.string().optional().describe("Correo destino para forward o URL para webhook"),
    priority: z.number().int().optional(),
    enabled: z.boolean().optional(),
  };
  tool("list_rules", "Lista las reglas de enrutamiento del dominio.", { domainId }, (a) => sdk.rules.list(a.domainId));
  tool("create_rule", "Crea una regla de enrutamiento (dominio activado).", { domainId, ...ruleShape }, ({ domainId: d, ...r }) => sdk.rules.create(d, r));
  tool("update_rule", "Modifica una regla.", { domainId, ruleId: z.string(), ...Object.fromEntries(Object.entries(ruleShape).map(([k, v]) => [k, v.optional()])) as { [K in keyof typeof ruleShape]: z.ZodOptional<(typeof ruleShape)[K]> } },
    ({ domainId: d, ruleId, ...r }) => sdk.rules.update(d, ruleId, r));
  tool("delete_rule", "Borra una regla.", { domainId, ruleId: z.string() }, (a) => sdk.rules.delete(a.domainId, a.ruleId));

  // --- Webhooks ---
  const events = z.array(z.enum(["email.received", "email.sent", "email.delivered", "email.bounced", "email.complained"]));
  tool("list_webhooks", "Lista los webhooks del dominio.", { domainId }, (a) => sdk.webhooks.list(a.domainId));
  tool("create_webhook", "Crea un webhook (dominio activado, URL https pública, máx. 10). El secreto para verificar la firma se devuelve una sola vez.", { domainId, url: z.string().url(), events },
    (a) => sdk.webhooks.create(a.domainId, { url: a.url, events: a.events }));
  tool("update_webhook", "Cambia URL, eventos o estado de un webhook.", { domainId, webhookId: z.string(), url: z.string().url().optional(), events: events.optional(), enabled: z.boolean().optional() },
    ({ domainId: d, webhookId, ...r }) => sdk.webhooks.update(d, webhookId, r));
  tool("delete_webhook", "Borra un webhook.", { domainId, webhookId: z.string() }, (a) => sdk.webhooks.delete(a.domainId, a.webhookId));
  tool("test_webhook", "Encola un evento `ping` de prueba; se entrega en el siguiente minuto.", { domainId, webhookId: z.string() }, (a) => sdk.webhooks.test(a.domainId, a.webhookId));
  tool("webhook_deliveries", "Últimas entregas de un webhook con código HTTP, intentos y error.", { domainId, webhookId: z.string() }, (a) => sdk.webhooks.deliveries(a.domainId, a.webhookId));

  // --- Envío ---
  tool("send_email",
    "⚠️ Confirma con el usuario antes de enviar. Envía un correo suelto desde el dominio (dominio activado: 50 al día) SIN dejar hilo en la Bandeja; para conversar con alguien y ver su respuesta usa inbox_send. `from` es la parte local de una máscara activa; sin él sale de noreply@. Cuerpo: `markdown` (lleva la firma del dominio), `html` o `body` (texto plano).",
    {
      domainId, to: z.string(), subject: z.string(),
      markdown: z.string().optional(), html: z.string().optional(), body: z.string().optional(),
      from: z.string().optional(), fromName: z.string().optional(), replyTo: z.string().optional(),
      cc: z.array(z.string()).max(20).optional(), bcc: z.array(z.string()).max(20).optional(),
      inReplyTo: z.string().optional(), references: z.string().optional(),
      attachments: attachmentsShape,
      idempotencyKey: z.string().max(128).optional().describe("Reintentar con la misma clave no reenvía ni gasta cuota (24 h)"),
    },
    ({ domainId: d, idempotencyKey, ...input }) => sdk.send.send(d, input, { idempotencyKey }));
  tool("bulk_send", "Envío masivo asíncrono a varios destinatarios; devuelve un jobId para bulk_status.", { domainId, recipients: z.array(z.string()), subject: z.string(), html: z.string(), from: z.string().optional() },
    ({ domainId: d, ...input }) => sdk.send.bulkSend(d, input));
  tool("bulk_status", "Estado de un envío masivo.", { domainId, jobId: z.string() }, (a) => sdk.send.bulkStatus(a.domainId, a.jobId));

  // --- Operación ---
  tool("list_logs", "Registro de reenvíos y envíos del dominio.", { domainId, limit: z.number().int().min(1).max(100).optional() }, (a) => sdk.logs.list(a.domainId, { limit: a.limit }));
  tool("list_suppressions", "Direcciones a las que el dominio ya no envía (rebote permanente, queja o manual).", { domainId }, (a) => sdk.suppressions.list(a.domainId));
  tool("add_suppression", "Deja de enviar a una dirección.", { domainId, email: z.string() }, (a) => sdk.suppressions.add(a.domainId, a.email));
  tool("remove_suppression", "Vuelve a permitir envíos a una dirección.", { domainId, email: z.string() }, (a) => sdk.suppressions.remove(a.domainId, a.email));
  tool("list_smtp_credentials", "Credenciales SMTP relay del dominio.", { domainId }, (a) => sdk.smtp.list(a.domainId));
  tool("create_smtp_credential", "Crea una credencial SMTP relay (dominio activado). La contraseña se devuelve una sola vez.", { domainId, label: z.string() }, (a) => sdk.smtp.create(a.domainId, a.label));
  tool("revoke_smtp_credential", "Revoca una credencial SMTP.", { domainId, credentialId: z.string() }, (a) => sdk.smtp.revoke(a.domainId, a.credentialId));

  // --- Conectar, activar y cobrar ---
  //
  // Lo que antes necesitaba a una persona por WhatsApp: dictar los registros, explicar el
  // "bloqueado" y mandar la liga de pago. Un pago SIEMPRE lo hace el usuario en MercadoPago.

  tool("domain_dns_setup",
    "Los registros exactos que el usuario debe pegar en el panel de su registrador (MX, TXT _amazonses, 3 CNAME de DKIM, SPF recomendado, DMARC opcional), con `name` relativo ('@', '_amazonses') y `fqdn`. Con live (por omisión) dice cuáles ya se ven en el DNS público (`ok`), sugiere el SPF fusionado si ya tenía uno y, en `registrarHint`, en qué panel y menú se pegan (Hostinger, GoDaddy, Cloudflare, Namecheap, Route 53).",
    { domainId, live: z.boolean().optional().describe("Comparar con el DNS público (por omisión true)") },
    (a) => sdk.domains.dnsSetup(a.domainId, { live: a.live ?? true }));

  tool("activation_link",
    "Liga de pago de MercadoPago para activar un dominio ($99 MXN/mes): quita el bloqueo y da máscaras ilimitadas, equipo, envíos y buzones. Con `kind` compra un bloque extra para un dominio ya activado. El USUARIO abre la liga y paga; no digas que quedó activado hasta confirmarlo con list_addons o domain_health.",
    {
      domainId,
      kind: z.enum(["domain", "storage50", "sends100"]).optional().describe("domain = activar (por omisión); storage50 = +50 GB de buzón; sends100 = +100 envíos/día"),
      payerEmail: z.string().optional().describe("Correo de la cuenta de MercadoPago del pagador, si no es el de MailMask"),
      period: z.enum(["monthly", "annual"]).optional().describe("Sólo para activar: monthly ($99/mes, por omisión) o annual ($999 al año)"),
    },
    async (a) => {
      const r = await sdk.billing.checkout(a.domainId, a.kind ?? "domain", { payerEmail: a.payerEmail, period: a.period });
      return { paymentUrl: r.init_point, addonId: r.addonId, paid: false, note: "Liga de pago para el usuario. No está pagado hasta que MercadoPago lo confirme." };
    });

  tool("billing_status", "Suscripción de la cuenta (plan legado, si existe). Lo que se cobra hoy es por dominio: para eso usa list_addons.", {}, () => sdk.billing.status());
  tool("list_addons", "Catálogo de add-ons con precio (centavos MXN) y los del usuario con su estado y dominio. Un add-on `domain` activo en un domainId = ese dominio está activado.", {}, () => sdk.billing.addons());

  // --- Comprar y transferir dominios ---

  tool("search_domains", "Busca si un dominio está disponible para comprar y su precio anual (centavos MXN). Incluye la extensión: 'miempresa.com'.", { domain: z.string() }, (a) => sdk.registrations.search(a.domain));
  tool("domain_prices", "Extensiones que se pueden comprar con precio de alta, renovación y transferencia (centavos MXN por año).", {}, () => sdk.registrations.tlds());
  tool("register_domain",
    "Compra un dominio: crea el registro pendiente y devuelve la liga de pago de MercadoPago (un año). El registro y el DNS de correo se configuran solos cuando el USUARIO paga. Confírmalo con search_domains antes.",
    { domain: z.string() },
    async (a) => {
      const r = await sdk.registrations.register(a.domain);
      return { paymentUrl: r.initPoint, registrationId: r.registrationId, paid: false, note: "El usuario abre la liga y paga; sigue el avance con list_registrations." };
    });
  tool("list_registrations", "Dominios comprados o transferidos por MailMask con su estado (`statusText`), vencimiento y renovación.", {},
    async () => (await sdk.registrations.list()).map((r) => ({ ...r, statusText: registrationStatusText(r) })));

  tool("transfer_check",
    "Antes de transferir un dominio a MailMask: requisitos (antigüedad, candado, privacidad), precio (incluye 1 año) y los registros DNS que tiene hoy. No cobra ni crea nada.",
    { domain: z.string() }, (a) => sdk.transfers.check(a.domain));
  tool("transfer_start",
    "Prepara la transferencia de un dominio a MailMask y devuelve `formUrl`: la liga al formulario seguro de la app donde el usuario pega el código EPP, sus datos WHOIS y paga. El código EPP NUNCA pasa por el chat: no lo pidas ni lo aceptes.",
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
  tool("transfer_status", "Estado de las transferencias de dominio del usuario (o de una), en palabras (`statusText`).",
    { domain: z.string().optional() },
    async (a) => (await sdk.registrations.list())
      .filter((r) => r.kind === "transfer" && (!a.domain || r.domainName === a.domain.toLowerCase().trim()))
      .map((r) => ({
        registrationId: r.id, domain: r.domainName, status: r.status, statusText: registrationStatusText(r),
        dnsImportStatus: r.dnsImportStatus, eppHint: r.transferAuthCodeHint, createdAt: r.createdAt, lastError: r.lastError,
      })));
  const registrationId = z.string().describe("ID de la registración (de list_registrations o transfer_status)");
  tool("transfer_dns", "Inventario de DNS que el dominio va a usar al terminar la transferencia. Revísalo CON el usuario: lo que no esté aquí dejará de funcionar.", { registrationId }, (a) => sdk.transfers.dns(a.registrationId));
  tool("update_transfer_dns",
    "Reemplaza el inventario de DNS de una transferencia por la lista COMPLETA que mandes (lee transfer_dns primero). Queda otra vez pendiente de aprobar.",
    { registrationId, records: z.array(z.object({ name: z.string(), type: z.string(), ttl: z.number().optional(), values: z.array(z.string()) })) },
    (a) => sdk.transfers.setDns(a.registrationId, a.records));
  tool("approve_transfer_dns", "Aprueba el inventario de DNS; nada se mueve hasta esto. Sólo con el visto bueno explícito del usuario.", { registrationId }, (a) => sdk.transfers.approveDns(a.registrationId));
  tool("resend_transfer_email", "Pide al registrador que reenvíe el correo de aprobación de la transferencia.", { registrationId }, (a) => sdk.transfers.resendEmail(a.registrationId));

  tool("transfer_out",
    "Inicia la salida de un dominio comprado en MailMask hacia otro registrador. Manda un correo al dueño para confirmar; el código EPP llega ahí, nunca en esta respuesta. Confirma con el usuario antes.",
    { registrationId }, (a) => sdk.registrations.transferOut(a.registrationId));
  tool("renewal_status", "Vencimiento y renovación anual de los dominios comprados en MailMask.",
    { registrationId: registrationId.optional() },
    async (a) => (await sdk.registrations.list())
      .filter((r) => !a.registrationId || r.id === a.registrationId)
      .map((r) => ({ registrationId: r.id, domain: r.domainName, status: r.status, expiresAt: r.expiresAt, renewalStatus: r.renewalStatus, renewalPriceCents: r.renewalPriceCents, nextChargeAt: r.nextChargeAt })));
  tool("renewal_link", "Liga de MercadoPago para la renovación anual automática de un dominio registrado. El usuario la abre y autoriza el cobro.",
    { registrationId, payerEmail: z.string().optional() },
    async (a) => {
      const r = await sdk.registrations.renewal(a.registrationId, { payerEmail: a.payerEmail });
      return { paymentUrl: r.init_point, nextChargeAt: r.nextChargeAt, paid: false };
    });

  // --- Equipo ---
  tool("list_members", "Personas con acceso a la Bandeja del dominio y las invitaciones pendientes.", { domainId }, (a) => sdk.members.list(a.domainId));
  tool("invite_member", "Invita a una persona a la Bandeja del dominio (dominio activado). Le llega un correo con la liga para aceptar. role: agent (responde) o admin.",
    { domainId, email: z.string(), name: z.string(), role: z.enum(["agent", "admin"]).optional() },
    (a) => sdk.members.invite(a.domainId, { email: a.email, name: a.name, role: a.role }));
  tool("remove_member", "Quita a una persona del dominio (memberId de list_members). Confirma con el usuario antes.", { domainId, memberId: z.string() }, (a) => sdk.members.remove(a.domainId, a.memberId));
  tool("cancel_invite", "Cancela una invitación pendiente (token de list_members).", { domainId, token: z.string() }, (a) => sdk.members.cancelInvite(a.domainId, a.token));

  // --- Bandeja ---
  tool("get_signature", "Firma (markdown) que se añade a lo que se envía desde el dominio.", { domainId }, (a) => sdk.signature.get(a.domainId));
  tool("set_signature", "Cambia la firma del dominio (markdown, máx. 2000 caracteres; vacía la borra). Sólo se aplica a correos escritos en markdown.",
    { domainId, signature: z.string() }, (a) => sdk.signature.set(a.domainId, a.signature));
  tool("list_canned_replies", "Respuestas guardadas de la Bandeja del dominio.", { domainId }, (a) => sdk.canned.list(a.domainId));
  tool("create_canned_reply", "Guarda una respuesta reutilizable (título y cuerpo en markdown; máx. 50 por dominio).",
    { domainId, title: z.string(), body: z.string() }, (a) => sdk.canned.create(a.domainId, { title: a.title, body: a.body }));
  tool("delete_canned_reply", "Borra una respuesta guardada.", { domainId, cannedId: z.string() }, (a) => sdk.canned.delete(a.domainId, a.cannedId));

  // --- Bandeja: el agente atiende el correo de su máscara ---
  //
  // Son las rutas de la app tal cual (vía SDK): mismos permisos por dominio y rol
  // (`requireBandeja`), mismo recorte de 7 días del dominio gratis y mismos topes de envío.
  // Lo único que se hace aquí es darle al modelo texto en vez de HTML.
  const conversationId = z.string().describe("ID de la conversación (de inbox_list)");
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
    "Lista las conversaciones de la Bandeja de un dominio, de la más reciente a la más vieja. Filtra por `alias` (la máscara: 'soporte' o 'soporte@dominio.com'), `status` (open, snoozed, closed, unread = no leídas por ti, deleted = papelera) o `assignedTo`. Con `q` busca en asunto, remitente y cuerpo (tope 50, sin paginar). Para la siguiente página pasa `cursor` = nextCursor. En el dominio gratis sólo se ven los últimos 7 días.",
    {
      domainId,
      alias: z.string().optional().describe("Máscara del hilo: parte local o dirección completa"),
      status: z.enum(["open", "snoozed", "closed", "unread", "deleted"]).optional(),
      assignedTo: z.string().optional().describe("Correo de la persona asignada"),
      q: z.string().optional().describe("Texto a buscar"),
      limit: z.number().int().min(1).max(100).optional().describe("Por omisión 50"),
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
    });

  tool("inbox_read",
    "Abre una conversación: sus mensajes en texto plano (los 30 más recientes; para los anteriores pasa `before` = nextBefore), notas internas del equipo y adjuntos listados por mensaje. La marca como leída para ti. `direction` inbound = lo que escribió el contacto, outbound = lo que salió del dominio. Para el contenido de un adjunto usa inbox_attachment.",
    { domainId, conversationId, before: z.string().optional().describe("nextBefore de una lectura anterior") },
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
    });

  tool("inbox_attachment",
    "Lee un adjunto de un mensaje recibido (messageId e index de inbox_read). Texto, CSV, JSON y similares vuelven como texto; imágenes de hasta 2 MB como imagen; lo demás (PDF, Office, zip) sólo con nombre y tamaño.",
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
    "⚠️ Confirma con el usuario el texto antes de enviar. Responde en el hilo, desde la máscara del hilo y al contacto, enhebrado (Re: asunto). Escribe en `markdown`: lleva la firma del dominio y cita el último mensaje recibido (quote: false para no citar). No gasta la cuota de envíos (tope de 200 respuestas por hora por dominio). Pide el DNS del dominio verificado.",
    {
      domainId, conversationId,
      markdown: z.string().optional().describe("Cuerpo en markdown (recomendado)"),
      body: z.string().optional().describe("Texto plano, sin firma"),
      html: z.string().optional(),
      cc: z.array(z.string()).max(20).optional(), bcc: z.array(z.string()).max(20).optional(),
      quote: z.boolean().optional(),
      attachments: attachmentsShape,
    },
    ({ domainId: d, conversationId: c, ...input }) => conPista(sdk.inbox.reply(d, c, input)));

  tool("inbox_send",
    "⚠️ Confirma con el usuario destinatario, asunto y texto antes de enviar. Escribe un correo nuevo desde una máscara activa del dominio y abre un hilo en la Bandeja: la respuesta del contacto llega a esa misma conversación (síguela con inbox_list/inbox_read). Requiere dominio activado ($99 MXN/mes, si no: activation_link) y verificado; gasta 1 de los envíos del día.",
    {
      domainId,
      fromAlias: z.string().describe("Parte local de la máscara que envía: 'ventas'"),
      to: z.string(), subject: z.string(),
      markdown: z.string().optional().describe("Cuerpo en markdown (recomendado: lleva la firma)"),
      body: z.string().optional(), html: z.string().optional(),
      cc: z.array(z.string()).max(20).optional(), bcc: z.array(z.string()).max(20).optional(),
      attachments: attachmentsShape,
    },
    ({ domainId: d, ...input }) => conPista(sdk.inbox.compose(d, input)));

  tool("inbox_mark",
    "Cambia el estado de una conversación: `read` true la marca leída para ti; `status` closed = archivarla/resolverla, open = reabrirla, snoozed = posponerla hasta `snoozedUntil` (ISO futura, máx. 90 días; un correo nuevo la despierta antes); `priority` normal o urgent; `tags` reemplaza las etiquetas.",
    {
      domainId, conversationId,
      read: z.boolean().optional(),
      status: z.enum(["open", "snoozed", "closed"]).optional(),
      snoozedUntil: z.string().optional(),
      priority: z.enum(["normal", "urgent"]).optional(),
      tags: z.array(z.string()).optional().describe("La lista COMPLETA de etiquetas"),
    },
    async ({ domainId: d, conversationId: c, read, ...cambios }) => {
      const hayCambios = Object.values(cambios).some((v) => v !== undefined);
      if (!hayCambios && !read) throw new Error("Nada que cambiar: pasa read, status, priority o tags.");
      const conv = hayCambios ? await sdk.inbox.update(d, c, cambios) : undefined;
      const leida = read ? await sdk.inbox.markRead(d, c) : undefined;
      return { ok: true, ...(conv ? { status: conv.status, priority: conv.priority, tags: conv.tags, snoozedUntil: conv.snoozedUntil ?? null } : {}), ...(leida ? { unreadCount: leida.unreadCount } : {}) };
    });

  tool("inbox_assign", "Asigna una conversación a una persona del equipo (correo de list_members) o, sin `assignedTo`, la deja sin asignar. Pide permiso de dueño o admin.",
    { domainId, conversationId, assignedTo: z.string().optional() }, (a) => sdk.inbox.assign(a.domainId, a.conversationId, a.assignedTo));
  tool("inbox_note", "Agrega una nota interna a la conversación: la ve el equipo en la Bandeja, NUNCA el contacto.",
    { domainId, conversationId, body: z.string() }, (a) => sdk.inbox.addNote(a.domainId, a.conversationId, a.body));
  tool("inbox_delete", "Manda conversaciones a la papelera (se pueden recuperar con inbox_restore; se vacía a los 15 días). Máx. 200 por llamada; sólo dueño o admin. Confirma con el usuario antes.",
    { domainId, conversationIds: z.array(z.string()).min(1).max(200) }, (a) => sdk.inbox.delete(a.domainId, a.conversationIds));
  tool("inbox_restore", "Saca una conversación de la papelera (las borradas salen en inbox_list con status deleted).",
    { domainId, conversationId }, (a) => sdk.inbox.restore(a.domainId, a.conversationId));
  tool("inbox_metrics", "Métricas de la Bandeja: volumen, tiempos de primera respuesta, reparto por persona y por día.",
    { domainId, days: z.number().int().min(1).max(365).optional().describe("Por omisión 30") }, (a) => sdk.inbox.metrics(a.domainId, { days: a.days }));

  tool("upload_attachment",
    "Sube un archivo para adjuntarlo en inbox_send, inbox_reply o send_email; devuelve el objeto que va en `attachments`. Pasa `url` (un archivo que el usuario adjuntó en el chat del asistente de MailMask) o `contentBase64` con `filename`. Máx. 5 MB; ejecutables bloqueados. Vale hasta que se envía.",
    {
      domainId,
      url: z.string().optional().describe("URL del adjunto del chat (/api/asistente/files/...)"),
      contentBase64: z.string().optional(),
      filename: z.string().optional(),
      contentType: z.string().optional().describe("Por omisión application/octet-stream"),
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
    "Pone el logo que acompaña la firma de los correos del dominio (PNG, JPG o WebP; máx. 500 KB). Pasa `url` de una imagen que el usuario adjuntó en el chat del asistente, o `contentBase64` con `contentType`.",
    { domainId, url: z.string().optional(), contentBase64: z.string().optional(), contentType: z.enum(["image/png", "image/jpeg", "image/webp"]).optional() },
    async (a) => {
      if (a.url) return sdk.domains.setLogoFromUrl(a.domainId, a.url);
      if (!a.contentBase64 || !a.contentType) throw new Error("Pasa url, o contentBase64 con contentType.");
      return sdk.domains.setLogo(a.domainId, new Blob([Buffer.from(a.contentBase64, "base64")], { type: a.contentType }), "logo");
    });
  tool("delete_domain_logo", "Quita el logo de la firma del dominio.", { domainId }, (a) => sdk.domains.removeLogo(a.domainId));

  // --- Cuenta: cobros, cancelaciones y referidos ---
  tool("list_orders", "Historial de cobros, cortesías y cancelaciones de la cuenta (folio, concepto, monto en centavos, periodo). Para factura (CFDI) la respuesta dice a dónde escribir.",
    { limit: z.number().int().min(1).max(200).optional(), before: z.string().optional().describe("nextCursor de la página anterior") },
    (a) => sdk.billing.orders({ limit: a.limit, before: a.before }));
  tool("cancel_addon",
    "Cancela la suscripción de un add-on (addonId de list_addons; p. ej. la activación de un dominio). Deja de cobrarse y lo incluido dura hasta el fin del periodo pagado. Las cortesías no se cancelan. Confirma con el usuario antes.",
    { addonId: z.string() }, (a) => sdk.billing.cancelAddon(a.addonId));
  tool("cancel_renewal",
    "Cancela la renovación anual automática de un dominio comprado en MailMask (registrationId de list_registrations). El dominio sigue vigente hasta su vencimiento; después puede perderse. Confirma con el usuario antes; si quiere llevárselo, es transfer_out.",
    { registrationId }, (a) => sdk.registrations.cancelRenewal(a.registrationId));
  tool("referral_status", "Programa de referidos de la cuenta: liga propia (slug), nombre que ven los invitados, referidos y créditos disponibles.", {}, () => sdk.referrals.get());
  tool("set_referral_slug", "Cambia la liga de referidos (3-30 caracteres: minúsculas, números y guiones). 409 si ya está tomada.",
    { slug: z.string() }, (a) => sdk.referrals.setSlug(a.slug));
  tool("set_referral_name", "Nombre que ven las personas invitadas («Brenda te invitó»), 2-40 caracteres.",
    { name: z.string() }, (a) => sdk.referrals.setName(a.name));
  tool("export_link", "Liga para descargar un JSON con todos los dominios, máscaras, reglas y últimos registros de la cuenta. Se abre en el navegador con la sesión de MailMask iniciada (5 al día).",
    {}, async () => ({ url: appUrl("/api/export"), note: "Abrir en el navegador con sesión iniciada en MailMask." }));

  // --- Perfil de la cuenta ---
  //
  // Es el perfil del usuario de MailMask (cabecera de /app, Bandeja, dock), no el de una
  // máscara ni lo que ve quien recibe el correo.
  tool("get_profile", "Perfil de la cuenta de MailMask del usuario: correo, nombre visible y foto (avatarUrl).", {}, () => sdk.account.getProfile());
  tool("update_profile", "Cambia el nombre visible de la cuenta del usuario (máx. 60 caracteres; vacío lo borra). Es el nombre con el que lo ve su equipo en la Bandeja; no cambia el remitente de los correos.",
    { displayName: z.string() }, (a) => sdk.account.updateProfile({ displayName: a.displayName }));
  tool("set_profile_photo", "Pone la foto de perfil de la cuenta del usuario. SÓLO sirve con la URL de una imagen que el usuario adjuntó en este chat (PNG, JPG o WebP, máx. 2 MB); cualquier otra URL se rechaza. Si no ha adjuntado una, pídesela.",
    { url: z.string().describe("URL del adjunto del chat (/api/asistente/files/...)") }, (a) => sdk.account.setAvatarFromUrl(a.url));
  tool("delete_profile_photo", "Quita la foto de perfil de la cuenta del usuario.", {}, () => sdk.account.removeAvatar());

  // --- Buzones: ligas para el navegador del usuario ---
  //
  // Son archivos (un plist, un .mbox de GB): no tiene sentido pasarlos por el modelo. La liga
  // funciona en el navegador donde el usuario tiene la sesión de MailMask abierta.
  const requireMailbox = async (d: string, alias: string) => {
    const fila = (await sdk.aliases.list(d)).find((x) => x.alias === alias.toLowerCase());
    if (!fila?.mailboxEnabled) throw new Error(`La máscara ${alias} no tiene buzón IMAP. Créalo con create_mailbox.`);
  };
  tool("apple_profile_link",
    "Liga al perfil que configura el buzón IMAP de una máscara en Apple Mail (iPhone, iPad, Mac). El usuario la abre en Safari del dispositivo con su sesión de MailMask iniciada y lo instala en Ajustes; le pedirá la contraseña del buzón.",
    { domainId, alias: aliasName },
    async (a) => {
      await requireMailbox(a.domainId, a.alias);
      return { url: appUrl(`/api/domains/${a.domainId}/apple-profile?alias=${encodeURIComponent(a.alias.toLowerCase())}`), note: "Abrir en Safari del dispositivo, con sesión iniciada en MailMask." };
    });
  tool("mailbox_export_link",
    "Liga para descargar todo el correo del buzón de una máscara en formato .mbox (Thunderbird, Apple Mail). Se abre en el navegador con la sesión de MailMask iniciada; sólo dueño o admin.",
    { domainId, alias: aliasName },
    async (a) => {
      await requireMailbox(a.domainId, a.alias);
      return { url: appUrl(`/api/domains/${a.domainId}/alias/${encodeURIComponent(a.alias.toLowerCase())}/mailbox/export`), note: "Abrir en el navegador con sesión iniciada en MailMask." };
    });

  // Catálogo por búsqueda: para clientes que prefieren cargar pocas herramientas.
  tool("search_tools", "Busca herramientas de MailMask por palabra clave y devuelve nombre y descripción.", { query: z.string() }, async (a) => {
    // Sin acentos de los dos lados: "renovacion" tiene que encontrar "renovación".
    const plain = (x: string) => x.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
    const q = plain(a.query).split(/\s+/).filter(Boolean);
    return catalogo.filter((t) => {
      const text = plain(`${t.name} ${t.description} ${KEYWORDS[t.name] ?? ""}`);
      return q.some((w) => text.includes(w));
    });
  });

  return server;
}

/** Atiende una petición HTTP de `/mcp` ya autenticada. Stateless: un servidor por petición. */
export async function atenderMcp(request: Request, o: { apiKey: string; fetchLocal: typeof fetch }): Promise<Response> {
  const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  const server = crearServidorMcp(o);
  await server.connect(transport);
  return transport.handleRequest(request);
}
