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
Borrar dominio, máscara, buzón o registro DNS, sacar a un miembro o transferir fuera son irreversibles: confírmalo con el usuario antes. Algunas responden que necesitan confirmación: el usuario la aprueba en la app; no reintentes ni busques otra vía.

## DNS administrado por MailMask
Con zona propia (create_dns_zone y cambiar los nameservers en el registrador) puedes editar registros: list_dns_records antes de escribir; set_dns_record reemplaza el conjunto completo; point_domain_to para Vercel, Netlify y similares. Los registros de correo están protegidos.

## Otros
- Equipo: list_members, invite_member, remove_member.
- Bandeja: get_signature y set_signature (markdown), respuestas guardadas (list/create/delete_canned_reply).
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
};

const domainId = z.string().describe("ID del dominio (de list_domains)");
const aliasName = z.string().describe("Parte local de la máscara, sin el dominio: 'hola' para hola@tudominio.com");

export function crearServidorMcp(o: { apiKey: string; fetchLocal: typeof fetch }): McpServer {
  const sdk = new MailMask({ apiKey: o.apiKey, baseUrl: "http://mcp.local", fetch: o.fetchLocal });
  const server = new McpServer({ name: "mailmask", version: MCP_VERSION }, { instructions: MCP_INSTRUCTIONS });
  const catalogo: { name: string; description: string }[] = [];

  const tool = <S extends z.ZodRawShape>(name: string, description: string, shape: S, run: (args: z.infer<z.ZodObject<S>>) => Promise<unknown>) => {
    catalogo.push({ name, description });
    // El genérico de registerTool no infiere bien con un shape genérico; el tipado real
    // de `args` lo garantiza la firma de `run`.
    const cb = async (args: z.infer<z.ZodObject<S>>) => { try { return ok(await run(args)); } catch (e) { return fallo(e); } };
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
    "Envía un correo nuevo desde el dominio (dominio activado: 50 al día). `from` es la parte local de una máscara activa; sin él sale de noreply@. Cuerpo: `markdown` (lleva la firma del dominio), `html` o `body` (texto plano).",
    {
      domainId, to: z.string(), subject: z.string(),
      markdown: z.string().optional(), html: z.string().optional(), body: z.string().optional(),
      from: z.string().optional(), fromName: z.string().optional(), replyTo: z.string().optional(),
      cc: z.array(z.string()).max(20).optional(), bcc: z.array(z.string()).max(20).optional(),
      inReplyTo: z.string().optional(), references: z.string().optional(),
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
    },
    async (a) => {
      const r = await sdk.billing.checkout(a.domainId, a.kind ?? "domain", { payerEmail: a.payerEmail });
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
