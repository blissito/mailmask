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

const domainId = z.string().describe("ID del dominio (de list_domains)");
const aliasName = z.string().describe("Parte local de la máscara, sin el dominio: 'hola' para hola@tudominio.com");

export function crearServidorMcp(o: { apiKey: string; fetchLocal: typeof fetch }): McpServer {
  const sdk = new MailMask({ apiKey: o.apiKey, baseUrl: "http://mcp.local", fetch: o.fetchLocal });
  const server = new McpServer({ name: "mailmask", version: MCP_VERSION });
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

  // Catálogo por búsqueda: para clientes que prefieren cargar pocas herramientas.
  tool("search_tools", "Busca herramientas de MailMask por palabra clave y devuelve nombre y descripción.", { query: z.string() }, async (a) => {
    const q = a.query.toLowerCase().split(/\s+/).filter(Boolean);
    return catalogo.filter((t) => q.some((w) => t.name.includes(w) || t.description.toLowerCase().includes(w)));
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
