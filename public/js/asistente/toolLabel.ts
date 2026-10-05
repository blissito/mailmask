/**
 * Nombre humano de una tool MCP, para la traza del turno.
 *
 * Las tools del MCP de MailMask (`mcp.ts`) siguen casi todas el patrón `verbo_recurso` (`list_events`,
 * `create_booking`…), así que la regla general se traduce por partes en vez de
 * mantener un diccionario que se desactualice cada vez que el paquete agrega
 * una tool. El diccionario existe sólo para las que NO siguen el patrón.
 *
 * ## Dos cosas que hacían que la traza no dijera nada
 *
 * 1. **El nombre llega con prefijo de servidor**: `mcp__mailmask__list_domains`. Sin
 *    quitarlo, `verbo` era siempre `"mcp"`, nada hacía match y todo caía al
 *    prettifier crudo — de ahí "Mcp mailmask run tool".
 * 2. **Codemode enmascara la tool real detrás de `run_tool`.** El nombre de
 *    verdad viaja en argumentos que el SSE no trae, así que es IMPOSIBLE saber
 *    aquí cuál corrió. Lo honesto es decir "una herramienta", no inventar.
 */

/** `mcp__mailmask__list_domains` → `list_domains`. */
export const bareName = (name: string): string => {
  const parts = name.split("__").filter(Boolean)
  return (parts[parts.length - 1] ?? name).trim()
}

/**
 * Etiquetas exactas de las tools del MCP de MailMask (`mcp.ts`) y de las que
 * vienen en camino. Con nombre explícito porque `verbo_recurso` a secas da
 * frases torpes ("Creando dns zone"). Lo que no esté aquí cae a la regla general.
 */
const EXACT: Record<string, string> = {
  // Codemode / descubrimiento.
  run_tool: "Usando una herramienta de MailMask",
  discover_tools: "Buscando la herramienta adecuada",
  search_tools: "Buscando la herramienta adecuada",
  toolsearch: "Buscando una herramienta",
  // Dominios.
  list_domains: "Consultando tus dominios",
  get_domain: "Consultando el dominio",
  create_domain: "Agregando el dominio",
  verify_domain: "Verificando el dominio",
  domain_health: "Revisando la salud del dominio",
  delete_domain: "Eliminando el dominio",
  domain_dns_setup: "Preparando los registros DNS",
  activation_link: "Generando el enlace para activar",
  // Perfil de la cuenta.
  get_profile: "Consultando tu perfil",
  update_profile: "Cambiando el nombre de tu perfil",
  set_profile_photo: "Poniendo tu foto de perfil",
  // Alias y buzones.
  list_aliases: "Consultando las direcciones",
  create_alias: "Creando la dirección",
  update_alias: "Actualizando la dirección",
  delete_alias: "Eliminando la dirección",
  create_mailbox: "Creando el buzón",
  delete_mailbox: "Eliminando el buzón",
  reset_mailbox_password: "Restableciendo la contraseña del buzón",
  apple_profile_link: "Generando el perfil para Apple Mail",
  mailbox_export_link: "Preparando la descarga del buzón",
  // DNS.
  list_dns_records: "Consultando los registros DNS",
  create_dns_zone: "Creando la zona DNS",
  dns_delegation_status: "Revisando los nameservers",
  set_dns_record: "Guardando un registro DNS",
  delete_dns_record: "Borrando un registro DNS",
  import_dns_records: "Importando los registros DNS",
  point_domain_to: "Apuntando el dominio",
  // Reglas y webhooks.
  list_rules: "Consultando las reglas",
  create_rule: "Creando la regla",
  update_rule: "Actualizando la regla",
  delete_rule: "Eliminando la regla",
  list_webhooks: "Consultando los webhooks",
  create_webhook: "Creando el webhook",
  update_webhook: "Actualizando el webhook",
  delete_webhook: "Eliminando el webhook",
  test_webhook: "Probando el webhook",
  webhook_deliveries: "Revisando las entregas del webhook",
  // Envío y registros.
  send_email: "Enviando el correo",
  bulk_send: "Enviando correos en lote",
  bulk_status: "Revisando el envío en lote",
  list_logs: "Consultando el registro de correos",
  list_suppressions: "Consultando la lista de supresión",
  add_suppression: "Agregando a la lista de supresión",
  remove_suppression: "Quitando de la lista de supresión",
  list_smtp_credentials: "Consultando las credenciales SMTP",
  create_smtp_credential: "Creando la credencial SMTP",
  revoke_smtp_credential: "Revocando la credencial SMTP",
  // Cobro y add-ons.
  billing_status: "Revisando tu facturación",
  list_addons: "Consultando los add-ons",
  // Registro, transferencias y renovación de dominios.
  search_domains: "Buscando dominios disponibles",
  domain_prices: "Consultando precios de dominios",
  register_domain: "Registrando el dominio",
  list_registrations: "Consultando tus registros de dominio",
  transfer_check: "Revisando si se puede transferir",
  transfer_start: "Iniciando la transferencia",
  transfer_status: "Revisando la transferencia",
  transfer_dns: "Revisando el DNS de la transferencia",
  approve_transfer_dns: "Aprobando el DNS de la transferencia",
  resend_transfer_email: "Reenviando el correo de la transferencia",
  transfer_out: "Preparando la salida del dominio",
  renewal_status: "Revisando la renovación",
  // Equipo y Bandeja.
  list_members: "Consultando el equipo",
  invite_member: "Invitando a una persona",
  remove_member: "Quitando a una persona",
  get_signature: "Consultando la firma",
  set_signature: "Guardando la firma",
  list_canned_replies: "Consultando las respuestas guardadas",
  create_canned_reply: "Guardando una respuesta",
  delete_canned_reply: "Borrando una respuesta guardada",
  set_domain_logo: "Poniendo el logo de la firma",
  delete_domain_logo: "Quitando el logo de la firma",
  inbox_list: "Revisando la Bandeja",
  inbox_read: "Leyendo la conversación",
  inbox_attachment: "Abriendo un adjunto",
  inbox_reply: "Respondiendo el correo",
  inbox_send: "Enviando un correo nuevo",
  inbox_mark: "Actualizando la conversación",
  inbox_assign: "Asignando la conversación",
  inbox_note: "Agregando una nota interna",
  inbox_delete: "Mandando a la papelera",
  inbox_restore: "Restaurando la conversación",
  inbox_metrics: "Consultando las métricas de la Bandeja",
  upload_attachment: "Subiendo un adjunto",
  // Cuenta.
  delete_profile_photo: "Quitando tu foto de perfil",
  list_orders: "Consultando tus pagos",
  cancel_addon: "Cancelando el add-on",
  cancel_renewal: "Cancelando la renovación",
  referral_status: "Consultando tus referidos",
  set_referral_slug: "Cambiando tu liga de referidos",
  set_referral_name: "Cambiando tu nombre de referidos",
  export_link: "Preparando la exportación",
  // Las herramientas propias del agente dentro de su caja.
  bash: "Trabajando en su caja",
  read: "Leyendo un archivo",
  write: "Escribiendo un archivo",
  edit: "Editando un archivo",
  glob: "Buscando archivos",
  grep: "Buscando en archivos",
}

const RESOURCES: Record<string, string> = {
  domains: "los dominios",
  domain: "el dominio",
  aliases: "las direcciones",
  alias: "la dirección",
  mailbox: "el buzón",
  dns_records: "los registros DNS",
  dns_record: "un registro DNS",
  rules: "las reglas",
  rule: "la regla",
  webhooks: "los webhooks",
  webhook: "el webhook",
  logs: "el registro de correos",
  members: "el equipo",
  member: "la persona",
  addons: "los add-ons",
}

const VERBS: Record<string, string> = {
  list: "Consultando",
  get: "Consultando",
  search: "Buscando",
  find: "Buscando",
  create: "Creando",
  update: "Actualizando",
  insert: "Agregando",
  add: "Agregando",
  remove: "Quitando",
  delete: "Eliminando",
  cancel: "Cancelando",
  send: "Enviando",
  audit: "Revisando",
  verify: "Verificando",
  set: "Guardando",
}

export function toolLabel(name: string): string {
  const clean = bareName(name)
  // Se compara en minúsculas: las tools propias del agente llegan capitalizadas
  // (`Bash`, `Read`, `ToolSearch`) y las del MCP en snake_case.
  /* `gs_` es un prefijo de espacio de nombres de la caja (`gs_web_scrape`,
     `gs_render_png`), igual que `mcp__`. Sin quitarlo, el verbo era "gs", nada
     hacía match y salía "Gs web scrape" — que es el identificador crudo con la
     primera letra en mayúscula, o sea lo que este archivo existe para evitar. */
  const key = clean.toLowerCase().replace(/^gs_/, "")
  if (EXACT[key]) return EXACT[key]

  const [verb, ...rest] = key.split("_")
  const resource = rest.join("_")
  const v = VERBS[verb]
  const r =
    RESOURCES[resource] ??
    RESOURCES[resource.replace(/s$/, "")] ??
    (resource ? resource.replace(/_/g, " ") : "")
  if (v && r) return `${v} ${r}`
  // Tool desconocida: legible, y sin NINGÚN prefijo de espacio de nombres — ni
  // el del servidor MCP ni el `gs_` de la caja. Se usa `key`, no `clean`: con
  // `clean` volvía a salir "Gs render png".
  return key.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase())
}
