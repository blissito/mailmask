# MailMask en el directorio de apps de ChatGPT (13-oct-2026)

URL que se envía (a OpenAI y al directorio de Claude): **`https://www.mailmask.studio/mcp/directory`**.
Es el mismo servidor de `/mcp` filtrado por `DIRECTORY_ALLOWLIST` (`mcp.ts`), con su guía
`MCP_DIRECTORY_INSTRUCTIONS`, mismo OAuth 2.1 de `oauth.ts` con `resource` propio y metadata RFC 9728 en
`/.well-known/oauth-protected-resource/mcp/directory` (su 401 la anuncia). Un token de `/mcp` no entra a
`/mcp/directory` ni al revés. `/mcp` (completo) no cambia para nadie y **no** se menciona en los portales.
Desde el 19-oct-2026 lleva **una pantalla** (MCP Apps): la Bandeja, ver «Pantalla de la Bandeja» abajo.
Nada se ha enviado a OpenAI.
Copia de lo hecho en Ghosty (`ghosty-studio/docs/claude/chatgpt-app-directorio.md`).

## Requisitos de OpenAI y dónde se cumplen

| Requisito | Cómo | Dónde |
|---|---|---|
| Verificación de dominio: token en texto plano en `/.well-known/openai-apps-challenge` | lee el secreto `OPENAI_APPS_CHALLENGE`; 404 si falta | `main.ts`, prueba en `mcp.test.ts` |
| PKCE `S256`, `resource` = `<issuer>/mcp`, `issuer` idéntico a `authorization_servers` | ya estaba | `oauth.ts` |
| RFC 9207: `iss` en toda vuelta del authorize + `authorization_response_iss_parameter_supported` | ya estaba (código, `access_denied` y errores) | `oauth.ts`, `oauth.test.ts` |
| Registro por **DCR** con `https://chatgpt.com/connector_platform_oauth_redirect` | DCR acepta cualquier https y compara exacto en el authorize; Claude y el loopback siguen igual | `validRedirectUri`, prueba en `oauth.test.ts` |
| `readOnlyHint`, `destructiveHint`, `openWorldHint` explícitos en todas | `READ_ONLY_TOOLS`, `DESTRUCTIVE_TOOLS`, `OPEN_WORLD_TOOLS` | `mcp.ts`, `mcp.test.ts` |
| Ícono cuadrado ≥48 px; variante oscura opcional | 512 px PNG + SVG | `public/img/chatgpt-app/` (servidos en `/img/chatgpt-app/…`) |
| Privacidad con datos, fines, destinatarios, retención y controles | §1–§9 de `/privacy` (retención §5, derechos §7, agentes §9) | `public/privacy.html` |

## Qué queda fuera de `/mcp/directory` (13-oct-2026)

OpenAI no deja vender dentro de la app y ningún directorio quiere credenciales en el chat. Fuera:

- **Cobros y compras**: `activation_link`, `billing_status`, `list_addons`, `list_orders`, `cancel_addon`,
  `cancel_renewal`, `search_domains`, `domain_prices`, `register_domain`, `list_registrations`, todo
  `transfer_*` (incl. `approve_transfer_dns`, `update_transfer_dns`, `resend_transfer_email`, `transfer_out`),
  `lock_domain_transfer`, `renewal_status`, `renewal_link`, referidos (`referral_status`, `set_referral_*`).
- **Secretos**: `create_mailbox`, `reset_mailbox_password` (contraseña del buzón), `create_webhook` (secreto
  de firma), `*_smtp_credential(s)`, `export_link` (exporta la cuenta entera); `create_alias` pierde el
  parámetro `mailbox`.
- **Envío masivo**: `bulk_send`, `bulk_status`.

`search_tools` sólo busca en lo que quedó (no hay otra tool genérica de despacho). La guía, las
descripciones y los esquemas no nombran nada de lo de arriba ni `/mcp`, ni MercadoPago (lo fija
`mcp.test.ts`). Volver a meter algo = agregarlo a la lista blanca y revisarlo contra las dos políticas.

## Lo que hace bliss en el portal (platform.openai.com → Apps)

1. Verificar la organización si no está.
2. Crear la app con MCP `https://www.mailmask.studio/mcp/directory`, auth OAuth → **DCR**.
3. Copiar el token del dominio a `OPENAI_APPS_CHALLENGE` en `/app/secrets.env` de la caja
   `mailmask-prod` y reiniciar; comprobar con
   `curl https://www.mailmask.studio/.well-known/openai-apps-challenge` y darle «Verify».
4. Conectar desde ChatGPT (modo desarrollador) con la cuenta de revisor y correr los 8 casos.
5. Grabar el video (los 5 positivos), subirlo no listado y pegar la liga.
6. Llenar textos, casos y Review details. Enviar.

## Pantalla de la Bandeja (19-oct-2026)

`inbox_list` declara `_meta.ui.resourceUri = ui://mailmask/bandeja.html` (fuente `widgets/bandeja.ts`
+ `.css`, `npm run build:widgets`, bundle commiteado). El HTML va dentro de `resources/read`, sin red
propia (`csp` vacía). Tarjeta: contadores y 8 conversaciones con 2 botones; pantalla completa: filtros,
hilo con notas y cerrar/posponer/urgente (`inbox_mark`). Responder lo redacta el modelo y el envío pasa
por la confirmación del host. Requisitos que cumple:

- **`ui.domain`**: ChatGPT lo exige para enviar un plugin con UI (`https://www.mailmask.studio`); Claude
  sólo acepta `<sha256(url)[:32]>.claudemcpcontent.com` y con otro valor no la pinta. Como el servidor
  es stateless, se decide por User-Agent (`isChatGptAgent` en `mcp.ts`): ChatGPT lo recibe, los demás
  no. El log `mcp ui resource read` guarda el User-Agent real para confirmarlo.
- Guía de UI de OpenAI: máx. 2 acciones en la tarjeta, sin logo dentro de ella, contraste AA, móvil.
- Directorio de Claude: los cambios del servidor no se reenvían; en `claude.ai/directory/manage` se
  suben 3–5 capturas PNG ≥1000 px recortadas a la respuesta, cada una con su prompt.
- ZIP de ChatGPT `chatgpt-plugin/mailmask-plugin.zip` en 1.1.0 (la descripción menciona la pantalla).
  Basta la verificación **individual** de la organización; cambios del MCP se recogen con «Rescan».

## Cuenta de revisor (13-oct-2026)

`directory-review@mailmask.studio` (la misma para Claude y ChatGPT), creada en prod con
`scripts/cuenta-revisor.ts` (idempotente; instrucciones de cómo correrlo en la caja en su cabecera).
Entra con correo + contraseña en `/login` (sin Google, sin MFA, sin códigos). La contraseña vive sólo en
`~/mailmask-reviewer.txt` de la Mac de bliss (chmod 600) y va únicamente en «Review details»; para rotarla,
`--reset-password` con el hash nuevo (corta los tokens OAuth emitidos).

Datos: dominio real `demo.mailmask.studio` (SES + registros en la zona de mailmask.studio, DMARC `p=none`),
activado por cortesía hasta 2027-12-31, direcciones `hello@`, `support@` y `billing@`, y tres conversaciones
de muestra en la Bandeja (remitentes `example.com/org/net`). El dominio no tiene zona asignada: el editor
de DNS no puede tocar la de mailmask.studio.

**No manda correo a terceros reales** (`sandbox.ts`): toda cuenta `*-review@mailmask.studio` sólo envía,
invita o reenvía a su propio correo, a sus dominios o a dominios reservados (`example.com`, `*.test`…).
Lo frena la ruta (403 legible) y, como última barrera, `ses.ts` (`sendFromDomain`, `sendRawFromDomain`,
`forwardEmail`); el reenvío bloqueado se descarta como la supresión.

## Paquete para el formulario (en inglés)

- **Name**: MailMask
- **Short description**: Manage your MailMask email domains, addresses and shared inbox from ChatGPT.
- **Long description**: MailMask (mailmask.studio) gives you professional email on your own domain: forwarding addresses, mailboxes, DNS, and a shared team inbox. This app lets you work with your account from ChatGPT: list your domains and check their health, see and create email addresses, review DNS records, read and reply to messages in your shared inbox, and look at sending logs. Payments are never made inside ChatGPT: they always open as a link on mailmask.studio. Sign-in uses your MailMask account through OAuth; the app only sees what you can see in MailMask, and you can revoke access at any time.
- **Category**: Productivity / Business
- **Website** https://www.mailmask.studio · **Support** https://www.mailmask.studio/docs · **Privacy** https://www.mailmask.studio/privacy · **Terms** https://www.mailmask.studio/terms
- **Example prompts**: «Is my domain's email set up correctly?» · «Create a sales@ address that forwards to me» · «What's new in my shared inbox?»

### Casos positivos

| # | Escenario | Prompt | Tools esperadas | Resultado esperado |
|---|---|---|---|---|
| 1 | Ver mis dominios | «List my MailMask domains» | `list_domains` | El dominio de muestra con plan y estado de MX/verificación |
| 2 | Salud del correo | «Is email on my domain set up correctly?» | `list_domains`, `domain_health` | Resumen de MX, SPF, DKIM y DMARC con lo que falte |
| 3 | Ver direcciones | «Which addresses do I have on my domain?» | `list_aliases` | Las direcciones de muestra y a dónde reenvían |
| 4 | Crear dirección | «Create a sales@ address on my domain that forwards to my email» | `list_domains`, `create_alias` | La dirección nueva confirmada; no envía correo |
| 5 | Revisar la Bandeja | «Show my MailMask shared inbox», luego «Abrir bandeja», abrir una conversación y «Cerrar» | `list_domains`, `inbox_list` (pinta la pantalla); desde la pantalla `inbox_read` e `inbox_mark` | La tarjeta con contadores y conversaciones; en pantalla completa el hilo con su nota interna; la conversación sale de «Abiertas» |

### Casos negativos

| # | Prompt | Por qué no debe actuar | Respuesta esperada |
|---|---|---|---|
| 1 | «What's the weather in Mexico City?» | No es de MailMask | No llama tools |
| 2 | «Show me my MailMask API key» | El MCP no expone llaves | Dice que se ven en el panel de mailmask.studio; no llama tools |
| 3 | «Translate this paragraph into French: …» | Tarea general sin relación con la cuenta | Lo traduce sin la app |

### Anotaciones (por si el escaneo pide aclarar)

- **readOnly** (`READ_ONLY_TOOLS`): listas, consultas, salud, logs, precios, estados y ligas de
  exportación. No cambian nada de la cuenta.
- **destructive** (`DESTRUCTIVE_TOOLS`): borran, revocan, cancelan o reemplazan sin vuelta atrás
  (`delete_*`, `remove_*`, `revoke_*`, `cancel_*`, `set_dns_record`, `transfer_out`, `inbox_delete`…).
- **openWorld** (`OPEN_WORLD_TOOLS`): tocan el mundo fuera de la cuenta — mandan correo
  (`send_email`, `bulk_send`, `inbox_reply|send`, `invite_member`), llaman un webhook
  (`test_webhook`), publican DNS o mueven/registran dominios.

### Assets

- Ícono claro: `public/img/chatgpt-app/mailmask-icon.svg` / `mailmask-icon-512.png`
  (https://www.mailmask.studio/img/chatgpt-app/mailmask-icon-512.png).
- Ícono oscuro (opcional): `mailmask-icon-dark.svg` / `mailmask-icon-dark-512.png`.
- Video de recorrido: pendiente (lo graba bliss con los 5 positivos; el 5 enseña la tarjeta, la
  pantalla completa y «Cerrar», en escritorio y en móvil).
