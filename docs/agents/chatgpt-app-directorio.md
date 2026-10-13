# MailMask en el directorio de apps de ChatGPT (13-oct-2026)

Mismo MCP público que el conector de Claude (`https://www.mailmask.studio/mcp`, OAuth 2.1 de
`oauth.ts`). Sin widgets: el directorio acepta apps sólo con tools. Nada se ha enviado a OpenAI.
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

## ⚠️ Riesgo de revisión: cobros dentro de la app

OpenAI no deja vender planes, suscripciones ni upgrades dentro de la app. Varias tools devuelven una
**liga de pago** que abre la persona (`activation_link`, `renewal_link`, `register_domain`,
`transfer_start`) o cancelan algo pagado (`cancel_addon`, `cancel_renewal`). Nunca cobran solas, pero el
revisor puede leerlas como compra dentro de la app. Si lo rechazan: ocultarlas cuando el cliente OAuth
es ChatGPT (`client_name`/redirect del registro) en vez de tocar el catálogo de Claude.

## Lo que hace bliss en el portal (platform.openai.com → Apps)

1. Verificar la organización si no está.
2. Crear la app con MCP `https://www.mailmask.studio/mcp`, auth OAuth → **DCR**.
3. Copiar el token del dominio a `OPENAI_APPS_CHALLENGE` en `/app/secrets.env` de la caja
   `mailmask-prod` y reiniciar; comprobar con
   `curl https://www.mailmask.studio/.well-known/openai-apps-challenge` y darle «Verify».
4. Conectar desde ChatGPT (modo desarrollador) con la cuenta de revisor y correr los 8 casos.
5. Grabar el video (los 5 positivos), subirlo no listado y pegar la liga.
6. Llenar textos, casos y Review details. Enviar.

## Cuenta de revisor

⚠️ **Pendiente**: no hay cuenta de revisor de MailMask documentada en el repo. Debe: entrar con
correo + contraseña (sin Google, sin MFA, sin código por correo), tener un dominio activado de muestra
con 2–3 direcciones, Bandeja con unos correos de prueba y quedarse viva. Las credenciales van sólo
en el formulario «Review details», nunca aquí.

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
| 5 | Revisar la Bandeja | «What's new in my shared inbox? Summarize the latest message» | `inbox_list`, `inbox_read` | Lista de conversaciones y resumen de la más reciente |

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
- Video de recorrido: pendiente (lo graba bliss con los 5 positivos).
