# Conectar MailMask: los otros clientes (no ChatGPT ni Claude)

Investigado el 19-oct-2026 con documentación oficial (sin navegador). MCP: `https://www.mailmask.studio/mcp`.
Nuestro DCR acepta `token_endpoint_auth_method` `none` (público, por defecto) y `client_secret_post` (`oauth.ts:174`).

## 1. Tabla de soporte (ordenada por impacto para un dueño de negocio en México)

| # | Cliente | MCP remoto por URL | OAuth (DCR) | Sólo header / API key | ¿Sirve en México? | Fuente oficial |
|---|---|---|---|---|---|---|
| 1 | **Gemini app** (gemini.google.com) | Sí, «Custom apps» en Connected Apps | Sí (DCR; si no, credenciales en «Advanced features») | No documentado | **No**: sólo 18+, **en EE. UU.**, cuenta personal (no Workspace), sólo inglés, Keep Activity encendido | https://support.google.com/gemini/answer/17209137 |
| 2 | **Microsoft Copilot** (app gratis copilot.microsoft.com) | **No** (sin conectores MCP propios) | — | — | No | (sin doc oficial que lo ofrezca; sólo Copilot Studio) |
| 2b | **Copilot Studio / M365 Copilot** | Sí, asistente MCP (Tools → Add a tool → New tool → Model Context Protocol), sólo Streamable HTTP | Sí: «OAuth 2.0 → Dynamic discovery» | Sí: «API key», tipo Header, nombre `Authorization` | Sí, pero pide licencia de Copilot Studio y tenant de M365: no es el dueño de tienda | https://learn.microsoft.com/microsoft-copilot-studio/mcp-add-existing-server-to-agent |
| 3 | **Perplexity** (web y Mac) | Sí: Plugins (o Customize → Connectors) → Add custom → Connector → Add MCP connector → Remote | Sí (descubrimiento + DCR; si no, Client ID/Secret) | Sí: «API Key» | Sí; los custom connectors piden plan de pago (Pro/Max/Enterprise, según guías de terceros) | https://www.perplexity.ai/help-center/en/articles/13915507-adding-custom-remote-connectors |
| 4 | **Le Chat (Mistral)** | Sí: Connectors → + Add Connector → pestaña «Custom MCP Connector» | Sí: «OAuth 2.1 con DCR», detecta el método solo | Sí: «HTTP Bearer Token» | Sí, **incluido el plan Free** (el dueño de la cuenta es admin) | https://docs.mistral.ai/le-chat/knowledge-integrations/connectors/mcp-connectors |
| 5 | **Cursor** | Sí: `mcp.json` con `url` (Customize → MCP) | Sí (Streamable HTTP + OAuth, descubre en `/.well-known/oauth-authorization-server`; callback `http://localhost:8787/callback`) | Sí: `headers` | Sí | https://cursor.com/docs/context/mcp · deeplink: https://cursor.com/docs/context/mcp/install-links |
| 6 | **VS Code + GitHub Copilot** | Sí: Command Palette → «MCP: Add Server» → HTTP | Sí: primero DCR, luego cae a pedir client ID; estado en menú Accounts | Sí: `headers` + `inputs` `promptString` `password: true` | Sí | https://code.visualstudio.com/docs/copilot/customization/mcp-servers · https://code.visualstudio.com/docs/copilot/reference/mcp-configuration · https://code.visualstudio.com/api/extension-guides/ai/mcp |
| 7 | **Gemini CLI** | Sí: `httpUrl` en `~/.gemini/settings.json` o `gemini mcp add --transport http` | Sí: sin bloque `oauth`, al 401 descubre y hace DCR; `/mcp auth mailmask` abre el navegador | Sí: `--header` / `headers` | Sí (gratis con cuenta de Google personal) | https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md |
| 8 | **Grok** (grok.com) | Sí: grok.com/connectors → New Connector → Custom → URL | «complete any required authentication» (no detalla OAuth/DCR) | No documentado | Sí | https://docs.x.ai/grok/connectors |
| 9 | **Windsurf** (hoy docs bajo «Devin Desktop») | Sí: Cascade → `…` → MCPs → Open MCP config file, `serverUrl` | Sí («OAuth para cada transporte», sin pasos) | Sí: `headers` | Sí | https://docs.devin.ai/desktop/cascade/mcp |

Riesgos a verificar en la fase con navegador:
- **Perplexity + cliente público**: hay reporte de `Dynamic client registration did not return a client_secret` con servidores que registran clientes públicos (https://community.perplexity.ai/t/custom-mcp-connector-fails-with-did-not-return-a-client-secret-for-rfc-7591-compliant-public-client-registrations/5172). Nosotros sólo damos secreto si el cliente pide `client_secret_post`; si Perplexity no lo pide, fallará. Probarlo antes de prometerlo; si truena, la salida es «API Key» con `mk_…` o devolver secreto por defecto.
- **VS Code**: issue de cliente DCR viejo que no se descarta tras un 401 (https://github.com/microsoft/vscode/issues/321834); el arreglo es «Authentication: Remove Dynamic Authentication Providers».
- **Gemini app**: no se puede capturar desde México sin cuenta de EE. UU.; el post debe decirlo tal cual.

## 2. Los que valen para el post (con capturas)

1. **Le Chat de Mistral** — el único chat de consumo, gratis, en español y disponible en México con OAuth por URL. Es el «Gemini/Copilot que sí se puede».
2. **Cursor** — el editor con IA más usado por quien programa la web del negocio; OAuth sin llaves.
3. **Gemini CLI** — gratis con la cuenta de Google y es la forma legal de usar Gemini con MailMask desde México.

Los demás van en una línea o bloque (sección 4).

## 3. Guion de capturas

Común a todos: si sale la pantalla de MailMask, usar la cuenta de demo (nunca la de bliss con dominios de clientes). **Tapar siempre**: correo de la cuenta en la pantalla de consentimiento si no es la de demo, avatar/nombre del cliente de IA, historial de chats en la barra lateral, `client_id`/tokens si aparecen en URLs, y nombres de dominios de clientes (kandey, brendago, fancyfiles, insightslab).

### Le Chat (requiere: cuenta Mistral gratis; sólo navegador, nada instalado)

| Archivo | Cómo llegar | Qué debe verse | Tapar | Texto del paso |
|---|---|---|---|---|
| `conectar-lechat-01.png` | chat.mistral.ai → menú lateral → Intelligence → **Connectors** | Página de conectores con el botón **+ Add Connector** | Historial de chats, avatar | «En Le Chat abre **Conectores** (Intelligence → Connectors) y toca **+ Add Connector**.» |
| `conectar-lechat-02.png` | Pestaña **Custom MCP Connector** | Formulario lleno: nombre `MailMask`, URL `https://www.mailmask.studio/mcp`, botón **Connect** | — | «En **Custom MCP Connector** ponle de nombre `MailMask`, pega `https://www.mailmask.studio/mcp` y da **Connect**. No pongas llave: Le Chat detecta OAuth solo.» |
| `conectar-lechat-03.png` | Tras Connect se abre mailmask.studio | Pantalla de consentimiento de MailMask: nombre del cliente, cuenta, a dónde regresa, **Permitir** / Cancelar | Correo si no es demo | «MailMask te pide permiso. Revisa la cuenta y da **Permitir**.» |
| `conectar-lechat-04.png` | Connectors → My Connectors → tarjeta MailMask → **Functions** | Lista de herramientas (list_domains, inbox_list…) y los interruptores **Always allow** | — | «Listo: en **Functions** ves lo que puede hacer. Deja lo de leer en *Always allow*; lo que envía o borra, que te pregunte.» |
| `conectar-lechat-05.png` | Chat nuevo, conector MailMask activo; pedir «¿Qué correos nuevos tengo en mi Bandeja?» | Llamada a `inbox_list` expandida + respuesta en español | Remitentes reales, asuntos | «Pregúntale algo de tu correo. La primera respuesta con datos reales confirma que quedó conectado.» |

### Cursor (requiere: Cursor instalado en la Mac + cuenta de Cursor; plan gratis basta)

| Archivo | Cómo llegar | Qué debe verse | Tapar | Texto del paso |
|---|---|---|---|---|
| `conectar-cursor-01.png` | Botón «Add to Cursor» del post (deeplink, ver abajo) o Cursor → Customize → MCP → Add custom | Diálogo de instalación con `mailmask` y la URL | Ruta del proyecto en el título | «Da clic en **Add to Cursor** (o pega el bloque en `~/.cursor/mcp.json`).» |
| `conectar-cursor-02.png` | Customize → MCP | Fila `mailmask` con aviso «Needs authentication» / botón **Connect** | — | «En la lista de MCP, junto a `mailmask`, da **Connect**.» |
| `conectar-cursor-03.png` | Se abre el navegador | Consentimiento de MailMask (regresa a `localhost:8787`) | Correo | «Da **Permitir** en MailMask y vuelve a Cursor.» |
| `conectar-cursor-04.png` | Customize → MCP | `mailmask` en verde con número de herramientas | — | «Queda en verde con sus herramientas.» |
| `conectar-cursor-05.png` | Chat de Agent: «Revisa el DNS de midominio.com y dime a dónde apunta la web» | Tool call `website_status` / `domain_health` aprobada + respuesta | Dominio real (usar el de demo) | «Pídele algo. Cursor te muestra cada herramienta que usa antes de ejecutarla.» |

Bloque para el post:
```json
{ "mcpServers": { "mailmask": { "url": "https://www.mailmask.studio/mcp" } } }
```
Deeplink: `cursor://anysphere.cursor-deeplink/mcp/install?name=mailmask&config=<base64 de {"url":"https://www.mailmask.studio/mcp"}>` (= `eyJ1cmwiOiJodHRwczovL3d3dy5tYWlsbWFzay5zdHVkaW8vbWNwIn0=`). Verificar en la fase de navegador que abre bien.

### Gemini CLI (requiere: Node 20+, `npm i -g @google/gemini-cli`, cuenta de Google personal; Terminal en la Mac)

| Archivo | Cómo llegar | Qué debe verse | Tapar | Texto del paso |
|---|---|---|---|---|
| `conectar-gemini-cli-01.png` | Terminal | `gemini mcp add --transport http -s user mailmask https://www.mailmask.studio/mcp` y su confirmación | Usuario/host del prompt | «Agrega MailMask con un comando. `-s user` lo deja para todas tus carpetas.» |
| `conectar-gemini-cli-02.png` | `gemini` → `/mcp auth mailmask` | Mensaje de que abre el navegador | Correo de Google en el banner | «Dentro de Gemini escribe `/mcp auth mailmask`.» |
| `conectar-gemini-cli-03.png` | Navegador | Consentimiento de MailMask | Correo | «Da **Permitir**. Gemini guarda el token en `~/.gemini/mcp-oauth-tokens.json`.» |
| `conectar-gemini-cli-04.png` | `/mcp` | `mailmask` conectado con su lista de herramientas | — | «`/mcp` confirma que está listo.» |
| `conectar-gemini-cli-05.png` | Prompt: «¿Cuántas direcciones tiene mi dominio y a dónde reenvían?» | Confirmación de la tool (`list_aliases`) y respuesta | Destinos reales | «Haz tu primera pregunta; Gemini te pide permiso por cada herramienta.» |

## 4. Una línea (o bloque) para el resto

- **Gemini app**: «Settings → Connected Apps → Add a custom app → pega la URL». Hoy sólo en EE. UU., cuenta personal y en inglés: desde México no aparece. Para Gemini usa Gemini CLI.
- **Microsoft Copilot (app gratis)**: no acepta servidores MCP propios. En empresa: **Copilot Studio** → Tools → Add a tool → New tool → Model Context Protocol → URL + «OAuth 2.0 / Dynamic discovery» (pide licencia de Copilot Studio).
- **Perplexity** (de pago): Plugins → Add custom → Connector → Add MCP connector → Remote → URL → OAuth. Si falla con «client_secret», elige **API Key** y pega `Bearer mk_…` (pendiente de probar).
- **VS Code + Copilot**: «MCP: Add Server» → HTTP → URL → `mailmask` → Global; VS Code abre el navegador para OAuth. Bloque:
  ```json
  { "servers": { "mailmask": { "type": "http", "url": "https://www.mailmask.studio/mcp" } } }
  ```
- **Windsurf / Devin Desktop**: Cascade → `…` → MCPs → Open MCP config file:
  ```json
  { "mcpServers": { "mailmask": { "serverUrl": "https://www.mailmask.studio/mcp" } } }
  ```
- **Grok**: grok.com/connectors → New Connector → Custom → URL (OAuth sin documentar; probar).
- **Cualquier otro cliente o script sin navegador**: `Authorization: Bearer mk_…` en el encabezado (ver `docs.html#mcp`).
