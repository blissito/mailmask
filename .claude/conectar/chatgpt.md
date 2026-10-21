# Plan de capturas: conectar MailMask a ChatGPT

Investigado el 19-oct-2026, sin navegador. **Lo que dice la doc oficial no coincide del todo con la UI
de cada cuenta**: confirmar cada etiqueta en pantalla al capturar y corregir el texto del paso.

## Lo que dice OpenAI (con fuentes)

- **Desde el 9-jul-2026 las «apps» se llaman «plugins»** y el directorio de apps pasó a ser el de plugins
  (compartido con Codex). Los artículos viejos dicen «Apps & Connectors»; `docs.html#mcp` también dice
  «Settings → Apps & Connectors → Create», **así que hay que actualizarlo** cuando se confirme la UI.
- Ruta oficial actual (doc de desarrolladores): **chatgpt.com/plugins → botón «+» → «Add custom MCP
  server»** → nombre y descripción → *Connection*: «Server URL» → autenticación (OAuth) → aviso de riesgo
  «I understand and want to continue» → «Create as a plugin» → revisar las tools → **instalar** → chat
  nuevo, escribir `@` y elegir el plugin. Sólo en web; Refresh en la ficha del plugin.
  https://developers.openai.com/plugins/deploy/connect-chatgpt
  https://developers.openai.com/api/docs/guides/custom-mcp-server
- **OAuth**: ChatGPT usa DCR si el servidor lo ofrece (MailMask sí; redirect
  `https://chatgpt.com/connector_platform_oauth_redirect`). Las tools sin `readOnlyHint` piden
  confirmación antes de correr; se puede recordar la elección por conversación (misma fuente).
- **Planes** (help center, artículo 12584461; da 403 a WebFetch, citado desde el buscador): MCP completo
  con escritura está en **Business, Enterprise y Edu**, en web; el admin del workspace enciende el
  **modo desarrollador** en la configuración del workspace (Enterprise/Edu pueden dárselo a miembros).
  **Pro**: sólo lectura/fetch en modo desarrollador. **Plus/Free**: sólo apps del directorio.
  Fuentes de terceros se contradicen sobre Plus/Pro y sobre dónde vive el interruptor
  (Settings → Apps → Advanced settings, o Settings → Security and login → Developer mode).
  https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt
  https://peliqan.io/blog/chatgpt-mcp/ · https://hjarni.com/blog/how-to-use-mcp-with-chatgpt
- **¿MailMask ya está en el directorio?** **No.** `docs/agents/chatgpt-app-directorio.md` dice «Nada se ha
  enviado a OpenAI» y ninguna búsqueda lo encuentra. Mientras no esté, un usuario Plus no puede usarlo.

### Consecuencia para el post
El público no técnico casi siempre tiene Free o Plus, y ahí **no se puede** conectar un servidor propio.
El post debe decirlo en la primera línea de requisitos y ofrecer la salida: Claude (cualquier plan con
conectores) o el asistente Mask dentro de /app. Cuando la app esté aprobada en el directorio, este
tutorial se reduce a «busca MailMask en Plugins → Conectar» y hay que rehacer las capturas 02–04.

## Qué URL usar
`https://www.mailmask.studio/mcp` (es la que dice `docs.html`, las 100 tools). Alternativa:
`/mcp/directory` (sin cobros ni secretos, igual a la futura app del directorio). Decisión de bliss; si se
elige `/mcp/directory`, cambiarla también en `docs.html`. Recomiendo `/mcp/directory` para ChatGPT: es lo
que verá el usuario cuando salga la app y deja fuera ligas de pago que OpenAI no quiere en el chat.

## Requisitos (caja en el post)
1. ChatGPT **Business, Enterprise o Edu**, en **chatgpt.com en la computadora** (no la app del teléfono).
2. **Modo desarrollador** encendido por el admin del workspace (en Business, cada admin lo enciende para sí).
3. Cuenta de MailMask con al menos un dominio y algo en la Bandeja (para que la primera respuesta luzca).

## Capturas (5)

### conectar-chatgpt-01.png — Encender el modo desarrollador
- Ruta: chatgpt.com → avatar → Settings (o Workspace settings si eres admin) → buscar «Developer mode»
  (Apps → Advanced settings, o Security and login; anotar cuál fue).
- Debe verse: el interruptor **encendido** y su aviso de beta.
- Tapar: nombre del workspace, correo y avatar de la cuenta, la lista lateral de chats si asoma.
- Texto: «Abre la configuración de ChatGPT y enciende el **modo desarrollador**. Si tu ChatGPT es de
  empresa y no lo ves, pídeselo a quien administra tu espacio de trabajo.»

### conectar-chatgpt-02.png — Formulario «Add custom MCP server» lleno
- Ruta: chatgpt.com/plugins → «+» → «Add custom MCP server».
- Debe verse: Name «MailMask», descripción corta («Mi correo de MailMask»), Server URL con la URL elegida,
  autenticación **OAuth** y la casilla del aviso marcada, con el botón «Create as a plugin» a la vista.
- Si sale campo de ícono: `https://www.mailmask.studio/img/chatgpt-app/mailmask-icon-512.png`.
- Tapar: barra lateral (otros chats/plugins personales), correo.
- Texto: «Ve a **Plugins**, toca **+** y elige **Add custom MCP server**. Ponle de nombre MailMask, pega
  `https://www.mailmask.studio/mcp…` y deja la autenticación en **OAuth**. Acepta el aviso y toca
  **Create as a plugin**. No hace falta copiar ninguna llave.»

### conectar-chatgpt-03.png — Pantalla de permiso de MailMask (/oauth/authorize)
- Llega sola al instalar/conectar el plugin (si no hay sesión, pasa antes por /login: **no** capturar el
  login, no aporta).
- Debe verse: «Conectar con MailMask», «**ChatGPT** quiere usar tu cuenta de MailMask (…)», la lista
  «Podrá, en tu nombre», «No podrá crear llaves de API», «te regresamos a chatgpt.com» y los botones
  **Permitir / Cancelar**. Tema claro.
- Tapar: **el correo de la cuenta** (va dentro del párrafo; blur o reemplazar por `tú@tudominio.com`),
  la barra de direcciones (lleva `client_id`, `state` y `code_challenge`).
- Texto: «ChatGPT te manda a MailMask. Revisa que diga **ChatGPT** y tu cuenta, y toca **Permitir**.
  Puedes cortar el acceso cuando quieras desconectando el plugin o cambiando tu contraseña.»
- Mejor con la cuenta de revisor `directory-review@mailmask.studio` (dominio `demo.mailmask.studio`):
  no expone datos reales y no puede mandar correo a terceros.

### conectar-chatgpt-04.png — Plugin conectado y sus herramientas
- Ruta: tras Permitir regresa a la ficha del plugin en chatgpt.com/plugins.
- Debe verse: «Connected»/instalado y el inicio de la lista de tools (list_domains, inbox_list…).
- Tapar: barra lateral y correo. Recortar la lista a ~6 tools; no hace falta enseñar las 100.
- Texto: «De vuelta en ChatGPT, MailMask aparece como conectado con sus herramientas. Las que sólo leen
  corren solas; las que cambian algo te piden permiso antes.»
- (Prescindible si hay que bajar a 4: fusionar su mensaje en el paso 05.)

### conectar-chatgpt-05.png — Primera petición que funciona
- Ruta: chat nuevo → escribir `@` → elegir MailMask → «¿Qué llegó hoy a mi correo?».
- Debe verse: la pastilla del plugin MailMask, la llamada a `inbox_list` (y `inbox_read` si la hace) y la
  respuesta con 2–3 conversaciones resumidas. Si ChatGPT pide confirmar, capturar después de aprobar.
- Tapar: barra lateral de chats, nombres y correos de remitentes reales (con la cuenta de revisor no
  hace falta: son `example.com/org/net`), correo de la cuenta.
- Texto: «Abre un chat nuevo, escribe **@**, elige **MailMask** y pregunta: *¿Qué llegó hoy a mi
  correo?* ChatGPT revisa tu Bandeja y te lo resume. Otras para probar: *¿Mi dominio está bien
  configurado?* · *Crea ventas@ que me reenvíe a mí*.»

Descartado: captura del login de MailMask, del aviso de riesgo por separado (va en la 02), de la lista
de plugins del directorio (MailMask no está), y del panel de admin del workspace.

## Riesgos (qué cambia en la cuenta real al conectar)
- **Se crea un cliente OAuth** (DCR) en `oauth_clients` y tokens `mo_` (1 h) / `mr_` (60 días, rotan).
  No se crea ninguna API key. Reintentar el formulario crea clientes de más: inofensivo pero se acumulan.
- La conexión con `/mcp` puede **todo lo que el dueño**: borrar dominios y direcciones, cambiar DNS,
  mandar correo, sacar ligas de pago. Con un token `mo_` lo destructivo **se ejecuta directo** (la tarjeta
  de confirmación sólo existe para `mt_` del asistente Mask); la única barrera es la confirmación de
  ChatGPT para tools sin `readOnlyHint`. No aprobar nada durante la sesión de capturas salvo lecturas.
- `inbox_read` **marca leída** la conversación: tras la captura 05 la Bandeja cambia para el equipo.
- El texto del correo que lee viaja a OpenAI (privacidad §9). Usar la cuenta de revisor para capturar.
- Con la cuenta de revisor: el login es correo + contraseña (`~/mailmask-reviewer.txt`); la URL debe ser
  la que se conecte, porque un token de `/mcp` no sirve en `/mcp/directory` ni al revés.
- Desconectar al terminar si se usó una cuenta real; cambiar la contraseña corta todos los tokens.
- El plan de la cuenta de ChatGPT con la que se capture debe ser Business/Enterprise/Edu; si bliss sólo
  tiene Plus/Pro, el flujo puede no existir o quedarse en sólo lectura (la 05 funcionaría, crear no).
