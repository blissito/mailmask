# Plan de capturas: Claude.ai / Desktop, Claude Code y skills

Investigado el 19-oct-2026. Fase sin navegador: aquí sólo va el plan.

## Lo verificado (fuentes oficiales)

- **Custom connector en claude.ai y Desktop**: menú **Customize > Connectors** → **+ Add** →
  **Add custom connector** → nombre + URL → **Continue** → revisar la autenticación detectada → en
  *Authentication*, "Sign in now" → en *OAuth client*, la opción de registro → **Add**. En el chat,
  **+** (abajo a la izquierda) → **Connectors** → interruptor por conversación.
  https://support.claude.com/en/articles/11175166-getting-started-with-custom-connectors-using-remote-mcp
- **Planes**: Free, Pro, Max, Team y Enterprise. **Free: un solo custom connector.** En Team sólo
  Owners/Primary Owners lo agregan (Organization settings > Connectors > Add > Custom > Web); los
  miembros después le dan **Connect** en Customize > Connectors. (Misma URL.)
- **Desktop**: los conectores remotos viven en la cuenta: si lo agregas en la web, ya aparece en
  Desktop, móvil y Claude Code. No hace falta `claude_desktop_config.json`. (Misma URL y
  https://claude.com/docs/connectors/directory.md)
- **Directorio**: MailMask **no aparece** en el directorio de conectores (búsqueda web sin resultados;
  en el repo hay preparación —`/mcp/directory`, cuenta revisora, marca, commits 2cab573/217d8b7/02df71e—
  pero nada indica que se haya publicado). Se envía en https://claude.ai/directory/manage.
  **El post debe usar el custom connector con `/mcp`**; cuando salga en el directorio, se agrega una
  nota "o búscalo en el directorio" (y ese usa `/mcp/directory`, catálogo acotado).
- **Claude Code**: `claude mcp add --transport http <nombre> <url>`, con `--scope user` para todos
  los proyectos (default `local`). Autenticar: `/mcp` → seguir el navegador; alternativa por shell
  `claude mcp login <nombre>`. Además, **si ya lo agregaste en claude.ai y entras a Claude Code con
  esa cuenta, el conector aparece solo** (no con API key, Bedrock ni Vertex).
  https://code.claude.com/docs/en/mcp
- **Skills**: Claude Code las carga de `~/.claude/skills/` (personal) o `.claude/skills/` (proyecto);
  se activan solas por la `description` o con `/nombre`. https://code.claude.com/docs/en/skills
  `npx skills add <url>` (vercel-labs/skills) detecta los agentes instalados, instala en
  `./.claude/skills/` por defecto y en `~/.claude/skills/` con `-g`; flags `-a claude-code`, `-y`,
  `--list`, `-s`. Pide Node ≥ 22.20 (según agenticskills.io, no oficial). https://github.com/vercel-labs/skills

## Hallazgos que corregir antes de publicar

1. `public/docs.html#mcp` y `public/skills/mailmask-mcp/SKILL.md` dicen **"Settings → Connectors"**;
   hoy es **Customize > Connectors** y **+ Add > Add custom connector**. Corregir los dos (y subir
   `metadata.version` de la skill + `npm run skills:publish`).
2. Nuestro metadata OAuth **no anuncia CIMD** (`client_id_metadata_document_supported`), sólo DCR.
   El formulario de Claude ofrece en *OAuth client* "Use Claude's published identity (Recommended)",
   "Register automatically" o "Use your own OAuth client". **Hay que comprobar en la captura cuál
   detecta solo**; si sale la recomendada y falla, el paso del post debe decir "Register
   automatically". (Riesgo #1 de toda la guía.)
3. La skill `mailmask-account` trabaja con API key (`MAILMASK_API_KEY`); la de MCP con OAuth. El post
   debe decir: skills + MCP por OAuth, sin llave. La llave sólo como alternativa.

## Ruta corta elegida (de cero a la primera petición)

- **Agente de código (Claude Code)**: skills → MCP → autenticar → pedir. Terminal = **bloques de
  código**, salvo dos capturas que sí aportan (menú `/mcp` y primera respuesta con herramientas).
- **Chat (claude.ai / Desktop)**: Customize > Connectors → Add custom connector → consentimiento →
  activar en el chat → primera petición. Desktop no lleva capturas propias: una línea "lo que
  agregues en la web aparece en Desktop".
- La pantalla de consentimiento es la misma para ambos: **una sola captura** (sale del flujo web).

Total: **9 capturas** (3 de Claude Code, 6 de claude.ai) + bloques de código.

## Sección A — Claude Code (va primero)

### Paso A1 — Instalar las skills (bloque de código, sin captura)
```bash
npx skills add https://www.mailmask.studio -g -a claude-code
```
Texto: «Instala las cinco skills de MailMask para Claude Code en todos tus proyectos. Con `-g` quedan
en `~/.claude/skills/`; sin él, sólo en la carpeta donde estás.»

### conectar-claude-01.png — Selección de skills en la terminal (opcional, la única de npx)
- Cómo: correr el comando de A1 **sin** `-y` en una terminal limpia (tema oscuro, fuente ≥16 px,
  ventana ~100×30).
- Debe verse: la lista con `mailmask-account`, `mailmask-mcp`, `mailmask-sdk`, `mailmask-dns`,
  `mailmask-docs` marcadas y Claude Code detectado.
- Tapar: ruta del home (`/Users/bliss`) en el prompt — usar un prompt neutro (`PS1='$ '`).
- Texto: «Deja marcadas las cinco y elige Claude Code.» Si la pantalla no aporta, se quita y queda
  sólo el bloque.

### Paso A2 — Agregar el servidor MCP (bloque de código)
```bash
claude mcp add --transport http --scope user mailmask https://www.mailmask.studio/mcp
```
Texto: «Sin encabezados ni llaves: MailMask usa OAuth. `--scope user` lo deja disponible en todos tus
proyectos.» Nota: «Si ya conectaste MailMask en claude.ai con la misma cuenta, Claude Code ya lo
tiene: sáltate este paso.»

### conectar-claude-02.png — `/mcp` con mailmask "needs authentication"
- Cómo: `claude` en una carpeta vacía (`~/demo`), escribir `/mcp`, bajar a `mailmask`, Enter.
- Debe verse: el panel de servidores con `mailmask` y la opción de autenticar (anotar la etiqueta
  exacta que muestre la versión instalada: "Authenticate" según nuestra doc; la doc oficial no la nombra).
- Tapar: **la lista de conectores de claude.ai** que Claude Code jala sola (Den_k, EasyBits, Ghosty,
  MailMask directorio…). Mejor: lanzar con `ENABLE_CLAUDEAI_MCP_SERVERS=false claude` para que sólo
  aparezca `mailmask`. Tapar también la ruta y el correo de la cuenta en el encabezado.
- Texto: «Abre Claude Code, escribe `/mcp`, elige mailmask y Authenticate. Se abre el navegador.»
  Alternativa en una línea: `claude mcp login mailmask`.

### (Consentimiento: reutiliza conectar-claude-06.png; el cliente dirá "Claude Code")
Si se quiere la variante, `conectar-claude-02b.png` con «Claude Code quiere usar tu cuenta…».
No hace falta: el texto del paso lo dice.

### conectar-claude-03.png — Primera petición en Claude Code
- Cómo: tras autenticar, en la misma sesión: «¿Qué dominios tengo en MailMask y cuál está activado?»
  Aprobar la herramienta `list_domains` / `domain_health`.
- Debe verse: el llamado a `mailmask - list_domains (MCP)` y la respuesta en español con el dominio.
- Tapar: dominios de clientes y correos reales. Usar la cuenta demo (ver Requisitos) para que sólo
  salga `demo.mailmask.studio`.
- Texto: «Pídele algo en español. La primera vez Claude te pide permiso para usar la herramienta.»

## Sección B — Claude.ai y Claude Desktop

### conectar-claude-04.png — Customize > Connectors con "+ Add"
- Cómo: https://claude.ai/customize/connectors → abrir el menú **+ Add**.
- Debe verse: el menú con **Add custom connector** resaltado.
- Tapar: la barra lateral con chats previos (recortar a la zona de ajustes), avatar/correo abajo a
  la izquierda, y los conectores ya instalados de bliss (EasyBits, Ghosty, Den_k, **MailMask** y
  **MailMask (directorio)** ya existen: hay que **quitar los dos de MailMask antes** para grabar el
  alta desde cero; ver Riesgos).
- Texto: «En claude.ai entra a Customize → Connectors, toca + Add y elige Add custom connector.»

### conectar-claude-05.png — Formulario: nombre y URL (y la parte de OAuth)
- Cómo: nombre `MailMask`, URL `https://www.mailmask.studio/mcp` → Continue → pantalla de
  autenticación detectada.
- Debe verse: nombre y URL llenos; en la siguiente vista, "Sign in now" y la opción de OAuth client
  que funcione (anotar cuál: ver Hallazgo 2). Si son dos vistas, componer una sola imagen con dos
  recortes o tomar sólo la de OAuth y dejar el nombre/URL en el texto.
- Tapar: nada sensible en el formulario; cuidar el fondo con chats.
- Texto: «Nombre: MailMask. URL: https://www.mailmask.studio/mcp. Sin encabezados ni llaves.
  Continúa, deja "Sign in now" y [la opción que funcionó]. Add.»

### conectar-claude-06.png — Consentimiento de MailMask (/oauth/authorize)
- Cómo: sale sola tras Add (si no hay sesión, primero /login: no capturar el login).
- Debe verse: «**Claude** quiere usar tu cuenta de MailMask (correo)», la lista "Podrá, en tu
  nombre" (dominios, máscaras, buzones y reglas; enviar correo; DNS y ligas de pago), "No podrá
  crear llaves de API", "te regresamos a claude.ai", botones **Permitir** y **Cancelar**.
- Tapar: **el correo** de la cuenta (o usar la cuenta demo y dejarlo, que es más claro). Barra de
  direcciones: dejar visible `www.mailmask.studio/oauth/authorize` pero **recortar los parámetros**
  (`state`, `code_challenge`, `client_id`).
- Texto: «MailMask te dice quién pide acceso y qué podrá hacer. Toca Permitir.» Nota de confianza:
  «Puedes cortar el acceso desconectándolo en Claude o cambiando tu contraseña de MailMask.»

### conectar-claude-07.png — Conector conectado en la lista
- Cómo: al volver a claude.ai, Customize > Connectors con MailMask "Connected"; opcional abrirlo
  para que se vean algunas herramientas.
- Debe verse: MailMask con su estado conectado.
- Tapar: los demás conectores (o recortar a la fila).
- Texto: «Listo: MailMask aparece conectado. También ya está en Claude Desktop, en el móvil y en
  Claude Code con la misma cuenta.»

### conectar-claude-08.png — Activarlo en el chat (+ → Connectors)
- Cómo: chat nuevo → **+** abajo a la izquierda → **Connectors** → interruptor de MailMask.
- Debe verse: el menú con MailMask encendido.
- Tapar: barra lateral de chats (recortar o colapsarla), otros conectores si se ven nombres privados.
- Texto: «En un chat nuevo, toca + → Connectors y enciende MailMask.» (Puede fundirse con la 09 si
  la 09 ya muestra el conector activo.)

### conectar-claude-09.png — Primera petición y respuesta
- Cómo: «Crea la dirección hola@demo.mailmask.studio que me reenvíe a mi correo» **o**, más segura,
  «¿Cómo está mi dominio en MailMask?» → herramienta `domain_health` → respuesta.
- Debe verse: la tarjeta de herramienta de MailMask (permiso "Allow once"/"Always allow") y la
  respuesta en español con MX/SPF/DKIM en verde.
- Tapar: correo destino real si se usa la de crear dirección; nombres de clientes.
- Texto: «Pídelo como se lo dirías a una persona. La primera vez Claude pregunta si puede usar la
  herramienta.»
- Recomendado para el post: la de crear dirección (es la promesa del producto), con destino
  ficticio o la cuenta demo; borrarla después.

## Requisitos para grabar

- **Cuenta**: usar `directory-review@mailmask.studio` (demo.mailmask.studio, activado, hello@/support@/
  billing@, sin correo a terceros reales por `sandbox.ts`). Contraseña en `~/mailmask-reviewer.txt`.
  Evita mostrar dominios y correo de clientes. Si se usa la cuenta de bliss, tapar todo dominio ajeno.
- **Cuenta de Claude**: una con plan Pro/Max (o Free si no tiene ya otro custom connector). La de
  bliss ya tiene MailMask y MailMask (directorio) como conectores y los usa esta sesión.
- Claude Code reciente (`claude --version` ≥ la que trae `claude mcp login`), Node ≥ 22.20 para npx.
- Chrome limpio: perfil o ventana sin pestañas personales, zoom 100 %, ventana 1440×900, tema claro
  de claude.ai (el sitio de MailMask es claro por default; que combinen).
- Capturas a 2× (Retina), recortadas a la zona útil, PNG.

## Riesgos para la cuenta real

1. **Quitar los conectores MailMask existentes de la cuenta de bliss** para grabar el alta: corta el
   acceso de esta y otras sesiones (esta sesión los tiene como `claude_ai_MailMask*`) y Claude Code
   también los pierde. Alternativa sin riesgo: grabar con **otra cuenta de Claude** (Free basta: un
   conector) y la cuenta demo de MailMask.
2. **Free = un custom connector**: si la cuenta de prueba ya tiene uno, el botón no deja agregar.
3. **OAuth client por defecto (CIMD) sin soporte nuestro**: probar primero; si falla, documentar
   "Register automatically" y anotar como pendiente anunciar CIMD.
4. Cada intento de alta registra un cliente por DCR (tope 2000/h por IP, sin problema) y deja tokens
   vivos: al terminar, desconectar los de prueba o cambiar la contraseña de la cuenta demo.
5. La primera petición **escribe de verdad** si se pide crear algo: usar la cuenta demo y borrar la
   dirección al final. Nunca pedir envío de correo en la grabación.
6. En Team/Enterprise el miembro no puede agregarlo: el post necesita una línea "pídele a tu Owner".
7. Barra de direcciones del authorize con `state`/`code_challenge`: recortar siempre.
8. Claude Code jala los conectores de claude.ai: sin `ENABLE_CLAUDEAI_MCP_SERVERS=false` se ven
   Den_k, EasyBits, Ghosty y los dos MailMask (duplicado confuso para el lector).
