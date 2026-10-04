# CLI de MailMask (`cli/`)

**Qué:** CLI en TypeScript sobre `@easybits.cloud/mailmask` (`sdk/`), un subcomando
por recurso del SDK — sin modelo declarativo encima. Esta primera entrega (ticket 1
del sprint) trae `login`, `logout`, `whoami`, `domains` y `dns`. Envío de
correo y un modo pensado para agentes llegan después en PRs propios sobre esta
misma base.

**Por qué:** la CLI no inventa nada encima del SDK — cada comando es 1:1 con un
método ya documentado, para que no haya dos formas de aprenderse la API.

## Convenciones

- **Framework:** [citty](https://github.com/unjs/citty) (`defineCommand` /
  `runMain`). Un archivo por comando en `cli/src/commands/`, registrado como
  `subCommands` en `cli/src/index.ts`.
- **Auth:** `MAILMASK_API_KEY` (variable de entorno, siempre gana) >
  keychain del SO (Keychain en macOS vía `security`, Secret Service en Linux vía
  `secret-tool`) > `~/.config/mailmask/credentials.json` (modo `600`) como
  fallback cuando no hay keychain. `mailmask login` sin `--api-key` hace el
  device-code flow (`cli/src/device-auth.ts`): pide al servidor un código, abre el
  navegador en `/cli/authorize` y hace poll hasta que alguien lo confirma con su
  sesión — nunca pide pegar la llave a mano. Las rutas del servidor están en
  `cli-auth.ts` (en memoria, TTL de 5 min: no necesita tabla ni migración).
  `MAILMASK_NO_KEYCHAIN` fuerza el fallback de archivo — es cómo `test/config.test.ts`
  prueba ese camino sin depender de si la máquina que corre la prueba tiene keychain real.
- **No existe un endpoint `/me`.** `whoami` arma la identidad combinando
  `apiKeys.list()` (para nombrar la llave activa por su `keyPrefix`) con
  `domains.list()` (conteo de dominios visibles). Si MailMask agrega un endpoint de
  identidad real, `whoami` debería migrar a usarlo en vez de esta combinación.
- **Exit codes** (ticket 1, mínimo viable): `0` éxito, `1` error genérico, `2` sin
  API key activa o rechazada por MailMask. La taxonomía completa (conflicto,
  transitorio, etc.) y el contrato `--json`/`--yes` para el resto de comandos son
  del ticket de confirmaciones — no los inventes antes de tiempo en comandos nuevos.
- **Secretos:** nunca se imprimen completos más de una vez. `maskSecret()` en
  `cli/src/output.ts` muestra sólo cabeza y cola; úsala para cualquier API key,
  contraseña de buzón, secreto de webhook o credencial SMTP que un comando nuevo
  tenga que confirmar en pantalla.
- **Seguridad del keychain y del device-code** (hallazgos de la vuelta 3 de check):
  `cli/src/keychain.ts` engancha `child.stdin.on("error", () => {})` antes de
  escribir — si `secret-tool`/`security` sale antes de leer stdin, el EPIPE no
  mata el proceso y `writeCredentials` cae a archivo en vez de quedarse a medias.
  En macOS, `security add-generic-password -w <key>` pasa la llave como argumento
  (visible un instante en `ps` para otros procesos del mismo usuario): es una
  limitación del binario `security`, que no soporta leer `-w` desde stdin como sí
  hace `secret-tool store` en Linux — no hay forma de evitarlo sin dejar de usar
  `security`. `POST /api/cli/device/start` es público (no hay sesión con la que
  pedir CSRF) pero sí lleva `rateLimitGuard` por IP y `createDeviceAuthStore` tiene
  un tope (`maxPending`, 500 por defecto) de device-codes pendientes a la vez, para
  que no se pueda inflar sin fin la memoria del proceso. `/cli/authorize`
  deliberadamente NO prellena el código desde la URL: `login.ts` abre
  `verificationUri` (sin `user_code`) y la página (`public/js/cli-authorize.js`)
  deja el campo vacío aunque llegara uno en la query string. La razón es la
  misma vía de phishing de siempre (un enlace armado por un atacante con SU
  propio código, para que la víctima sólo dé clic en "Autorizar" sin comparar
  nada): aquí la mitigación es real, no sólo un aviso — copiar el código a mano
  desde la terminal propia es un paso activo que un clic distraído no salta.
  `createDeviceAuthStore` tampoco devuelve `verificationUriComplete`: ese campo
  era exactamente el link con el código embebido, así que un cliente futuro no
  tiene de dónde volver a sacarlo.

- **Resolución de `<dominio>`:** todo comando que recibe un dominio acepta el
  nombre (`acme.com`) o el id — `cli/src/resolve.ts` lo busca en
  `domains.list()`; si no aparece, se deja pasar tal cual para que la API
  responda su propio 404 en vez de inventar uno aquí. `cli/src/commands/dns.ts`
  ya la reusa; los comandos de recursos futuros que cuelgan de un dominio
  (`aliases`, `rules`, ...) deben hacer lo mismo, no reimplementar la búsqueda.
- **`domains create --preset` / `dns preset`:** ambos llaman a
  `client.dns.preset()` del SDK (los mismos ocho presets que `point_domain_to`
  del MCP, ver `public/skills/mailmask-dns/SKILL.md`). La validación del nombre
  del preset pasa ANTES de tocar red — evita crear el dominio y sólo entonces
  fallar por un `--preset` mal escrito. Deliberadamente NO hay un
  `domains preset` separado: `dns preset` es el único lugar fuera de `create`,
  para no tener dos comandos haciendo lo mismo.
- **`dns upsert` y sus valores:** citty no tiene un tipo de positional "rest",
  así que `<nombre>` y `<tipo>` se declaran como positionals normales y los
  valores restantes se toman de `args._.slice(3)` (la lista completa de
  positionals sin tocar, no sólo "lo que sobró") — ver el comentario en
  `cli/src/commands/dns.ts`. No uses `rawArgs` para esto: ya rompió una vez
  con un `--ttl` de por medio.
- **Registros `managed` en `dns upsert`/`dns delete`:** el SDK no los protege
  del lado del cliente (sólo el servidor, con 409). `refuseIfManaged()` (exportada
  desde `cli/src/commands/dns.ts`) lista el dominio ANTES de mutar y se rehúsa en
  el CLI si el (nombre, tipo) ya es `managed: true` — mensaje claro sin gastar la
  llamada que de todos modos iba a fallar. **Falla CERRADO:** si el listado mismo
  falla (red, 5xx, lo que sea), NO deja pasar la mutación — aborta, porque es
  justo el momento en que menos se sabe si el registro es managed. Pruebas en
  `cli/test/dns.test.ts`.
- **Args compartidos entre `domains` y `dns`:** `PRESETS`, `jsonArg` y `domainArg`
  viven en `cli/src/args.ts`, no copiados en cada archivo de comando. Cualquier
  lista o flag que vaya a repetirse entre dos o más comandos va ahí, no a mano en
  cada uno.
- **Probar un comando que muta (con el SDK simulado):** `cli/test/test-helpers.ts`
  trae `fakeClient()` (un `MailMask` falso por `Proxy`: cada llamada queda en
  `calls`, un método que el test no configuró revienta en vez de devolver
  `undefined` en silencio) y `trapExit()` (mockea `process.exit` para que LANCE
  en vez de matar el proceso de pruebas, así `assert.rejects(..., ExitSignal)`
  comprueba el código Y detiene el flujo como un exit real). El mock de
  `requireClient` vía `mock.module("../src/client.js", ...)` tiene que instalarse
  ANTES del `import()` dinámico del comando — un `before()` corre demasiado
  tarde, cuando el comando ya resolvió el import real. Ver `cli/test/dns.test.ts`
  y `cli/test/domains.test.ts`.

## Convención dura — no se negocia en ningún comando futuro

**Ningún registro DNS con `managed: true` se toca desde el CLI, ni con `--force`.**
El SDK ya marca esto en `DnsRRSetAnotado.managed` (tipo exportado desde
`sdk/src/types.ts`) — es la fuente de verdad. Cualquier comando `dns upsert` o
`dns delete` que se agregue debe leer ese campo antes de mutar y rehusarse si es
`true`, sin excepción de flag.
