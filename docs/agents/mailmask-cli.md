# CLI de MailMask (`cli/`)

**Qué:** CLI en TypeScript sobre `@easybits.cloud/mailmask` (`sdk/`), un subcomando
por recurso del SDK — sin modelo declarativo encima. Esta primera entrega (ticket 1
del sprint) sólo trae `login`, `logout` y `whoami`; el resto de recursos
(`domains`, `aliases`, `dns`, `rules`, `webhooks`, `send`, `smtp`, `apikeys`, `logs`,
`suppressions`) llegan en tickets siguientes sobre esta misma base.

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

## Convención dura — no se negocia en ningún comando futuro

**Ningún registro DNS con `managed: true` se toca desde el CLI, ni con `--force`.**
El SDK ya marca esto en `DnsRRSetAnotado.managed` (tipo exportado desde
`sdk/src/types.ts`) — es la fuente de verdad. Cualquier comando `dns upsert` o
`dns delete` que se agregue debe leer ese campo antes de mutar y rehusarse si es
`true`, sin excepción de flag.
