# mailmask-cli

CLI oficial de [MailMask](https://mailmask.studio), construida sobre el SDK
[`@easybits.cloud/mailmask`](https://www.npmjs.com/package/@easybits.cloud/mailmask).
Un subcomando por recurso del SDK — sin modelo declarativo encima.

> Nombre del paquete/binario provisional: pendiente de confirmación antes de publicarlo a npm.

## Instalar (desarrollo)

```bash
npm install
npm run dev -- whoami
```

## Comandos de esta primera versión

```bash
mailmask login [--api-key mk_...] [--base-url https://...]
mailmask whoami [--json]
mailmask logout

mailmask domains list [--json]
mailmask domains get <dominio> [--json]
mailmask domains create <dominio> [--preset vercel|netlify|github-pages|cloudflare-pages|render|fly|redirect-a-www|dmarc] [--target ...] [--subdomain ...]
mailmask domains verify <dominio>
mailmask domains health <dominio>
mailmask domains delete <dominio> [--yes] [--json]

mailmask dns list <dominio> [--json]
mailmask dns upsert <dominio> <nombre> <tipo> <valor...> [--ttl 300]
mailmask dns delete <dominio> <nombre> <tipo> [--yes] [--json]
mailmask dns preset <dominio> <preset> [--target ...] [--subdomain ...]
mailmask dns create-zone <dominio>
mailmask dns delegation <dominio>

mailmask aliases list <dominio> [--json]
mailmask aliases create <dominio> <alias> [destino...] [--mailbox] [--json]
mailmask aliases update <dominio> <alias> [destino...] [--enable | --disable] [--json]
mailmask aliases delete <dominio> <alias> [--yes] [--json]
mailmask aliases mailbox create <dominio> <alias> [--json]
mailmask aliases mailbox delete <dominio> <alias> [--yes] [--json]
mailmask aliases mailbox reset-password <dominio> <alias> [--yes] [--json]
mailmask aliases apple-profile <dominio> <alias> -o perfil.mobileconfig
mailmask aliases export <dominio> <alias> [-o buzon.mbox]
```

`domains delete` y `dns delete` son destructivos: en una terminal preguntan
antes de borrar, y fuera de una terminal (CI, un agente) exigen `--yes` — sin
él salen con código `1` sin tocar la red.

Sin `--api-key`, `login` abre el navegador para autorizar el dispositivo
(device-code, como `gh auth login`) — no hace falta copiar y pegar nada. Con
`--api-key` se salta ese paso y guarda la llave directo; también se puede fijar
`MAILMASK_API_KEY` por variable de entorno, que tiene prioridad sobre lo
guardado y es la vía recomendada para CI o para un agente de código.

En los comandos de `domains`, `dns` y `aliases`, `<dominio>` acepta el nombre
(`acme.com`) o el id — se resuelve contra `domains list` (`cli/src/resolve.ts`).
`domains create --preset` registra el dominio y de una vez aplica un preset de
DNS; `dns preset` hace lo mismo sobre uno que ya existe — es la misma llamada
al SDK (`client.dns.preset`). `dns upsert` reemplaza el conjunto completo de
valores de un (nombre, tipo); los registros `managed: true` (MX, verificación,
DKIM, SPF) los protege el servidor.

### Alias y buzones

`aliases create` acepta uno o más destinos como argumentos sueltos
(`aliases create acme.com soporte ana@acme.com luis@acme.com`); con `--mailbox`
también se permite sin ningún destino, porque el correo se queda en el buzón
IMAP en vez de reenviarse. `aliases update` cambia destinos y/o el estado de
la máscara con `--enable`/`--disable` (mutuamente excluyentes); sin ninguno de
los dos y sin destinos nuevos, no hay nada que actualizar y sale con error.

El buzón IMAP vive bajo `aliases mailbox`: `create` lo crea para una máscara
existente (requiere el dominio activado), `delete` lo borra junto con todo su
correo, y `reset-password` genera una contraseña nueva e invalida la
anterior. La contraseña sólo se devuelve en el momento de crear el buzón o de
reiniciarla — en texto sale enmascarada (`sk_a...3f2`, ver `maskSecret()`);
para copiarla completa corre el mismo comando con `--json`.

`aliases apple-profile -o perfil.mobileconfig` escribe el perfil de
configuración de Apple Mail para el buzón de una máscara, listo para
instalarse con doble clic. `aliases export` descarga el buzón completo en
formato mbox: a un archivo con `-o`, o por stdout si no se indica (para
encadenarlo con otro comando).

`aliases delete`, `aliases mailbox delete` y `aliases mailbox reset-password`
son destructivos y siguen el mismo contrato que `domains delete`/`dns delete`:
preguntan en una terminal y exigen `--yes` fuera de ella.

La sesión se guarda en el keychain del sistema operativo (Keychain en macOS,
Secret Service/`secret-tool` en Linux). Si no hay keychain disponible —Windows,
o un Linux sin Secret Service— cae a `~/.config/mailmask/credentials.json` con
permisos `600`. `mailmask logout` borra la sesión de donde haya quedado.

## Códigos de salida

- `0` — éxito
- `1` — error genérico
- `2` — no hay API key activa, o MailMask la rechazó
- `3` — conflicto (409 de MailMask; p. ej. el dominio ya existe)
- `4` — no encontrado (404 de MailMask)
- `5` — error transitorio (429 o 5xx de MailMask, o de red) — vale la pena reintentar

Con `--json`, un error no imprime "✖ ..." sino `{"error": "...", "status": 404}`
a stderr (sin `status` si no vino de la API), para que un script lo parsee sin
adivinar el formato.

## Confirmación de lo destructivo

`domains delete`, `dns delete`, `aliases delete`, `aliases mailbox delete` y
`aliases mailbox reset-password` (y lo que se agregue después que borre,
revoque o envíe a terceros) piden confirmación antes de mutar. En una
terminal preguntan `[y/N]`; fuera de una terminal (CI, un agente, un script)
no hay a quién preguntarle, así que exigen `--yes` — sin él salen con código
`1` sin llamar al SDK, nunca asumen un "sí" silencioso.

## Desarrollo

```bash
npm run typecheck
npm test
npm run build   # genera dist/index.js con el shebang
```
