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
mailmask domains delete <dominio>

mailmask dns list <dominio> [--json]
mailmask dns upsert <dominio> <nombre> <tipo> <valor...> [--ttl 300]
mailmask dns delete <dominio> <nombre> <tipo>
mailmask dns preset <dominio> <preset> [--target ...] [--subdomain ...]
mailmask dns create-zone <dominio>
mailmask dns delegation <dominio>
```

Sin `--api-key`, `login` abre el navegador para autorizar el dispositivo
(device-code, como `gh auth login`) — no hace falta copiar y pegar nada. Con
`--api-key` se salta ese paso y guarda la llave directo; también se puede fijar
`MAILMASK_API_KEY` por variable de entorno, que tiene prioridad sobre lo
guardado y es la vía recomendada para CI o para un agente de código.

En los comandos de `domains` y `dns`, `<dominio>` acepta el nombre
(`acme.com`) o el id — se resuelve contra `domains list` (`cli/src/resolve.ts`).
`domains create --preset` registra el dominio y de una vez aplica un preset de
DNS; `dns preset` hace lo mismo sobre uno que ya existe — es la misma llamada
al SDK (`client.dns.preset`). `dns upsert` reemplaza el conjunto completo de
valores de un (nombre, tipo); los registros `managed: true` (MX, verificación,
DKIM, SPF) los protege el servidor.

La sesión se guarda en el keychain del sistema operativo (Keychain en macOS,
Secret Service/`secret-tool` en Linux). Si no hay keychain disponible —Windows,
o un Linux sin Secret Service— cae a `~/.config/mailmask/credentials.json` con
permisos `600`. `mailmask logout` borra la sesión de donde haya quedado.

## Códigos de salida

- `0` — éxito
- `1` — error genérico
- `2` — no hay API key activa, o MailMask la rechazó

El resto de la taxonomía de códigos y el contrato `--json`/`--yes` para el
resto de comandos llegan en un ticket aparte.

## Desarrollo

```bash
npm run typecheck
npm test
npm run build   # genera dist/index.js con el shebang
```
