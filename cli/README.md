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
```

Sin `--api-key`, `login` abre el navegador para autorizar el dispositivo
(device-code, como `gh auth login`) — no hace falta copiar y pegar nada. Con
`--api-key` se salta ese paso y guarda la llave directo; también se puede fijar
`MAILMASK_API_KEY` por variable de entorno, que tiene prioridad sobre lo
guardado y es la vía recomendada para CI o para un agente de código.

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
