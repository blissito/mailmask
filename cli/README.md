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

Sin `--api-key`, `login` la pide de forma interactiva (necesita una terminal
interactiva). También se puede fijar `MAILMASK_API_KEY` por variable de
entorno — tiene prioridad sobre lo guardado con `login` y es la vía recomendada
para CI o para un agente de código.

La API key se guarda en `~/.config/mailmask/credentials.json` con permisos
`600`. La integración con el keychain del sistema operativo (macOS Keychain /
Secret Service / Credential Manager) queda para una siguiente iteración; hoy
sólo existe el fallback de archivo.

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
