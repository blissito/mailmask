# Relay de salida (caja de Stalwart)

Todo lo que mandan los buzones IMAP (Apple Mail, Outlook…) pasa por aquí antes de salir:

    Apple Mail ─465→ Stalwart ─ruta `ses`, LMTP→ 127.0.0.1:2525 (este relay)
              ─HTTPS + HMAC→ POST https://www.mailmask.studio/api/internal/outbound
              → tope diario · supresión · SES · email_logs · Bandeja

Existe para que lo de Apple Mail aparezca en la Bandeja, cuente en los 50 envíos/día y respete
la lista de supresión. Aplicado el 1-oct-2026; detalle y rollback en CLAUDE.md, "Un solo camino
de salida".

## Instalar o actualizar
Desde la raíz del repo, en la Mac:

```bash
for f in install.sh mailmask-outbound-relay.service package.json package-lock.json relay.mjs; do
  scripts/caja.sh put box/outbound-relay/$f /root/mailmask-relay-src/$f
done
S=$(grep '^OUTBOUND_RELAY_SECRET=' .env | cut -d= -f2)
scripts/caja.sh exec "cd /root/mailmask-relay-src && chmod +x install.sh && OUTBOUND_RELAY_SECRET=$S ./install.sh"
```

`install.sh` es idempotente: instala Node 20 en `/opt/node-v20.18.1` si falta (tarball `.gz`;
la caja no trae `xz`), crea el usuario `mailmask-relay`, copia a `/opt/mailmask-relay`, escribe
`/etc/mailmask-relay.env` (0640) y reinicia la unidad sólo si algo cambió.

## Diagnosticar
```bash
scripts/caja.sh exec 'systemctl is-active mailmask-outbound-relay; journalctl -u mailmask-outbound-relay -n 30 --no-pager'
```
- `Escuchando` al arrancar; `Entregado a MailMask` (status 200 + sesMessageId) por envío.
- 530/535 en el journal: Stalwart no autentica por LMTP → `RELAY_REQUIRE_AUTH=false` en
  `/etc/mailmask-relay.env` (sigue siendo sólo loopback) y reiniciar.
- 451 repetidos: la app no responde o el secreto no coincide con el de Fly.

## Códigos que devuelve a Stalwart
| La app responde | El relay contesta | Qué pasa |
|---|---|---|
| 200 `perRcpt` | 250 / 5xx por destinatario | sale lo aceptado; DSN por lo rechazado |
| 422 (tope, remitente, política) | 5xx | Stalwart manda el aviso de no entrega |
| 401, 5xx, timeout, red | 451 | Stalwart reintenta; nunca cae a SES directo |
