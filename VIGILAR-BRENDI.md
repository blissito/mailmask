# Vigilar la compra y el threading de Brenda

## 1. Cuando pague el add-on

Dejar corriendo en una terminal:

```bash
fly logs | grep -iE "Add-on|webhook"
```

**Lo que debe aparecer**, en este orden:

```
MP subscription fetched   external_reference=addon:<uuid>  status=authorized
Add-on activado           addonId=... kind=sends100 email=brenda@...
```

**Si aparece esto, algo salió mal:**

| Log | Qué pasó | Arreglo |
|---|---|---|
| `Add-on preapproval sin fila` | El `external_reference` llegó pero no existe la fila | Revisar la tabla `addons`; probablemente se borró el pending |
| Nada, ni un log | El webhook no llegó a MailMask | Revisar la notification_url en MercadoPago |
| `MP subscription fetched` con `external_reference` = un email | MP no respetó el external_reference → **cayó por el camino de plan** | Verificar de inmediato que su `sub_plan` no cambió |

**Verificación por API** (como admin, desde el navegador con sesión iniciada):

```
https://www.mailmask.studio/api/admin/users/brenda@sudominio.com
```

Debe traer `addons: [{ kind: "sends100", status: "active", currentPeriodEnd: "..." }]`
y `limits.sendsUnlocked: true` con `limits.sends: 100`.

**Si quedó en `pending`**, activarlo a mano:

```bash
fly ssh console -C "/bin/sh -c 'cd /app && node -e \"
const D=require(\\\"better-sqlite3\\\");
const d=new D(\\\"/data/mailmask.db\\\");
const end=new Date(Date.now()+35*864e5).toISOString();
d.prepare(\\\"UPDATE addons SET status=?, current_period_end=? WHERE user_email=? AND status=?\\\")
 .run(\\\"active\\\", end, \\\"brenda@sudominio.com\\\", \\\"pending\\\");
console.log(d.prepare(\\\"SELECT id,kind,status FROM addons WHERE user_email=?\\\").all(\\\"brenda@sudominio.com\\\"));
\"'"
```

## 2. Cuando mande un correo y le respondan (threading)

```bash
fly logs | grep -iE "Compose sent|Inbound threaded|Inbound created"
```

**Camino correcto:**

```
Compose sent                            conversationId=A  messageId=<uuid@dominio>
Inbound threaded into existing conversation   conversationId=A  matchedRef=<uuid@dominio>
```

El `conversationId` debe ser **el mismo** y `matchedRef` debe coincidir con el
`messageId` del compose.

**Threading roto** — se ve así:

```
Compose sent                     conversationId=A  messageId=<uuid@dominio>
Inbound created new conversation conversationId=B  refsInEmail=2  unmatchedRefs=[...]
```

Es decir: llegó la respuesta con referencias, pero ninguna coincide con lo guardado.
Causa más probable: **SES reescribió nuestro Message-ID**. Si `unmatchedRefs` trae un
id distinto al que emitimos, ésa es la confirmación.

Arreglo en ese caso: usar el parámetro `_from` (hoy muerto) de `findConversationByThread`
en `db.ts:973` como fallback — match por `domain_id + from + subject normalizado` reciente.

**Ojo:** si `refsInEmail=0`, el cliente de correo de Brenda no mandó `In-Reply-To`.
Eso no es culpa nuestra, pero el fallback de arriba también lo cubriría.
