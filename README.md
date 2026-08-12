<div align="center">

<img src="public/img/logo.png" alt="MailMask" width="120" height="120">

# MailMask

Email profesional con tu dominio. Máscaras, forwarding y bandeja compartida — sin Google Workspace.

**[mailmask.studio](https://mailmask.studio)**

</div>

## Qué es

MailMask te permite recibir y gestionar emails con tu dominio propio. Configura máscaras (aliases) que reenvían a tu Gmail, Outlook o cualquier buzón existente, sin montar un servidor de correo y sin pagar licencia por buzón. Ideal para freelancers, startups y equipos pequeños.

## Features

- **Máscaras con forwarding** — direcciones como hola@tudominio.com que reenvían a uno o varios destinatarios
- **Envío autenticado** — salida desde tu dominio con DKIM y SPF configurados automáticamente en SES
- **Bandeja compartida** — asigna conversaciones a miembros del equipo y responde desde el dashboard, con actualización en tiempo real vía SSE
- **API REST + SDK** — cliente JS/TS publicado como [`@easybits.cloud/mailmask`](https://www.npmjs.com/package/@easybits.cloud/mailmask)
- **SMTP relay** — credenciales SMTP para enviar desde tu código o SaaS (plan Developer)
- **Reglas de enrutamiento** — reenvío condicional por alias
- **RBAC por dominio** — roles owner, admin y agent con permisos granulares
- **Respaldos verificados** — snapshot completo del SQLite con `VACUUM INTO`, verificado con `integrity_check` antes de subir a S3
- **Blog integrado** — 24 guías SEO sobre email profesional y forwarding
- **Docs con agente** — chat de soporte en `/docs` que responde por RAG sobre la documentación

## Planes

Precios en MXN. Máscaras, reglas, envíos y reenvío se cuentan **por dominio**, no por cuenta.

|  | Básico | Freelancer | Developer |
|---|---|---|---|
| Mensual | $49 | $449 | $999 |
| Anual | $490 | $4,490 | $9,990 |
| Dominios | 1 | 15 | 20 |
| Máscaras | 5 | 50 | 100 |
| Reglas | — | 10 | 50 |
| Historial | 15 días | 30 días | 90 días |
| Envíos/día | — (add-on) | 200 | 1,000 |
| **Reenvío de entrada** | **100/hora** | **500/hora** | **2,000/hora** |
| API + SDK | ✓ | ✓ | ✓ |
| SMTP relay | — | — | ✓ |
| Webhooks | — | — | ✓ |

Son dos límites distintos. **Envíos** es el correo saliente que originas tú (panel, API, SMTP relay). **Reenvío de entrada** es el correo que llega a una máscara y sale al buzón destino — el caso de uso principal, medido por hora y un orden de magnitud mayor: ~2,400, ~12,000 y ~48,000 al día. Quien solo reenvía nunca toca el límite de envíos.

### Add-ons

Se compran encima de cualquier plan activo y se cobran aparte, mes a mes.

| Add-on | Precio | Qué hace |
|---|---|---|
| Envíos 25/día | +$49 | Desbloquea el envío desde tu dominio, tope 25/día por dominio |
| Envíos 100/día | +$99 | Igual, tope 100/día por dominio |
| Dominio extra | +$99 c/u | Un dominio más de cupo. Acumulable. No incluye envío |

Los dos de envíos son mutuamente excluyentes; se compran una vez y aplican a todos los
dominios de la cuenta, con el tope contando por dominio y por día.

Fuente de verdad: `PLANS` y `ADDONS` en [`db.ts`](db.ts).

## Stack

Node + tsx · Elysia · SQLite (Drizzle) · AWS SES/S3 · MercadoPago · Fly.io

## Setup

```bash
cp .env.example .env
npm install
npm run dev    # localhost:8000
npm test
```

Requiere los buckets de S3 `mailmask-inbound` y `mailmask-backups` en `us-east-1`. Todo AWS está fijado a esa región: SES inbound solo existe en us-east-1, us-west-2 y eu-west-1, y ahí viven las receipt rules y los dominios verificados.

## Deploy

```bash
fly deploy     # ~22s, ~11s de downtime
```

El downtime es estructural: con SQLite en un volumen único solo una máquina puede montarlo, así que Fly debe detener la vieja antes de arrancar la nueva.

## Endpoints de salud

| Ruta | Uso |
|------|-----|
| `/healthz` | Liveness para fly-proxy. Sin I/O. |
| `/health` | Diagnóstico: profundidad de cola, dead letters y estado de SES. Devuelve 503 si algo está degradado — **no** usar como readiness del proxy. |

## Documentación y agente

La página pública [`/docs`](https://mailmask.studio/docs) tiene doble propósito: es la documentación para usuarios y la fuente de la base de conocimiento del **Asistente MailMask**, el chat que responde dudas ahí mismo.

El agente vive en [Formmy](https://www.formmy.app) y responde por RAG sobre 18 documentos que se le suben; **no lee el sitio en vivo**. Las fuentes son dos:

1. **13 secciones extraídas de `public/docs.html`** — instalación, autenticación, dominios, aliases, reglas, envío, logs, SMTP, API keys, errores, MCP y referencia de la API.
2. **`EXTRA_DOCS` en `scripts/upload-docs.ts`** — lo que no está en la página: planes y precios, configuración de dominio, bandeja, envío masivo y RBAC.

No se actualiza solo. Después de editar `docs.html` o `EXTRA_DOCS`:

```bash
FORMMY_SECRET_KEY=sk_live_xxx npx tsx scripts/upload-docs.ts   # borra y re-sube, idempotente
npm run build:chat                                             # solo si tocaste docs-chat.tsx
```

El `baseUrl` del SDK debe ser **`https://www.formmy.app`**. El apex `formmy.app` no sirve certificado TLS, así que apuntar ahí hace que todo `fetch` muera en el handshake con un `Failed to fetch` que parece CSP y no lo es. El host va en tres archivos (`docs-chat.tsx`, `upload-docs.ts`, `setup-agent.ts`) y en el `connect-src` del CSP en `main.ts`; el bundle lleva el valor incrustado, por eso hay que reconstruirlo.

## Estructura

| Archivo | Propósito |
|---------|-----------|
| `main.ts` | Todos los endpoints, estáticos y middleware |
| `db.ts` | Capa de datos, definición de planes, CRUD |
| `schema.ts` | Schema de Drizzle (22 tablas) |
| `auth.ts` | JWT, hashing PBKDF2, tokens CSRF |
| `ses.ts` | SES, S3, IAM, helpers de respaldo |
| `forwarding.ts` | Procesamiento y reenvío de correo entrante |
| `backup.ts` | Respaldo completo de la base con verificación |
| `cron.ts` | Tareas programadas |
| `public/docs.html` | Docs públicas y fuente del agente |
| `public/js/docs-chat.tsx` | Widget del Asistente MailMask |
| `scripts/upload-docs.ts` | Sube la base de conocimiento del agente |
| `scripts/setup-agent.ts` | Persona e instrucciones del agente |

---

Hecho con 🚬🫁 por [@blissito](https://github.com/blissito) · [fixter.org](https://fixter.org)
