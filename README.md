# MailMask

Email profesional con tu dominio. Máscaras, forwarding y bandeja compartida — sin Google Workspace.

**[mailmask.studio](https://mailmask.studio)**

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

## Planes

Los límites son por plan. Precios en MXN.

| Plan | Mensual | Anual | Dominios | Máscaras | Reglas | Historial | Envíos/día | API | SMTP | Webhooks |
|------|---------|-------|----------|----------|--------|-----------|------------|-----|------|----------|
| Básico | $49 | $490 | 1 | 5 | — | 15 días | 10 | ✓ | — | — |
| Freelancer | $449 | $4,490 | 15 | 50 | 10 | 30 días | 50 | ✓ | — | — |
| Developer | $999 | $9,990 | 20 | 100 | 50 | 90 días | 200 | ✓ | ✓ | ✓ |

Fuente de verdad: `PLANS` en [`db.ts`](db.ts).

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

---

Hecho con 🚬🫁 por [@blissito](https://github.com/blissito) · [fixtergeek.com](https://www.fixtergeek.com)
