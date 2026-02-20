# MailMask

**Email aliases y forwarding para proteger tu privacidad.** Crea direcciones como `yo@tudominio.com` que reenvian a tu email real. Desactiva cuando quieras.

## Features

- **Custom domains** — conecta tu propio dominio y crea aliases ilimitados
- **Catch-all** — captura todos los emails de tu dominio con un wildcard `*`
- **Reglas avanzadas** — filtra por remitente, asunto o destinatario con contains/equals/regex
- **Webhooks** — notifica a tu app cuando llega un email que matchea una regla
- **Forwarding inteligente** — reenvio transparente via SES, conserva headers originales
- **Descarta spam** — reglas para descartar emails no deseados antes de que lleguen
- **Billing con MercadoPago** — suscripciones mensuales con guest checkout y checkout autenticado
- **Rate limiting persistente** — proteccion contra abuso con Deno KV (persiste entre deploys)
- **SNS signature validation** — webhook SES autenticado criptograficamente
- **100% en español** — UI y mensajes pensados para LATAM

## Planes

| Plan | Precio | Dominios | Aliases | Reglas | Logs |
|------|--------|----------|---------|--------|------|
| Basico | $99/mes | 1 | 10 | — | — |
| Pro | $299/mes | 5 | 20 | 20 | 15 dias |
| Agencia | $999/mes | 20 | 100 | 100 | 90 dias |

## Stack

- [Deno](https://deno.com) + [Elysia](https://elysiajs.com)
- Deno KV (persistencia)
- AWS SES (inbound/outbound email)
- AWS S3 (almacenamiento temporal de emails)
- MercadoPago (suscripciones)
- JWT auth con HttpOnly cookies

## Arquitectura

```
Email entrante → MX tudominio.com → SES inbound
  → S3 (almacena .eml, TTL 24h)
  → SNS → webhook → MailMask parsea → forwarding via SES outbound
```

## Estructura del proyecto

```
main.ts          — App Elysia, todos los endpoints (auth, domains, billing, webhooks)
auth.ts          — JWT + password hashing (PBKDF2)
db.ts            — Capa de datos con Deno KV + definicion de planes
ses.ts           — Integracion AWS SES/S3
forwarding.ts    — Procesamiento de email inbound
rate-limit.ts    — Rate limiting con Deno KV
public/          — Frontend (HTML + vanilla JS)
```

## API

### Auth
| Metodo | Ruta | Descripcion |
|--------|------|-------------|
| `POST` | `/api/auth/register` | Crear cuenta |
| `POST` | `/api/auth/login` | Login (JWT cookie) |
| `POST` | `/api/auth/logout` | Logout |
| `GET`  | `/api/auth/me` | Usuario actual |
| `GET`  | `/api/auth/verify-email` | Verificar email (token) |
| `POST` | `/api/auth/forgot-password` | Recuperar password |
| `POST` | `/api/auth/set-password` | Establecer nuevo password |

### Domains y aliases
| Metodo | Ruta | Descripcion |
|--------|------|-------------|
| `GET`  | `/api/domains` | Listar dominios |
| `POST` | `/api/domains` | Agregar dominio |
| `GET`  | `/api/domains/:id` | Detalle de dominio |
| `POST` | `/api/domains/:id/verify` | Verificar DNS |
| `DELETE`| `/api/domains/:id` | Eliminar dominio |
| `GET`  | `/api/domains/:id/aliases` | Listar aliases |
| `POST` | `/api/domains/:id/aliases` | Crear alias |
| `PUT`  | `/api/domains/:id/aliases/:alias` | Actualizar alias |
| `DELETE`| `/api/domains/:id/aliases/:alias` | Eliminar alias |

### Reglas y logs
| Metodo | Ruta | Descripcion |
|--------|------|-------------|
| `GET`  | `/api/domains/:id/rules` | Listar reglas |
| `POST` | `/api/domains/:id/rules` | Crear regla |
| `DELETE`| `/api/domains/:id/rules/:ruleId` | Eliminar regla |
| `GET`  | `/api/domains/:id/logs` | Ver logs de emails |

### Billing
| Metodo | Ruta | Descripcion |
|--------|------|-------------|
| `POST` | `/api/billing/guest-checkout` | Checkout sin cuenta |
| `POST` | `/api/billing/checkout` | Checkout autenticado |
| `POST` | `/api/billing/cancel` | Cancelar suscripcion |
| `GET`  | `/api/billing/status` | Estado de suscripcion |
| `POST` | `/api/webhooks/mercadopago` | Webhook de MP |

### Webhooks
| Metodo | Ruta | Descripcion |
|--------|------|-------------|
| `POST` | `/api/webhooks/ses-inbound` | Webhook de SES/SNS |

## Quickstart

```bash
git clone https://github.com/blissito/mailmask.git
cd mailmask
cp .env.example .env  # editar variables
deno task dev          # http://localhost:8000
deno task test
```

## Deploy

Deployado en [Deno Deploy](https://dash.deno.com). Push a `main` triggerea deploy automatico.

---

Hecho con cafe por [**@blissito**](https://github.com/blissito)

[fixtergeek.com](https://www.fixtergeek.com) | [formmy.app](https://formmy.app)
