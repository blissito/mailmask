# MailMask

**Email aliases y forwarding para proteger tu privacidad.** Crea direcciones como `yo@tudominio.com` que reenvian a tu email real. Desactiva cuando quieras.

## Features

- **Custom domains** — conecta tu propio dominio y crea aliases ilimitados
- **Catch-all** — captura todos los emails de tu dominio con un wildcard `*`
- **Reglas avanzadas** — filtra por remitente, asunto o destinatario con contains/equals/regex
- **Forwarding inteligente** — reenvio transparente via SES, conserva headers originales
- **Descarta spam** — reglas para descartar emails no deseados antes de que lleguen
- **Webhooks** — notifica a tu app cuando llega un email que matchea una regla
- **Rate limiting** — proteccion contra abuso integrada
- **100% en español** — UI y mensajes pensados para LATAM

## Stack

- [Deno](https://deno.com) + [Elysia](https://elysiajs.com)
- Deno KV (persistencia)
- AWS SES (inbound/outbound email)
- AWS S3 (almacenamiento temporal de emails)
- JWT auth con HttpOnly cookies

## Quickstart

```bash
# Clonar
git clone https://github.com/blissito/mailmask.git
cd mailmask

# Configurar
cp .env.example .env  # editar variables

# Correr
deno task dev          # http://localhost:8000

# Tests
deno task test
```

## API

| Metodo | Ruta | Descripcion |
|--------|------|-------------|
| `POST` | `/api/auth/register` | Crear cuenta |
| `POST` | `/api/auth/login` | Login (JWT cookie) |
| `POST` | `/api/domains` | Agregar dominio |
| `POST` | `/api/domains/:id/verify` | Verificar DNS |
| `POST` | `/api/domains/:id/aliases` | Crear alias |
| `POST` | `/api/domains/:id/rules` | Crear regla |
| `GET`  | `/api/domains/:id/logs` | Ver logs de emails |

## Infra

```
Email entrante → MX tudominio.com → SES inbound
  → S3 (almacena .eml, TTL 24h)
  → SNS → webhook → MailMask parsea → forwarding via SES outbound
```

## Deploy

Deployado en [Deno Deploy](https://dash.deno.com). Push a `main` triggerea deploy automatico.

---

Hecho con cafe por [**@blissito**](https://github.com/blissito)

[fixtergeek.com](https://www.fixtergeek.com) | [formmy.app](https://formmy.app)
