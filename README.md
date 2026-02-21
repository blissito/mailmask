# MailMask

Email profesional con tu dominio. Alias, forwarding y bandeja compartida — sin Google Workspace.

**[mailmask.studio](https://mailmask.studio)**

## Qué es

MailMask te permite recibir y gestionar emails con tu dominio propio. Configura aliases que reenvían a tu Gmail, Outlook o cualquier buzón existente. Ideal para freelancers, startups y equipos pequeños que quieren email profesional sin pagar Google Workspace.

## Features

- **Aliases ilimitados** — crea direcciones como hola@tudominio.com, soporte@tudominio.com
- **Forwarding** — reenvío automático a uno o múltiples destinatarios
- **Bandeja compartida** — asigna conversaciones a miembros del equipo, responde desde el dashboard
- **SMTP relay** — envía emails desde tu código o SaaS con credenciales SMTP (plan Developer)
- **RBAC por dominio** — roles owner, admin y agent con permisos granulares
- **Notificaciones** — aviso cuando un alias recibe su primer email
- **Blog integrado** — guías SEO sobre email profesional y forwarding
- **Checkout flexible** — suscripciones con MercadoPago (guest o autenticado)

## Planes

| Plan | Precio |
|------|--------|
| Básico | $49 MXN/mes |
| Freelancer | $449 MXN/mes |
| Developer | $1,499 MXN/mes |

## Stack

Deno + Elysia · SQLite · AWS SES/S3 · MercadoPago

## Setup

```bash
cp .env.example .env
deno task dev   # localhost:8000
deno task test
```

---

Hecho con 🚬🫁 por [@blissito](https://github.com/blissito) · [fixtergeek.com](https://www.fixtergeek.com)
