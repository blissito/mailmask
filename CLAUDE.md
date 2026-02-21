# CLAUDE.md

## Project overview
MailMask — email alias/forwarding service. Deno + Elysia monolith with Deno KV, AWS SES/S3, MercadoPago billing.

## Commands
```bash
deno task dev     # Run dev server on :8000
deno task test    # Run tests
```

## Architecture
- Single-file API server (`main.ts`) with all routes
- No framework router separation — everything is chained `.get()/.post()` on one Elysia instance
- Frontend is vanilla HTML + JS in `public/`
- Deno KV for all persistence (users, domains, aliases, rules, logs, rate limits)
- JWT auth via HttpOnly cookies (`auth.ts`)

## Key files
| File | Purpose |
|------|---------|
| `main.ts` | All API endpoints, static file serving, middleware |
| `auth.ts` | JWT creation/verification, PBKDF2 password hashing |
| `db.ts` | Deno KV data layer, plan definitions, all CRUD |
| `ses.ts` | AWS SES send email, S3 fetch |
| `forwarding.ts` | Inbound email parsing and forwarding logic |
| `rate-limit.ts` | Persistent rate limiting with Deno KV |
| `public/js/app.js` | Main frontend logic (dashboard, checkout, domains) |

## Conventions
- **Language**: Spanish for user-facing strings, English for code/comments
- **Validation**: Inline validation, only add zod if schemas are reused across endpoints
- **Error responses**: Always JSON `{ error: "message" }` with appropriate status code
- **Auth**: JWT in HttpOnly cookie named `token`, verified via `verifyJwt()` from `auth.ts`
- **Plans**: Defined in `db.ts` as `PLANS` constant (basico, freelancer, developer; legacy: pro, agencia)

## Billing
- MercadoPago PreApproval API for subscriptions
- Two checkout flows: guest (no account) and authenticated
- Guest checkout creates a pending-checkout token with 24h TTL
- MP webhook (`/api/webhooks/mercadopago`) handles payment notifications with HMAC validation
- Known: `payer_email` cannot match the MP collector account ("Payer and collector cannot be the same user")

## TODO

### Crítico — bloquea lanzamiento público
- [x] ~~**Link de activar cuenta no sirve**~~: corregido JSON encoding de tokens, agregado endpoint resend-verification y banner en dashboard.
- [x] ~~**Hardcodear KV database URL**~~: migrado a Postgres.
- [ ] **Monitoreo/alerting**: health check externo + alertas (email/Slack) en errores de forwarding. (deprioritized — no se hará este año)
- [x] ~~**Retry en forwarding**~~: resuelto.
- [x] ~~**Revisar `cron.ts`**~~: resuelto.

### Alto — primeras semanas
- [ ] Pagina de pricing publica en landing
- [ ] Agregar endpoint PUT para editar reglas
- [ ] Dashboard: mostrar uso actual vs limites del plan
- [ ] Email de confirmación de pago para usuarios autenticados (hoy solo guests reciben welcome email)

### Medio — primer mes
- [ ] Tests: no hay archivos de test. Cubrir al menos forwarding (Source rewrite, dedup) y webhook billing.
- [ ] Logs centralizados: todo va a `console.error`. Dificulta depurar problemas de un usuario específico en prod.
- [ ] Backup/export de datos de usuario (aliases, reglas)
- [ ] Notificaciones por email cuando un alias recibe su primer email
- [ ] Soporte para multiple destinatarios en un alias
- [ ] Evaluar pattern de almacenamiento de mensajes en Mesa: ¿leer body de S3 on demand vs duplicar en KV? Investigar otros patterns (cache intermedio, pre-procesado a formato ligero, CDN/signed URLs). Concluir cuál es el mejor approach antes de implementar.

### Backlog
- [ ] **SMTP relay**: Ofrecer credenciales SMTP para que usuarios envíen desde cualquier cliente (Gmail, Thunderbird). Dominio ya es identidad SES verificada, solo falta generar credenciales y endpoint de autenticación SMTP. Disponible desde plan Freelancer.
- [ ] Probar checkout autenticado con email diferente al collector de MP
- [ ] **SDK**: Cliente JS/TS para consumir la API de MailMask (crear aliases, listar dominios, etc.). Publicar en npm. Disponible desde plan Developer.
- [ ] **Webhooks**: Permitir registrar URLs para recibir eventos (email recibido, alias creado, etc.). UI para gestionar webhooks por dominio, endpoint de registro, sistema de delivery con reintentos. Disponible desde plan Developer.
- [ ] **Members y permisos por dominio**: UI completa para invitar miembros a un dominio, asignar roles (owner, editor, viewer), gestionar permisos. Incluye: modelo de datos (tabla members/invitations), endpoints CRUD, UI en dashboard para listar/invitar/remover miembros, control de acceso en todos los endpoints de dominio según rol.
