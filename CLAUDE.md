# CLAUDE.md

## Project overview
MailMask — email alias/forwarding service. Elysia monolith with SQLite, AWS SES/S3, MercadoPago billing.

## Commands
```bash
deno task dev     # Run dev server on :8000
deno task test    # Run tests
```

## Architecture
- Single-file API server (`main.ts`) with all routes
- No framework router separation — everything is chained `.get()/.post()` on one Elysia instance
- Frontend is vanilla HTML + JS in `public/`
- SQLite for all persistence (users, domains, aliases, rules, logs, rate limits)
- JWT auth via HttpOnly cookies (`auth.ts`)

## Key files
| File | Purpose |
|------|---------|
| `main.ts` | All API endpoints, static file serving, middleware |
| `auth.ts` | JWT creation/verification, PBKDF2 password hashing |
| `db.ts` | SQLite data layer, plan definitions, all CRUD |
| `ses.ts` | AWS SES send email, S3 fetch |
| `forwarding.ts` | Inbound email parsing and forwarding logic |
| `rate-limit.ts` | Persistent rate limiting with SQLite |
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
- [x] ~~**Hardcodear KV database URL**~~: migrado a SQLite.
- [x] ~~**Monitoreo/alerting**~~: deprioritized — equipo trabaja diario en el sitio, no se hará este año.
- [x] ~~**Retry en forwarding**~~: resuelto.
- [x] ~~**Revisar `cron.ts`**~~: resuelto.

### Alto — primeras semanas
- [x] ~~Pagina de pricing publica en landing~~: `/pricing` standalone + sección en landing con smooth scroll.
- [x] ~~Agregar endpoint PUT para editar reglas~~: `PUT /api/domains/:id/rules/:ruleId` con validación completa.
- [x] ~~Dashboard: mostrar uso actual vs limites del plan~~: reglas y envíos por dominio en `/api/auth/me` + renderUsage().
- [x] ~~Email de confirmación de pago para usuarios autenticados~~: ya implementado.

### Medio — primer mes
- [ ] Tests: cubrir forwarding y webhook billing. (no urgente por ahora)
- [ ] Logs centralizados: se migrará a solución propia cuando esté lista.
- [ ] Backup/export de datos de usuario (aliases, reglas)
- [ ] **Email de "certificado" al verificar dominio**: Cuando un dominio pasa a verificado (DNS confirmado), enviar email estilo AWS Health Event — diseño tipo certificado/notificación con: nombre del dominio, región/fecha, estado DKIM/MX, badge de "verificado", CTA al dashboard. Inspirado en las notificaciones de AWS SES DKIM_PENDING_TO_VERIFIED. Pendiente: detectar el momento exacto de verificación (¿cron de chequeo DNS? ¿webhook SES?).
- [x] ~~Notificaciones por email cuando un alias recibe su primer email~~
- [x] ~~Soporte para multiple destinatarios en un alias~~
- [ ] **Definir estrategia de historial/almacenamiento**: retención por plan (15-30 días basico/freelancer, ilimitado developer), flush automático, add-on de almacenamiento, UI de uso. Diferenciador clave vs competencia — discutir antes de implementar.
- [ ] Evaluar pattern de almacenamiento de mensajes en Bandeja: ¿leer body de S3 on demand vs duplicar en SQLite? Investigar otros patterns (cache intermedio, pre-procesado a formato ligero, CDN/signed URLs). Concluir cuál es el mejor approach antes de implementar.

### Contenido / Educación
- [ ] **Guías de automatización con IA + aliases**: Blog posts y/o sección educativa enseñando a usuarios a automatizar workflows usando aliases específicos de MailMask + herramientas de IA. Ejemplos: alias dedicado para recibir notificaciones de n8n/Make/Zapier, alias como trigger de workflows AI, alias para clasificación automática de leads, alias temporal para campañas con análisis automático. Doble propósito: educar usuarios existentes y atraer audiencia técnica vía SEO. Investigar y documentar patrones concretos antes de escribir.

### Backlog
- [ ] **SES Tenants + aislamiento de reputación**: Implementar SES Tenants (feature de agosto 2025) para aislar reputación por dominio de cliente. 1 tenant por dominio, política Standard para Básico/Freelancer, Strict para Developer. Managed Dedicated IPs para tiers de pago (auto-scaling, sin warmup manual). EventBridge para recibir eventos de cambio de estado/reputación y pausar forwarding automáticamente. Evaluar VDM (Virtual Deliverability Manager) para dashboard de entregabilidad por config set. También agregar `monthlyForwards` a PLANS para limitar emails procesados por mes y proteger margen (hoy solo existe `forwardPerHour`).
- [x] ~~**SMTP relay**~~: Implementado. Credenciales SMTP para enviar desde código/SaaS (no clientes de correo). Solo plan Developer. IAM user por credencial con policy scoped al dominio.
- [ ] **IMAP/POP (Dovecot)**: Integrar Dovecot open source (basado en ForwardEmail) para ofrecer servidor de entrada completo. Permitiría configurar clientes de correo (Apple Mail, Outlook, Thunderbird) con recepción + envío. Proyecto separado a futuro, no incluir en marketing actual.
- [ ] Probar checkout autenticado con email diferente al collector de MP
- [ ] **SDK**: Cliente JS/TS para consumir la API de MailMask (crear aliases, listar dominios, etc.). Publicar en npm. Disponible desde plan Developer.
- [ ] **Webhooks**: Permitir registrar URLs para recibir eventos (email recibido, alias creado, etc.). UI para gestionar webhooks por dominio, endpoint de registro, sistema de delivery con reintentos. Disponible desde plan Developer.
- [ ] **Flush de historial / almacenamiento**: Basico/Freelancer tienen franja de 15-30 días de retención, después se hace flush automático. Developer incluye almacenamiento base para conservar todo su historial, y puede comprar más cuando se acabe (add-on por GB o por bloque). Definir: UI para ver uso de almacenamiento, alerta cuando se acerca al límite, flujo de compra de almacenamiento adicional, export antes de flush. Investigar costos S3/Postgres para pricing. **Nota competitiva:** Ningún competidor directo (SimpleLogin, ImprovMX, ForwardEmail, addy.io) almacena contenido de emails ni ofrece historial — todos son forwarding puro sin retención. Bandeja + historial persistente es diferenciador único que posiciona a MailMask más cerca de Helpscout/Intercom pero a fracción del costo y con máscaras incluidas. El almacenamiento como add-on es feature sin competencia en el segmento.
- [~] **Blog** *(parcial)*: 3 posts publicados + index + blog.css integrado en landing. Posts: email profesional sin Google Workspace, reenviar emails de dominio a Gmail, gestionar emails de dominio en equipo. Faltan ~9 posts SEO adicionales del plan original.
- [ ] **Calculadora interactiva (lead magnet)**: Página pública con sliders/range inputs donde el usuario calcula cuánto ahorra vs Google Workspace según número de usuarios, dominios y buzones. Muestra comparativa de costo mensual/anual y CTA a registro. Funciona como lead magnet para SEO y compartir en redes.
- [ ] **Campaña "dominio gratis"**: Diseñar y ejecutar campaña de marketing aprovechando el feature de registro de dominio integrado. Definir: oferta (dominio gratis primer año con plan X, etc.), landing page dedicada, copy para email/redes, segmento objetivo, métricas de éxito. Coordinar con implementación de registro de dominios (Route 53).
- [ ] **Schema markup (structured data)**: Agregar JSON-LD a landing, blog y páginas clave para SEO. Schemas: Organization, Product, FAQPage, BlogPosting, BreadcrumbList. Mejora visibilidad en Google y rich snippets.
- [ ] **pgvector + RAG**: Habilitar extensión `pgvector` en Postgres, agregar columnas `embedding vector(1536)` a mensajes/conversaciones. Implementar pipeline de embedding (OpenAI/Anthropic) al recibir emails y búsqueda semántica en Bandeja. Verificar soporte en hosting (Neon/Supabase soportan pgvector). Caso de uso: buscar conversaciones por contexto, respuestas sugeridas, knowledge base por dominio.
- [ ] **Bandeja: asignar con select de team**: Cambiar input de email en modal de asignar por `<select>` que liste agentes del dominio (ya existe `GET /api/domains/:id/agents`).
- [ ] **Members y permisos por dominio**: UI completa para invitar miembros a un dominio, asignar roles (owner, editor, viewer), gestionar permisos. Incluye: modelo de datos (tabla members/invitations), endpoints CRUD, UI en dashboard para listar/invitar/remover miembros, control de acceso en todos los endpoints de dominio según rol. **Pendiente definir**: qué pueden ver los members (aliases, reglas, logs, bandeja), cómo se comparten dominios (invitación por email, link), qué ve un member en su dashboard cuando tiene acceso a dominios de otros usuarios.
- [ ] **Registro de dominios integrado (Route 53)**: El usuario busca, paga y tiene dominio+email funcionando sin configurar nada. Flujo: (1) búsqueda de disponibilidad via `route53domains:CheckDomainAvailability`, (2) pago via MercadoPago (cargo anual separado de suscripción), (3) registro via `route53domains:RegisterDomain` con contacto del usuario, (4) configuración DNS automática en hosted zone — MX apuntando a SES inbound, TXT de verificación, CNAMEs de DKIM — via `route53:ChangeResourceRecordSets`, (5) verificación SES automática del dominio. SDKs: `@aws-sdk/client-route-53` + `@aws-sdk/client-route-53-domains`. UI: buscador de dominio en dashboard con precios por TLD, estado de registro, renovación automática. Billing: cargo anual por dominio (~$12-14 USD .com) cobrado como producto separado en MP o incluido en planes altos. Modelo DB: tabla `domain_registrations` (domainId, route53OperationId, registeredAt, expiresAt, autoRenew, contactInfo). **Diferenciador clave**: ningún competidor (SimpleLogin, ImprovMX, ForwardEmail, addy.io) ofrece registro+configuración integrada — todos requieren que el usuario vaya a su registrador y configure DNS manualmente. Esto convierte a MailMask en solución "todo en uno" para email profesional.
