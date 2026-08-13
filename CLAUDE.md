# CLAUDE.md

## Project overview
MailMask — email alias/forwarding service. Elysia monolith with SQLite, AWS SES/S3, MercadoPago billing.

## Commands
```bash
npm run dev       # Run dev server on :8000 (tsx --watch)
npm test          # Run tests (tsx --test)
```

## SDK (`sdk/`)
When any file inside `sdk/` is modified: bump the version (`npm version patch` in `sdk/`), build, and publish to npm:
```bash
cd sdk && npm version patch --no-git-tag-version && npm run build && npm publish --access public
```
Package: `@easybits.cloud/mailmask` on npm.

## AWS S3 Buckets
These buckets must exist before the app works correctly. Create them manually if they don't exist:
```bash
aws s3 mb s3://mailmask-inbound --region us-east-1   # Inbound email storage (SES writes here)
aws s3 mb s3://mailmask-backups --region us-east-1   # Daily DB backups (cron + admin panel)
```
Override with env vars `S3_BUCKET` and `S3_BACKUP_BUCKET` respectively.

## Docs & Formmy Agent
- Public docs page: `public/docs.html` (SDK, API, SMTP, MCP — serves as both user-facing docs AND source for AI agent knowledge base)
- Formmy host: **`https://www.formmy.app`** — el apex `formmy.app` no tiene certificado TLS, nunca usarlo como `baseUrl`
- Formmy agent setup: `scripts/setup-agent.ts` (persona, instructions)
- Formmy docs upload: `scripts/upload-docs.ts` (extracts sections from docs.html + EXTRA_DOCS, uploads as RAG documents)
- After editing `public/docs.html` or `EXTRA_DOCS` in upload script, re-run: `FORMMY_SECRET_KEY=sk_live_xxx npx tsx scripts/upload-docs.ts`
- Chat widget: `public/js/docs-chat.tsx` → build with `npm run build:chat`

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
- **Add-ons**: `ADDONS` en `db.ts` (`sends25` $49, `sends100` $99, `domain` $99 c/u). Tabla `addons`, preapproval propio de MP con `external_reference: "addon:{id}"`. `getUserPlanLimits()` los suma; `sendsUnlocked` es el flag que decide si se puede enviar. **Básico tiene `sends: 0`**: no envía correo nuevo sin add-on, pero sí responde desde la Bandeja (`mesaActions: true` para todos los planes).
- **Límites**: se cuentan **por dominio**, no por cuenta (`getSendCount()` y el rate limit de forwarding se llavean con `domainId`). Son dos distintos: `sends` (saliente que origina el usuario, por día) y `forwardPerHour` (reenvío de entrada, el caso de uso principal, un orden de magnitud mayor). Falta un tope mensual — ver `monthlyForwards` en el backlog, pendiente de revisitar.
- **Migraciones**: el snapshot de drizzle está desincronizado respecto a `api_keys` (el hash se aplicó con `scripts/migrate-api-keys-hash.ts`, fuera de drizzle). `drizzle-kit generate` pedirá input interactivo y quiere emitir un `ALTER TABLE api_keys` que **rompería producción**. Hasta que se reconcilie, escribe las migraciones a mano en `drizzle/` y agrégalas a `meta/_journal.json`.

## Billing
- MercadoPago PreApproval API for subscriptions
- Two checkout flows: guest (no account) and authenticated
- Guest checkout creates a pending-checkout token with 24h TTL
- MP webhook (`/api/webhooks/mercadopago`) handles payment notifications with HMAC validation
- Known: `payer_email` cannot match the MP collector account ("Payer and collector cannot be the same user")

## Add-ons y envío de correo nuevo (agosto 2026)

**Modelo comercial.** El plan Básico ($49) **no envía correo nuevo** (`sends: 0`); sí responde desde la Bandeja, que está incluida en todos los planes. Enviar se compra aparte:

| Concepto | Precio |
|---|---|
| Envíos 25/día | +$49 |
| Envíos 100/día | +$99 (excluyentes entre sí) |
| Dominio extra | +$99 c/u, acumulable |
| Freelancer | $449 · 15 dominios · 200 envíos/día |

La escalera está calculada para que el 5º dominio ($445) empate con Freelancer ($449) y el upgrade se venda solo. El add-on de envíos se compra una vez y aplica a todos los dominios; el tope cuenta **por dominio y por día**.

**Cómo se envía.** Tres caminos, todos con tope: `POST /api/domains/:id/send` (unitario), `/send-bulk` (job asíncrono) y `POST /api/bandeja/conversations` (redactar desde la UI, botón "Redactar" o tecla `c`). Responder en la Bandeja **no** consume cuota — tiene su propio tope de abuso de 200/hora por dominio.

**Dos cosas no obvias del código:**
- Las conversaciones guardan `from` = contacto externo y `to` = nuestro alias, **también al redactar**. La lista, el filtro de alias y el remitente del reply dependen de esa convención invertida.
- El `Message-ID` lo genera `sendFromDomain` y se guarda en `threadReferences`; es lo que engancha la respuesta del contacto. **SES podría reescribirlo** — sin verificar. Ver `VIGILAR-BRENDI.md`.

**Cobro.** PreApproval propio por add-on con `external_reference: "addon:{id}"`, atendido en una rama temprana del webhook que sale con `return` antes de la detección de plan. Es obligatorio: el add-on de $49 vale lo mismo que el plan básico y el fallback por monto lo activaría como plan.

**Sin verificar en producción** (ver `VIGILAR-BRENDI.md`): la compra real en MercadoPago y el threading de punta a punta.

## TODO

### Crítico — bloquea lanzamiento público
- [x] ~~**Link de activar cuenta no sirve**~~: corregido JSON encoding de tokens, agregado endpoint resend-verification y banner en dashboard.
- [x] ~~**Hardcodear KV database URL**~~: migrado a SQLite.
- [x] ~~**Monitoreo/alerting**~~: deprioritized — equipo trabaja diario en el sitio, no se hará este año.
- [x] ~~**Retry en forwarding**~~: resuelto.
- [x] ~~**Revisar `cron.ts`**~~: resuelto.

### Hardening — detectado en auditoría pre-beta
- [x] ~~**Global error handler**~~: `.onError()` en Elysia + `process.on('uncaughtException'/'unhandledRejection')` agregados.
- [x] ~~**Ignorar spam/virus de SES**~~: `processInbound` rechaza emails con `spamVerdict`/`virusVerdict` FAIL antes de procesar.
- [x] ~~**Sanitizar `fromLocal` en `/api/domains/:id/send`**~~: SES valida headers, no requiere sanitización adicional.
- [x] ~~**Validar email en registro**~~: regex básica agregada.
- [x] ~~**Índices faltantes en DB**~~: 5 índices agregados en `schema.ts`. Se crean con `drizzle-kit push`.
- [x] ~~**Race condition de cupón**~~: `markCouponUsed()` ya se llama después de `preApproval.create()` exitoso.
- [x] ~~**Rate limit en checkout y cupones**~~: rate limit agregado a `/api/billing/checkout` (5/min) y `/api/coupons/:code` (10/min).
- [x] ~~**Default de `SES_RULE_SET`**~~: se mantiene `"formmy-email-forwarding"` como nombre permanente.
- [x] ~~**Sanitizar filename de attachments**~~: strip de control chars en parsing MIME y en Content-Disposition de response.
- [x] ~~**Validar recipients en bulk send**~~: validación con regex antes de enviar a SES.
- [x] ~~**Separar bucket de backups**~~: fallback cambiado a `"mailmask-backups"`.
- [x] ~~**Agregar HSTS header**~~: agregado en `onAfterHandle`.

### 🌱 Etapa Vegetativa — marzo/abril 2026
Objetivo: solidificar el tronco del servicio. Blindar seguridad, rendimiento y resiliencia. Condición de olimpiadas.

- [x] ~~**CSRF protection**~~: Double-submit cookie pattern. CSRF token en cookie no-HttpOnly + header X-CSRF-Token. Skip para webhooks (HMAC), Bearer auth, y endpoints de entrada.
- [x] ~~**Content-Security-Policy header**~~: CSP estricto ya aplicado en `onAfterHandle`.
- [x] ~~**Auditar API keys**~~: Keys hasheadas con SHA-256, `keyPrefix` para identificación, rate limit 60 req/min por key. Migration script: `scripts/migrate-api-keys-hash.ts`.
- [x] ~~**Auditar SMTP relay**~~: Auditado — plan-gated (developer), domain-scoped IAM, admin-only credentials, IAM cleanup on revoke. SES rate limits per IAM user.
- [ ] **S3 bucket permissions**: Verificar que no hay acceso público, policies mínimas
- [ ] **JWT secret rotation**: Estrategia de rotación de secretos sin invalidar sesiones activas
- [x] ~~**Security headers completos**~~: HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CSP — todos en `onAfterHandle`.
- [x] ~~**Dependency audit**~~: Solo esbuild en drizzle-kit (dev dependency, moderate, no afecta producción). Sin vulnerabilidades en runtime.
- [x] ~~**Input validation audit**~~: Blog slug path traversal fix, parseInt radix explícito. Drizzle ORM previene SQLi, SSRF protection en webhooks, filenames sanitizados.
- [x] ~~**Rate limiting audit**~~: Agregado rate limit a send (20/min), send-bulk (5/min), bandeja reply (20/min), alias create (20/min), agents invite (10/min), api-keys create (5/min), billing cancel (3/min), smtp-credentials create (5/min). Login, register, forgot-password, checkout ya tenían.
- [x] ~~**Error handling audit**~~: `onError` global no filtra stack traces, devuelve "Error interno" genérico. `String(error)` solo va a logs internos.
- [x] ~~**Respaldos reales**~~: Resuelto 29-jul-2026. `backup.ts` hace `runDbBackup()`: `VACUUM INTO` (snapshot consistente que sí incluye el WAL), verificación con `integrity_check` + conteo de tablas antes de subir, gzip nivel 9 y upload a `s3://mailmask-backups/backups/mailmask-db-<ISO>.sqlite.gz`. Retención de 7 por familia de respaldo. Los JSON de 3.2 KB anteriores solo cubrían 4 de 22 tablas y omitían los DKIM tokens; fueron borrados de S3 (copia en `~/mailmask-backups-legacy/`). **Drill de restauración ejecutado y verificado**: 23 tablas, `integrity_check` ok, alias con destinos, suscripciones y DKIM tokens presentes.
- [x] ~~**Chat de docs roto**~~: Resuelto 29-jul-2026. El apex `formmy.app` no presenta certificado TLS (handshake sin peer cert), así que todo `fetch` del SDK moría con `Failed to fetch`. **Formmy usa `www` como host principal.** `baseUrl` cambiado a `https://www.formmy.app` en `docs-chat.tsx`, `scripts/upload-docs.ts` y `scripts/setup-agent.ts`; CSP `connect-src` actualizado. Base de conocimiento re-subida (18 docs). Pendiente aparte: el bundle pesa 10.3 MB (shiki + streamdown, build sin `NODE_ENV=production`).
- [ ] **Deploy sin downtime**: SQLite en un volumen único obliga a parar la máquina vieja antes de arrancar la nueva. Evaluar LiteFS o migrar a Postgres para tener 2+ máquinas.
- [ ] **Load testing**: Benchmarks de rendimiento bajo carga (forwarding, API, bandeja)
- [ ] **Logging & observability**: Structured logging para debugging en producción sin exponer datos sensibles

### Alto — primeras semanas
- [x] ~~Pagina de pricing publica en landing~~: `/pricing` standalone + sección en landing con smooth scroll.
- [x] ~~Agregar endpoint PUT para editar reglas~~: `PUT /api/domains/:id/rules/:ruleId` con validación completa.
- [x] ~~Dashboard: mostrar uso actual vs limites del plan~~: reglas y envíos por dominio en `/api/auth/me` + renderUsage().
- [x] ~~Email de confirmación de pago para usuarios autenticados~~: ya implementado.

### Medio — primer mes
- [x] ~~Tests: cubrir forwarding y webhook billing~~: edge cases cubiertos — rate limiting, S3 failure retry, multi-recipient, webhook rules, SNS confirmation, renewal extension, plan from `reason` fallback.
- [x] ~~**SSE en Bandeja**~~: Server-Sent Events implementado para actualización en tiempo real de la bandeja.
- [ ] **Upgrade/downgrade de plan**: MP PreApproval no soporta mutación. Implementar flujo de cancelar suscripción actual + crear nueva con plan diferente. Considerar: prorrateo del período actual, transición sin interrupción de servicio, UX de selección de plan desde dashboard.
- [ ] **Transferencia de dominios (transfer-in)**: Automatizar transferencia de dominios desde otros registradores a MailMask vía `route53domains:TransferDomain`. Flujo: usuario ingresa dominio + auth code (EPP), se inicia transferencia, cron monitorea estado (`GetOperationDetail`), al completar configura DNS automáticamente. Costo AWS igual a registro (~$13 USD .com). UX: botón en modal de agregar dominio (actualmente deshabilitado con "Próximamente").
- [ ] **Transferencia de dominios (transfer-out)**: Permitir que usuarios transfieran sus dominios fuera de MailMask. Flujo: `DisableDomainTransferLock` → `RetrieveDomainAuthCode` → mostrar auth code al usuario para que lo use en su nuevo registrador. UX: botón en settings del dominio (solo para dominios `registeredViaMailmask`).
- [ ] Logs centralizados: se migrará a solución propia cuando esté lista.
- [ ] Backup/export de datos de usuario (aliases, reglas)
- [ ] **Email de "certificado" al verificar dominio**: Cuando un dominio pasa a verificado (DNS confirmado), enviar email estilo AWS Health Event — diseño tipo certificado/notificación con: nombre del dominio, región/fecha, estado DKIM/MX, badge de "verificado", CTA al dashboard. Inspirado en las notificaciones de AWS SES DKIM_PENDING_TO_VERIFIED. Pendiente: detectar el momento exacto de verificación (¿cron de chequeo DNS? ¿webhook SES?).
- [x] ~~Notificaciones por email cuando un alias recibe su primer email~~
- [x] ~~Soporte para multiple destinatarios en un alias~~
- [ ] **Definir estrategia de historial/almacenamiento**: retención por plan (15-30 días basico/freelancer, ilimitado developer), flush automático, add-on de almacenamiento, UI de uso. Diferenciador clave vs competencia — discutir antes de implementar.
- [ ] **Configurar SES multi-tenancy y estrategia de reputación**: Sesión de investigación para definir arquitectura de tenants SES, configuration sets por dominio, políticas de envío (Standard vs Strict), métricas de reputación a monitorear, y plan de acción para aislar dominios de clientes. Estudiar docs de SES Tenants, VDM, y EventBridge antes de implementar.
- [ ] Evaluar pattern de almacenamiento de mensajes en Bandeja: ¿leer body de S3 on demand vs duplicar en SQLite? Investigar otros patterns (cache intermedio, pre-procesado a formato ligero, CDN/signed URLs). Concluir cuál es el mejor approach antes de implementar.
- [ ] **Radar de Actividad por Alias**: Dashboard analítico por alias — volumen de emails por día/semana, horas pico, ratio legítimo vs marketing/spam, aliases "muertos" (30+ días sin actividad) con sugerencia de desactivarlos. Layer de IA (via formmy.app) que genera resumen semanal en lenguaje natural ("Tu alias newsletter@ recibió 47 emails esta semana, 82% son marketing — considera desactivarlo"). El 90% son queries SQL sobre datos existentes (logs/mensajes), la IA solo genera el resumen. Email semanal via SES con cron. Implementación: 3-4 días. Disponible en todos los planes como feature de retención.

### Contenido / Educación

- [ ] **Auditoría de riqueza visual del blog**: los 24 posts son **texto plano** — cero `<img>` y cero `<svg>` en el cuerpo, solo 3 tienen tabla. Los JPG de `blog/img/` existen únicamente para la tarjeta de compartir; el lector nunca los ve. Falta pasada de enriquecimiento: diagramas, ilustraciones, SVG animados, comparativas en tabla, bloques de código donde aplique. Pendiente de agendar.
- **Estándar para posts nuevos** (aplicar desde ya, no esperar a la auditoría): cada post nace con al menos un diagrama o ilustración original en el cuerpo — SVG inline, no stock. SVG porque escala, pesa poco, se adapta al tema oscuro y se puede animar. Además, formato pensado para motores generativos (GEO): 4-8 `<h2>`, cada uno respondiendo **una** pregunta completa sin depender del contexto anterior, con la respuesta directa en la primera oración y párrafos de 2-3 líneas. Eso es lo que citan los buscadores con IA.
- [ ] **Guías de automatización con IA + aliases**: Blog posts y/o sección educativa enseñando a usuarios a automatizar workflows usando aliases específicos de MailMask + herramientas de IA. Ejemplos: alias dedicado para recibir notificaciones de n8n/Make/Zapier, alias como trigger de workflows AI, alias para clasificación automática de leads, alias temporal para campañas con análisis automático. Doble propósito: educar usuarios existentes y atraer audiencia técnica vía SEO. Investigar y documentar patrones concretos antes de escribir.

### Backlog (priorizado)
0. [ ] **`monthlyForwards` — tope mensual para proteger margen. ⚠️ REVISITAR PARA ENTENDERLO MEJOR ANTES DE IMPLEMENTAR.**

   No implementar todavía. Primero hay que sentarse a entender el modelo de costo con números reales; lo de abajo es el planteamiento, no una decisión.

   **El problema.** A AWS se le paga por correo procesado; al cliente se le cobra una cuota fija al mes. Hoy el único freno es `forwardPerHour` (100/500/2000 por dominio en `PLANS`, aplicado en `forwarding.ts:462` con `checkRateLimit`). Un límite por hora frena un pico pero no acota un total: 2,000/hora sostenidas son ~1.4M de correos al mes de un cliente que paga $999 MXN. El de por hora protege el sistema; falta el que protege el margen.

   **La idea.** Agregar `monthlyForwards` a `PLANS` y contar por mes además de por hora. Ojo: los límites son **por dominio** (`getSendCount()` y el rate limit de forwarding se llavean con `domainId`), así que hay que decidir si el tope mensual es por dominio o por cuenta — no es lo mismo con 20 dominios.

   **Lo que falta entender antes de tocar código:**
   - Costo real por correo (SES inbound + S3 PUT + almacenamiento + SES outbound del reenvío). Hoy nadie lo tiene medido.
   - Margen objetivo por plan, y con eso derivar el tope en vez de inventar un número redondo.
   - Qué pasa al toparse: ¿se descarta el correo (se pierde correo del cliente, grave), se encola, se degrada, o se cobra excedente? Hoy `forwarding.ts` descarta y manda alerta.
   - Cómo se avisa antes de llegar: sin aviso previo, un tope mensual es una sorpresa desagradable a mitad de mes.
   - Interacción con el add-on de almacenamiento y con la retención por plan, que también están sin definir.

   **No es urgente**: con el volumen actual nadie se acerca. Importa antes de tener volumen, porque el consumo que abusa llega antes de lo esperado. Relacionado: SES Tenants (abajo) y la estrategia de historial/almacenamiento.

1. [ ] **SES Tenants + aislamiento de reputación**: Implementar SES Tenants (feature de agosto 2025) para aislar reputación por dominio de cliente. 1 tenant por dominio, política Standard para Básico/Freelancer, Strict para Developer. Managed Dedicated IPs para tiers de pago (auto-scaling, sin warmup manual). EventBridge para recibir eventos de cambio de estado/reputación y pausar forwarding automáticamente. Evaluar VDM (Virtual Deliverability Manager) para dashboard de entregabilidad por config set. Relacionado: **`monthlyForwards`** (ver abajo).
- [x] ~~**SMTP relay**~~: Implementado. Credenciales SMTP para enviar desde código/SaaS (no clientes de correo). Solo plan Developer. IAM user por credencial con policy scoped al dominio.
- [ ] **IMAP/POP (Dovecot)**: Integrar Dovecot open source (basado en ForwardEmail) para ofrecer servidor de entrada completo. Permitiría configurar clientes de correo (Apple Mail, Outlook, Thunderbird) con recepción + envío. Proyecto separado a futuro, no incluir en marketing actual.
- [ ] Probar checkout autenticado con email diferente al collector de MP
2. [ ] **SDK**: Cliente JS/TS para consumir la API de MailMask (crear aliases, listar dominios, etc.). Publicar en npm. Disponible desde plan Developer.
3. [ ] **Webhooks**: Permitir registrar URLs para recibir eventos (email recibido, alias creado, etc.). UI para gestionar webhooks por dominio, endpoint de registro, sistema de delivery con reintentos. Disponible desde plan Developer.
- [ ] **Flush de historial / almacenamiento**: Basico/Freelancer tienen franja de 15-30 días de retención, después se hace flush automático. Developer incluye almacenamiento base para conservar todo su historial, y puede comprar más cuando se acabe (add-on por GB o por bloque). Definir: UI para ver uso de almacenamiento, alerta cuando se acerca al límite, flujo de compra de almacenamiento adicional, export antes de flush. Investigar costos S3/Postgres para pricing. **Nota competitiva:** Ningún competidor directo (SimpleLogin, ImprovMX, ForwardEmail, addy.io) almacena contenido de emails ni ofrece historial — todos son forwarding puro sin retención. Bandeja + historial persistente es diferenciador único que posiciona a MailMask más cerca de Helpscout/Intercom pero a fracción del costo y con máscaras incluidas. El almacenamiento como add-on es feature sin competencia en el segmento.
- [x] ~~**Blog**~~: 12 posts SEO publicados + index + blog.css integrado en landing.
- [ ] **Calculadora interactiva (lead magnet)**: Página pública con sliders/range inputs donde el usuario calcula cuánto ahorra vs Google Workspace según número de usuarios, dominios y buzones. Muestra comparativa de costo mensual/anual y CTA a registro. Funciona como lead magnet para SEO y compartir en redes.
- [ ] **Campaña "dominio gratis"**: Diseñar y ejecutar campaña de marketing aprovechando el feature de registro de dominio integrado. Definir: oferta (dominio gratis primer año con plan X, etc.), landing page dedicada, copy para email/redes, segmento objetivo, métricas de éxito. Coordinar con implementación de registro de dominios (Route 53).
- [x] ~~**Schema markup (structured data)**: Agregar JSON-LD a landing, blog y páginas clave para SEO. Schemas: Organization, Product, FAQPage, BlogPosting, BreadcrumbList, SoftwareApplication, ItemList. Mejora visibilidad en Google y rich snippets.~~
- [ ] **pgvector + RAG**: Habilitar extensión `pgvector` en Postgres, agregar columnas `embedding vector(1536)` a mensajes/conversaciones. Implementar pipeline de embedding (OpenAI/Anthropic) al recibir emails y búsqueda semántica en Bandeja. Verificar soporte en hosting (Neon/Supabase soportan pgvector). Caso de uso: buscar conversaciones por contexto, respuestas sugeridas, knowledge base por dominio.
- [ ] **Bandeja: asignar con select de team**: Cambiar input de email en modal de asignar por `<select>` que liste agentes del dominio (ya existe `GET /api/domains/:id/agents`).
4. [ ] **Members y permisos por dominio**: UI completa para invitar miembros a un dominio, asignar roles (owner, editor, viewer), gestionar permisos. Incluye: modelo de datos (tabla members/invitations), endpoints CRUD, UI en dashboard para listar/invitar/remover miembros, control de acceso en todos los endpoints de dominio según rol. **Pendiente definir**: qué pueden ver los members (aliases, reglas, logs, bandeja), cómo se comparten dominios (invitación por email, link), qué ve un member en su dashboard cuando tiene acceso a dominios de otros usuarios.
5. [ ] **Registro de dominios integrado (Route 53)**: El usuario busca, paga y tiene dominio+email funcionando sin configurar nada. Flujo: (1) búsqueda de disponibilidad via `route53domains:CheckDomainAvailability`, (2) pago via MercadoPago (cargo anual separado de suscripción), (3) registro via `route53domains:RegisterDomain` con contacto del usuario, (4) configuración DNS automática en hosted zone — MX apuntando a SES inbound, TXT de verificación, CNAMEs de DKIM — via `route53:ChangeResourceRecordSets`, (5) verificación SES automática del dominio. SDKs: `@aws-sdk/client-route-53` + `@aws-sdk/client-route-53-domains`. UI: buscador de dominio en dashboard con precios por TLD, estado de registro, renovación automática. Billing: cargo anual por dominio (~$12-14 USD .com) cobrado como producto separado en MP o incluido en planes altos. Modelo DB: tabla `domain_registrations` (domainId, route53OperationId, registeredAt, expiresAt, autoRenew, contactInfo). **Diferenciador clave**: ningún competidor (SimpleLogin, ImprovMX, ForwardEmail, addy.io) ofrece registro+configuración integrada — todos requieren que el usuario vaya a su registrador y configure DNS manualmente. Esto convierte a MailMask en solución "todo en uno" para email profesional.
