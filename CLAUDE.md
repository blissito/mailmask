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

**Antes de publicar, corre `npm test -- sdk.test.ts`.** Ese archivo ejercita el
SDK real contra la app real (in-process, vía el `fetch` inyectable de
`MailMaskConfig`) y es lo único que ata el cliente a las rutas del servidor.

Existe porque la 0.1.4 salió a npm rota de raíz y nadie lo notó por meses: los
cuatro métodos de `aliases.*` pegaban a `/aliases` cuando el servidor expone
`/alias` en singular, `bulkSend`/`bulkStatus` apuntaban a rutas inexistentes, y
`SendEmailInput` declaraba `fromLocal` cuando la ruta lee `from` — o sea que
**todo correo salía desde `noreply@` en silencio**, sin error. La suite vieja no
lo veía porque `integration.test.ts` pega a las rutas a mano, lo que justamente
enmascaraba el desajuste.

Al agregar un método al SDK, agrégale su caso en `sdk.test.ts`. Un test que sólo
comprueba "no es 404" ya vale: eso solo habría atrapado 6 de los 10 bugs.

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
- **Regex de usuario**: las reglas con `match: "regex"` pasan por `revisarPatron()` de `regex-guard.ts` al guardarse (POST y PUT de reglas), y el texto se acota con `acotarTexto()` antes de evaluarlo en `forwarding.ts`. Es la única defensa posible: en tiempo de evaluación no se puede interrumpir un `RegExp.test()` porque es síncrono — el `setTimeout` que había alrededor devolvía a los 20 s con un tope de 50 ms. Explicado para el público en `/blog/que-es-redos-expresiones-regulares`.
- **Recursos SES por dominio**: un dominio necesita tres cosas en SES —identidad, regla de recepción en el rule set y config set— y "verificado" sólo mira la identidad. Sin la regla, SES contesta `550 5.1.1 mailbox unavailable` a todo y MailMask no se entera. `ensureDomainInbound()` en `ses.ts` reconcilia base contra SES al arrancar y en `POST /api/domains/:id/verify`. Nació de brendago.design (sep-2026): el DELETE limpió SES, la fila revivió de un respaldo y la reparación manual de agosto sólo devolvió la identidad. El config set lleva además un **event destination** al tópico `SNS_OUTBOUND_TOPIC_ARN` (rebotes y quejas → `/api/webhooks/ses-events`, firmado igual que el de entrada); sin ese secret la lista de supresión no se alimenta nunca. `ensureConfigSetEventDestination()` rellena el destino en sets viejos.
- **Lista de supresión**: la alimenta el webhook de eventos (rebote `Permanent` y queja) y la consultan **los tres envíos del usuario y también el reenvío** (`doForward` en `forwarding.ts` descarta con `status: "discarded"` y lo anota en el log del dominio). Insistir a un buzón que rebotó Permanent daña la reputación del dominio en SES.
- **Tareas programadas**: nunca llames a `cron.schedule()` directo — usa `programar()` de `scheduler.ts`, que sólo agenda si el proceso arrancó `main.ts`. `node-cron` se re-agenda cada segundo, así que un solo `schedule` al importar un módulo dejaba vivo para siempre el proceso de pruebas. Eso obligaba a `--test-force-exit`, que truncaba el reporte: `npm test` decía 244 tests en una corrida y 293 en la siguiente, siempre en verde. Por la misma razón el `app.listen()` y las reparaciones de arranque de `main.ts` van bajo `esServidor`.

- **Migraciones**: el snapshot de drizzle sigue desincronizado respecto a `api_keys`. `drizzle-kit generate` pedirá input interactivo y quiere emitir un `ALTER TABLE api_keys` que **rompería producción**. Hasta que se reconcilie, escribe las migraciones a mano en `drizzle/` y agrégalas a `meta/_journal.json`.
- **`api_keys` se repara sola al arrancar** (`pg.ts`, justo después de `migrate()`). El paso de llaves en claro a SHA-256 se aplicó a producción con `scripts/migrate-api-keys-hash.ts`, un script suelto que nunca entró a las migraciones: por eso **toda base nueva —tests, dev, un despliegue limpio— nacía con la tabla vieja y `createApiKey` moría** con `no column named key_hash`. Producción funcionaba y nadie lo veía. La reparación es idempotente (sólo actúa si existe la columna `key`), conserva las llaves hasheándolas y no toca una base ya migrada. Va en código y no en un `.sql` porque hay bases en los dos estados y SQL no puede preguntar por una columna. El script suelto queda como referencia histórica.

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

### 🔥 Urgente — evaluar IMAP/POP
- [ ] **Cerrar el hueco de recepción: cuánto cuesta y si AWS lo resuelve.** Hoy MailMask envía por SMTP pero **no ofrece IMAP ni POP**, así que nadie puede usar Outlook o Apple Mail como cliente completo: el correo entrante sigue cayendo en el buzón al que se reenvía. La landing lo prometía mal y ya se corrigió, pero el hueco de producto sigue ahí y es lo que separa "capa de reenvío" de "email profesional de verdad".

  **WorkMail ya está descartado, con números** (agosto 2026): cuesta **$4 USD por usuario al mes** (≈$76 MXN, con 50 GB e IMAP incluidos). Un solo buzón cuesta más que todo el plan Básico ($49). Pero el problema de fondo no es el margen: **cobra por usuario**, que es justo el modelo contra el que se posiciona el producto entero ("Google cobra por persona, MailMask por dominio"). Adoptarlo obligaría a cobrar por persona y borraría el diferenciador.

  Y hay un choque técnico que lo vuelve casi imposible: **el MX de un dominio apunta a un solo lugar**. Hoy apunta a SES inbound, de donde salen el reenvío, las reglas y la Bandeja. Si WorkMail toma el MX, se cae todo el pipeline — habría que elegir por dominio: o Bandeja, o WorkMail.

  **Ruta recomendada: Stalwart** (no Dovecot). Servidor de correo en Rust, binario único, habla IMAP, JMAP, POP3 y SMTP. Lo decisivo para nosotros: **soporta S3 nativo como almacén de mensajes** — los cuerpos van a S3 y los metadatos a Postgres o SQLite —, así que el correo no vive en el disco de la caja de sandboxes, que es la objeción principal. Usa menos memoria que Dovecot y trae JMAP.

  **Primer paso: un spike de un día, no lanzarlo.** Levantar Stalwart contra el S3 que ya existe, mandar un correo y leerlo desde Apple Mail. Eso dice si la ruta sirve y cuánto cuesta de verdad. **Nada de marketing antes del spike.**

  Lo que el spike tiene que resolver antes de prometer nada:
  - **El MX: la recomendación es NO moverlo.** Si Stalwart recibe directo, tendría que hacer todo lo que hoy hace el pipeline —reglas, reenvío, Bandeja, spam y virus— y se pierden los veredictos que SES ya da gratis. La ruta incremental es que **SES siga recibiendo y Stalwart sea un destino más**: `forwarding.ts` ya tiene el mensaje crudo en S3, así que solo hay que agregar un paso que lo deposite en el buzón por LMTP o `IMAP APPEND`. Ventajas: no se toca nada de lo que funciona, es reversible (si Stalwart cae, el reenvío sigue), y se puede activar por dominio o por alias en vez de migrar de golpe. El costo es guardar el mensaje dos veces, que es lo barato aquí. Mover el MX solo tendría sentido para jubilar el reenvío por completo — otro producto, no el siguiente paso.
  - **Provisión de buzones**: hoy un alias es una fila que reenvía; con IMAP necesita cuenta, contraseña y almacenamiento. Es producto nuevo (altas, recuperación, qué pasa al borrar un alias).
  - TLS para el host de IMAP, protección contra fuerza bruta en un puerto expuesto, respaldo del almacén de metadatos.
  - **Precio**: cambia la estructura de costos, así que hay que decidir si es add-on, plan nuevo o incluido.
  - Carga de soporte: ofrecer IMAP implica atender configuraciones de clientes de correo.

  **Por qué importa más de lo que parece.** Hoy MailMask **no puede reemplazar a Google Workspace**: reenvía *hacia* Gmail, así que el cliente sigue dependiendo de Google. La landing compara contra Workspace pero lo que se vende es una capa encima de una cuenta que ya tienen. IMAP es lo que lo convierte en reemplazo de verdad. El mercado no es solo "quien usa Outlook": es quien se quiere ir de Google, quien lee en la app nativa del teléfono, y quien necesita offline.

  **La contra, para no sobrevalorarlo:** para agencias, freelancers y negocios chicos la Bandeja puede ser suficiente, y de hecho es mejor que un cliente de correo para trabajo en equipo (historial compartido, asignación, notas). Por eso el add-on debe ser **opcional y por dominio**, no incluido encareciendo a todos.

  **Referencia de mercado** (agosto 2026): **Migadu** valida el modelo — dominios y buzones ilimitados, cobra **solo por almacenamiento**: $19 USD/año por 5 GB hasta $990/año por 500 GB. Purelymail: $10 USD/año plano + $0.56/GB extra. Fastmail: $60 USD/año **por persona**. Zoho: ~$1 USD/usuario/mes, y **su plan gratis no incluye IMAP** — el mercado ya lo trata como algo de pago.

  **Nadie paga por "JMAP"**: es un protocolo, no una función que el cliente reconozca; ni Fastmail lo cobra aparte. Lo que se vende es buzón y almacenamiento. JMAP es la ventaja técnica que hace volar la Bandeja y regala búsqueda y sincronización.

  Precio de referencia, a confirmar con el spike: **+$99 MXN/mes por dominio con ~10 GB** encaja en la escalera de add-ons actual. El almacenamiento no es el costo (10 GB en S3 son ~$4.40 MXN/mes); lo caro es operación y soporte.

  **Antes de construir, medir**: la FAQ ahora dice "próximamente" en vez de prometerlo mal, así que por primera vez se puede medir cuánta gente pregunta por IMAP.

  Relacionado: el add-on de almacenamiento y la retención por plan, ambos sin definir.

### ⏭️ Lo primero de la próxima sesión
- [ ] **Evaluar el costo de sacar la app de Fly**. Análisis, no decisión: qué costaría migrar y a dónde. Lo que ata hoy a Fly es el **volumen único con SQLite** — es la misma restricción que impide el deploy multi-máquina y sin downtime, así que conviene evaluarlo junto con el punto de abajo y no por separado.

  A cuantificar: costo mensual actual en Fly vs alternativas (VPS simple, Railway, Render, EC2 con EBS); qué se rompe al mover el volumen y cómo se migra la base sin perder correo en tránsito; qué pasa con las reglas de recepción de SES y el `notification_url` de MercadoPago si cambia el host; y si la migración obliga de todos modos a pasar a Postgres, en cuyo caso el costo real es ese, no el del hosting. Ojo con el DNS y los certificados: el apex ya hace 301 a `www` y hay dominios de clientes apuntando a SES.

- [ ] **Deploy sub-minuto**. Hoy cada `fly deploy` toma varios minutos y se sintió en una sesión con muchos despliegues seguidos. Ya se bajó de 25+ min a ~22s de build con 11s de downtime (ver `deploy-optimization-pending` en memoria), pero el ciclo completo sigue siendo lento. A revisar: caché de capas de Docker, tamaño de la imagen y qué se copia al contexto de build, `fly deploy --local-only` vs remoto, y si conviene separar el build de assets del de la app. El downtime en sí ya está acotado por SQLite en volumen único — eso es harina de otro costal (LiteFS o Postgres, ya anotado abajo).

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
- [x] ~~**Respaldos reales**~~: Resuelto 29-jul-2026. `backup.ts` hace `runDbBackup()`: `VACUUM INTO` (snapshot consistente que sí incluye el WAL), verificación con `integrity_check` + conteo de tablas antes de subir, gzip nivel 9 y upload a `s3://mailmask-backups/backups/mailmask-db-<ISO>.sqlite.gz`. Retención de 7 por familia de respaldo. Los JSON de 3.2 KB anteriores solo cubrían 4 de 22 tablas y omitían los DKIM tokens; fueron borrados de S3 (copia en `~/mailmask-backups-legacy/`). **Drill de restauración ejecutado y verificado**: 23 tablas, `integrity_check` ok, alias con destinos, suscripciones y DKIM tokens presentes. **Ojo al restaurar**: un respaldo restaura la base, no AWS. La restauración del 29-jul revivió la fila de `brendago.design` sin su regla de recepción ni su config set (el DELETE los había borrado minutos antes) y el dominio rebotó todo un mes. Desde sep-2026 el arranque reconcilia cada dominio contra SES (`ensureDomainInbound`), así que tras restaurar basta con un deploy o reinicio; aun así, después de una restauración revisa `fly logs` por `Recreated missing receipt rule`.
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

### Compositor de correo

- [ ] **Corrección ortográfica en el compositor**. Hoy el editor de la Bandeja
  (`public/js/composer.ts`, Tiptap) no revisa ortografía. Lo barato es dejar el
  corrector nativo del navegador (`spellcheck="true"` en el elemento editable),
  que ya trae el diccionario del sistema y no cuesta nada — verificar que
  ProseMirror no lo esté apagando. Lo caro y diferenciador sería una revisión
  propia en español (sugerencias en línea, tono, muletillas), que se apoyaría en
  los agentes de Formmy; eso entra en la sesión de "qué features de IA añadir".
  Empezar por lo nativo y medir si alguien pide más.

### Diseño
- [ ] **Tema claro con toggle**. Hoy todo el sitio es oscuro fijo. La evidencia de 2026 dice que no hay ganador universal: oscuro rinde en herramientas de desarrollo, claro en público no técnico que necesita confiar rápido —que es el público de la home— y **lo que mejor funciona es híbrido**, claro donde se lee y oscuro donde se enfatiza. Hay casos documentados donde la versión clara ganó 16% más clics pero 42% menos conversiones, así que no se cambia a ciegas: **toggle y medir**, no reemplazar.

  Implementación: tokens de color en `public/css/input.css` (hoy solo define `--mask-*`; los grises salen de clases `zinc-*` de Tailwind hardcodeadas en el HTML). Hay que pasar los fondos y textos a variables para poder invertirlos, respetar `prefers-color-scheme` en la primera visita y recordar la elección. Ojo: son 4 archivos HTML grandes más los 25 del blog.

  **Ya hecho (agosto 2026)**: se corrigió el contraste de la home. `text-zinc-500` era el color de texto más usado (56 veces) y daba 4.12:1 sobre el fondo —por debajo del mínimo AA de 4.5:1— y 3.67:1 dentro de las tarjetas; `text-zinc-600` estaba en 2.29:1. Se subieron a zinc-400 y zinc-500. **El resto del sitio (pricing, docs, blog, app) sigue sin auditar de contraste.**

### Contenido / Educación

- [ ] **Auditoría del blog** (una sola pasada, pendiente de agendar). Dos frentes:
  - **Riqueza visual**: los 24 posts son **texto plano** — cero `<img>` y cero `<svg>` en el cuerpo, solo 3 tienen tabla. Los JPG de `blog/img/` existen únicamente para la tarjeta de compartir; el lector nunca los ve. Falta enriquecer con diagramas, ilustraciones, SVG animados, comparativas en tabla y bloques de código donde aplique.
  - **Navegación**: el índice es una lista plana de 24 posts sin forma de filtrar. Agregar **categorías y filtros** (por audiencia: freelancer, agencia, startup, tienda, equipo remoto; y por tipo: guía, comparativa, tutorial) y un **buscador**. Con 24 piezas ya duele; con 40 el índice deja de servir. Considerar que las categorías necesitan páginas propias indexables para que aporten SEO, no solo filtrado en cliente.
- **Estándar visual del blog — validado, seguirlo siempre**: el diagrama debe ser **literal y etiquetado**, no una metáfora. Cajas con nombre, flechas con verbo, columnas que comparan "antes / después" o "opción A / opción B". Referencias buenas: el diagrama de los tres caminos de envío en `enviar-emails-desde-dominio.html` y la comparación Gmail vs dominio en `dejar-de-escribir-desde-gmail-personal.html`. **Regla de oro: si necesita un pie de foto que explique la metáfora, está mal.** Se probó una ilustración conceptual (la conversación como costura que se revienta) y se descartó por ambigua.
- **Post técnico de referencia — la receta que funcionó** (`que-es-redos-expresiones-regulares.html`, 21-ago-2026). Nació de un hallazgo real de una sesión de trabajo: revisando `forwarding.ts` apareció un guard anti-ReDoS que no protegía nada. Ese origen es la parte replicable — **el mejor material sale del trabajo del día, no de una lista de keywords**. Lo que lo hizo bueno, en orden de importancia:
  1. **Números medidos, no estimados.** Se corrió el caso real y se citaron los tiempos (30 caracteres → 4.6 s; 32 → 18 s; el guard de 50 ms devolviendo a los 20 s). Un dato medido es lo que un motor generativo cita y lo que un lector técnico recuerda. Antes de escribir "es lento", mídelo y pon el número.
  2. **Un antipatrón concreto con su código.** El post desmonta algo que el lector probablemente tiene escrito en su repo. Enseñar qué NO funciona, con el snippet exacto, vale más que la explicación teórica.
  3. **Dos diagramas literales**: el mecanismo (los repartos que prueba el motor, con la tabla de tiempos al lado) y la comparación (hilo principal vs worker). Cumple la regla de oro: ninguno necesita pie de foto para entenderse.
  4. **Honestidad sobre el producto.** El borrador afirmaba defensas que MailMask no tenía; se comprobó contra el código, se corrigió el texto y después se implementó de verdad (`regex-guard.ts`). **Nunca publicar una capacidad sin verificarla en el código primero** — y si el post explica cómo explotar algo, cerrar el hueco antes de publicar.
  5. Cierre de producto corto y al final, sin inflar.
- **Publicado con el mismo molde** (2-sep-2026): `dominio-verificado-que-rebota-anatomia-ses.html` — los tres recursos de un dominio en SES, línea de tiempo de CloudTrail y reconciliación al arrancar.
- **Temas candidatos para posts técnicos** (mismo molde: hallazgo real + números medidos). Todos salen de trabajo ya hecho en este repo, así que el material existe: por qué `--test-force-exit` escondía el 20% de la suite y cómo se detecta (`scheduler.ts`); por qué un `From` mal formado tumbó todo el correo transaccional ocho días sin que nadie lo notara, y qué alerta lo hubiera cazado; cómo se arma un correo MIME multicapa de verdad (`ses.ts`) y por qué Outlook muestra un clip fantasma; por qué un respaldo en JSON no es un respaldo y cómo se verifica una restauración; qué cuesta de verdad procesar un correo en SES+S3. **Antes de escribir cualquiera, confirmar que el dato sigue siendo cierto en el código.**
- **Estándar para posts nuevos** (aplicar desde ya, no esperar a la auditoría): cada post nace con al menos un diagrama o ilustración original en el cuerpo — SVG inline, no stock. SVG porque escala, pesa poco, se adapta al tema oscuro y se puede animar. Además, formato pensado para motores generativos (GEO): 4-8 `<h2>`, cada uno respondiendo **una** pregunta completa sin depender del contexto anterior, con la respuesta directa en la primera oración y párrafos de 2-3 líneas. Eso es lo que citan los buscadores con IA.
- [ ] **Evaluar qué features de IA añadir y promocionar** (sesión dedicada, con investigación previa). Punto de partida: hay **cero código de IA** en el repo, pero ya se publicaron dos posts que crean expectativa — `clasificador-automatico-emails-ia.html` y `respuestas-sugeridas-ia.html`, ambos en futuro ("estamos explorando", "cuándo estará disponible"). O sea, la demanda ya está sembrada y sin cobrar.

  Criterios para decidir: (1) qué se apoya en lo que **ya es sólido** — la Bandeja con historial persistente es el activo diferenciador, porque ningún competidor guarda contenido; (2) qué **valora y paga** la comunidad de verdad, no lo que está de moda — investigar antes de elegir; (3) qué se puede montar sobre los agentes de Formmy, que es la vía ya explorada en esos posts.

  Candidatos ya escritos en este backlog: clasificación automática de correos, respuestas sugeridas, el Radar de Actividad por alias (resumen semanal en lenguaje natural) y búsqueda semántica con pgvector. Falta priorizarlos con datos, no por intuición.

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
