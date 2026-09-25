# CLAUDE.md

## Project overview
MailMask — email alias/forwarding service. Elysia monolith with SQLite, AWS SES/S3, MercadoPago billing.

## Commands
```bash
npm run dev       # Run dev server on :8000 (tsx --watch)
npm test          # Run tests (tsx --test)
```

## Deploy
**Siempre desde un worktree limpio de HEAD, nunca desde `/Users/bliss/mailmask` con trabajo sin commit.** `fly deploy` empaqueta el árbol de trabajo tal cual: el 5-sep-2026 un deploy se llevó a producción un `main.ts` que importaba un módulo que estaba en un stash y tumbó el sitio; otro se llevó cambios de precios a medias. Con dos sesiones de Claude en el mismo repo esto pasa.
```bash
W=$SCRATCHPAD/deploy-wt; git worktree add --detach "$W" HEAD && (cd "$W" && fly deploy); git worktree remove --force "$W"
```
Y nunca `git stash`, `checkout` ni `reset` sobre archivos que otra sesión tiene abiertos; commitea sólo con `git add <tus archivos>`.

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

## MCP (`mcp.ts`, 7-sep-2026)

`POST /mcp` es un servidor MCP Streamable HTTP **sin sesiones** (`@modelcontextprotocol/sdk`,
`WebStandardStreamableHTTPServerTransport`, `enableJsonResponse`), autenticado sólo con
`Authorization: Bearer mk_…` (la API key normal; sin ella 401, y `/mcp` está exento de CSRF
porque nunca acepta cookie). **Cada herramienta es el SDK real** (`sdk/src`, que sí viaja
en la imagen) hablando con la app en proceso vía `app.fetch` — el mismo truco de
`sdk.test.ts` —, así que no puede desalinearse de una ruta sin que `sdk.test.ts` lo cace.
Para añadir una: método en el SDK → caso en `sdk.test.ts` → `tool()` en `mcp.ts`. Un
`MailMaskError` sale como `isError` con `HTTP <status>: <mensaje>` (el 403 del precio es
información útil para el agente). No se exponen las API keys (un agente con una llave no
fabrica más), ni Bandeja ni billing. Pruebas en `mcp.test.ts`. Docs en `docs.html#mcp` y
`EXTRA_DOCS` de `upload-docs.ts`. GET/DELETE dan 405: sin sesiones no hay stream ni cierre.

## MCP Registry oficial (`studio.mailmask/mailmask`, 19-sep-2026)

Listado en `registry.modelcontextprotocol.io` con el manifiesto `server.json` de la raíz (sólo
`remotes` → `https://www.mailmask.studio/mcp`; el SDK npm no es stdio). El namespace se verifica
por HTTP: el registry lee `https://mailmask.studio/.well-known/mcp-registry-auth` **en el apex y
sin seguir redirects**, por eso esa ruta es la única exenta del 301 naked→www en `main.ts`
(`mcp.test.ts` lo fija). La llave privada Ed25519 vive en `~/.mailmask-mcp-registry-key.pem`
(fuera del repo; sin ella no se republica bajo este namespace; el `openssl` del sistema es
LibreSSL, usar `/opt/homebrew/opt/openssl@3/bin/openssl`). `version` de `server.json` sube en
**cada** republicación (las publicaciones son inmutables y el string debe ser único); la
`description` tiene tope de 100 caracteres. Publicar: `mcp-publisher validate` →
`mcp-publisher login http --domain mailmask.studio --private-key <seed hex>` → `mcp-publisher publish`.

## Skills para agentes (`public/skills/`, 18-sep-2026)

Mismo montaje que ghosty-studio. Cinco skills en formato Agent Skills (`mailmask-account`,
`mailmask-mcp`, `mailmask-sdk`, `mailmask-dns`, `mailmask-docs`), instalables con
`npx skills add https://www.mailmask.studio` (well-known) o `npx skills add blissito/mailmask-skills`
(espejo en GitHub, que es lo que cuenta skills.sh). `scripts/skills-pack.mts` valida cada
`SKILL.md` (nombre = carpeta, `metadata.version`, ≤500 líneas, y **la description no puede
llevar `: `** — Claude descarta la skill en silencio, medido en ghosty) y escribe
`index.json` (v0.2.0 con `digest`) + `index.legacy.json` + `.tar.gz` de las multi-archivo. Lo
generado **no se commitea**: lo produce el `RUN` del Dockerfile (por eso `.dockerignore` re-incluye
`scripts/skills-pack.mts` y `public/skills/**/*.md`) y `skills.test.ts` corre la validación en
`npm test`. Rutas en `main.ts`: `/skills/*`, `/.well-known/agent-skills/index.json`,
`/.well-known/skills/index.json`. **Al tocar una skill**: `npm run skills:publish` (subtree push
al espejo, manual) y, si cambió la sección `#skills` de `docs.html`, re-subir la KB de Formmy.

## Dominios: registro, renovación, transferencias y DNS (7-sep-2026)

El registro de un dominio nuevo llevaba meses construido y **nunca se había ejercitado**.
Al revisarlo salieron tres bugs de producción y dos huecos de producto.

**El caro:** `registerDomain` manda `AutoRenew: true` a AWS y el pago del cliente era una
Preference **de una sola vez**. O sea, AWS renovaba el dominio cada año y **nos lo cobraba a
nosotros**, en silencio, para siempre. Ahora hay una suscripción anual de MercadoPago
(`domain-renew:<id>`, patrón de los add-ons) y un digest diario de dominios que vencen en
menos de 90 días sin renovación cobrada.

**`AutoRenew` se queda encendido y ningún cron lo apaga.** La asimetría manda: con AutoRenew
el peor caso es pagar ~$13 USD de un cliente moroso; sin él, cualquier bug el día del
vencimiento pierde el dominio, y rescatarlo en redención cuesta ~$90 USD más el correo
caído. Por eso el impago **no** corta: cobra, insiste a los 3/7/14 días y a los 21 le pasa la
decisión a una persona. El único lugar donde se apaga es un transfer-out confirmado.

**Los otros dos bugs, ya arreglados:** `configureDnsRecords` hacía un UPSERT ciego —el UPSERT
reemplaza el RRSet completo, así que el TXT del apex se llevaba por delante la verificación
de Google del cliente y el MX su correo en producción—; y `createHostedZone` llevaba
`Date.now()` en el `CallerReference`, así que cada reintento del cron creaba **otra** hosted
zone para el mismo dominio (se pagan las dos y responde la equivocada). Hoy `ensureHostedZone`
adopta la existente y `configureDnsRecords` fusiona el SPF en vez de pisarlo.
`expiresAt` sale de `getDomainDetail`, no de `Date.now() + 365 días`.
`GET /api/domains/registrations` ya no filtra `awsCostCents` al cliente.

### Editor de DNS (`dns-records.ts`, `dns-import.ts`, `/api/domains/:id/dns`)

**El modelo es el RRSet, no el registro suelto.** `ChangeResourceRecordSets` es atómico por
`(nombre, tipo)` y no sabe borrar un valor: exponer valores sueltos obligaría a
leer-modificar-escribir con una carrera invisible entre dos pestañas o dos llamadas de un
agente. Con RRSets la operación natural es un UPSERT idempotente, que además es lo que un LLM
usa sin romper nada.

**El guardián no lleva escotilla de forzado.** Si existiera un `?force=true`, un agente lo
pondría a la primera negativa. El MX, el TXT `_amazonses` y los CNAME de DKIM están
bloqueados; el TXT del apex es **parcial** —editable mientras conserve
`include:amazonses.com`— porque ahí conviven nuestro SPF y las verificaciones de Google,
Stripe y demás. El 409 devuelve `suggestedValues` con la fusión ya hecha para que el agente
reintente sin razonar. La salida legítima (mover el correo a otro proveedor) es borrar el
dominio de MailMask.

**La zona se adopta si ya existe.** `GET /dns` pregunta a Route 53 por nombre cuando la fila
no tiene `hostedZoneId`, y guarda lo que encuentre (con freno de 6 h vía `dnsCheckedAt`, para
no gastar una llamada por vista en los dominios que de verdad no están ahí). Hizo falta
porque el backfill de la migración 0018 copiaba el id desde `domain_registrations`, y esa
tabla **está vacía**: nadie ha registrado nunca por ese flujo. `mailmask.studio` tiene su
zona desde siempre —se montó a mano— y salía como "sin DNS". La lección es la de siempre en
este repo: un backfill que asume que el estado se creó por nuestro camino feliz se equivoca
con todo lo que se hizo a mano antes.

**Cobertura ampliada:** un dominio de fuera puede delegar sus nameservers a una hosted zone
nuestra sin transferir el registro, y así tener el editor. `POST /dns/zone` **importa antes
de enseñar los nameservers**, y si la importación o la fusión fallan borra la zona: media
zona es peor que ninguna. La importación sondea con `node:dns/promises` contra los NS
autoritativos actuales y una lista heurística de nombres —sin AXFR **no se puede enumerar la
zona de otro**, sólo preguntar nombre por nombre—, así que el aviso de que puede faltar algo
no es cortesía, es la verdad.

La pestaña DNS **ya no se oculta** para los dominios comprados aquí: era justo el cliente que
nos compró el dominio el único que no podía tocar nada. La lista de "copia esto en tu
proveedor" sigue ahí como segunda rama: hay quien no va a delegar nunca.

MCP: 7 herramientas, con `point_domain_to` de alto nivel. Un LLM sabe que Vercel quiere un
CNAME, pero se inventa el destino y confunde apex con www; esa herramienta convierte tres
llamadas frágiles en una determinista.

### Transferencias (`domain-transfer.ts`)

**Transfer-in.** Los requisitos se comprueban **antes de cobrar** (`CheckDomainTransferability`
más RDAP para la edad de 60 días y el candado; la privacidad WHOIS y el acceso al correo los
confirma el cliente porque no se pueden ver desde fuera). El auth code EPP **nunca toca disco
ni logs**: vive en un `Map` con TTL de una hora y en la fila sólo quedan sus últimos 4
caracteres.

Dos cosas no obvias, y las dos existen para no tumbarle la web al cliente:

1. **A `TransferDomain` se le pasan los nameservers actuales del cliente.** Si no se mandan,
   AWS pone los suyos al completarse y el dominio se queda sin DNS de golpe. Pasándolos, el
   transfer no cambia nada y la migración a nuestra zona la hacemos después, ya con la zona
   poblada. Convierte el momento más peligroso en un no-evento.
2. **`finalizeDomainRegistration` se detiene** si `kind === "transfer"` y el inventario de DNS
   no está en `approved`. El orden después es normativo: crear zona → escribir **todo** el
   inventario aprobado → `configureDnsRecords` con fusión → **y sólo entonces**
   `updateNameservers`.

El transfer-in de AWS incluye +1 año, así que se cobra el precio de renovación. El sondeo va
cada 10 minutos; recordatorios a los 2, 5 y 8 días y cancelación a los 10 (AWS caduca la
solicitud sola a los ~5 en muchos TLDs). Un fallo alerta con "hay que reembolsarle": el
reembolso es manual.

**Qué TLD se aceptan.** El alta de un dominio nuevo se limita a `TLD_PRICES`, una parrilla
curada de 12 con precios pensados a mano. **La transferencia no**: ahí el dominio ya es del
cliente, así que la pregunta no es "¿cuáles vendemos?" sino "¿cuáles puede mover AWS?" — y
son **413**. Usar la tabla de 12 como filtro rechazaba a clientes que ya tenemos:
`brendago.design` y `fancyfiles.app` son reales y los dos habrían sido un 400.
`precioDeTransferencia()` en `tld-pricing.ts` devuelve el precio curado si existe y, si no,
consulta `ListPrices` en vivo (caché de 24 h) y le aplica margen. El tipo de cambio es
`USD_MXN` en el entorno y no un número clavado en el código: eso envejece en silencio y
acaba vendiendo bajo costo. Un `TransferPrice` de cero o en otra moneda se **rechaza**, no
se toma por una ganga. Ojo con el rango: `.design` cuesta $64 USD y hay TLDs de hasta $480,
así que el margen es porcentual y no una cantidad fija.

**Tres cosas que sólo se vieron probando contra dominios reales** (7-sep-2026, antes de la
primera transferencia con cliente):

1. **RDAP fallaba siempre.** `rdap.org` está detrás de Cloudflare y sin `User-Agent` contesta
   **403 con HTML**; el `JSON.parse` reventaba y todos los requisitos degradaban a "?" — que
   es el fail-open que yo mismo escribí, así que no se notaba. Con UA responde 200 y dice
   registrador, edad y candado. Lección: un fail-open que nunca se ejercita es un apagado.
2. **Un `UNTRANSFERABLE` de AWS se mostraba como "?"** y dejaba pagar. Ahora es `ok: false`.
   `brendago.design` da exactamente eso: tiene `server transfer prohibited`, que lo pone el
   registro y el cliente no puede quitar, así que hoy **no se puede transferir**.
3. **El inventario de DNS salía incompleto y distinto en cada corrida.** Se disparaban ~150
   consultas simultáneas contra el servidor autoritativo del cliente, que empezaba a
   descartarlas. Con `brendago.design`: 4-5 registros e inestable. Ahora hay tope de 6
   simultáneas, `tries: 2` (un UDP perdido no es "no existe") y presupuesto de 45 s: **12
   registros, idénticos en tres corridas**. Además, para un dominio que ya está en la cuenta
   se le pasan los nombres que ya conocemos —los CNAME de DKIM llevan un token aleatorio que
   ninguna heurística adivina—, y eran justo los que faltaban: sin ellos, mover el dominio le
   habría roto la firma DKIM al cliente en silencio. Y un corte por tiempo ya no devuelve el
   inventario vacío (que el cliente aprobaría creyendo que su zona no tenía nada), sino lo que
   alcanzó con `truncado: true`.

**Lo que cerró la auditoría del 8-sep-2026** (toda la superficie: alta, pago, aprovisionamiento,
transfer-in/out, renovación, DNS y crons). Once huecos, y los tres primeros costaban dinero o
clientes:

1. **Todo dominio quedaba a nombre de MailMask.** `whoisContact()` aceptaba los datos del
   cliente desde el principio y **nadie se los pasaba nunca**. En un transfer-in eso es
   quitarle la titularidad de algo que ya era suyo. Ahora `/transfer/start` exige un contacto
   WHOIS válido (teléfono en el formato `+52.5512345678` que pide el registro, país ISO-2),
   se guarda en `whois_contact` (migración 0022) y viaja a `TransferDomain`. El alta nueva
   sigue a nombre de MailMask, pero los `REGISTRANT_*` ya no tienen respaldo inventado: si
   falta uno, `whoisContact()` lanza. Un WHOIS falso es causa de suspensión por el registro.
2. **`/transfer/start` cobraba sin comprobar los requisitos**: `checkDomainReadiness()` sólo
   lo llamaba `/transfer/check`, o sea que el guardián vivía en el front y un POST directo
   cobraba un dominio intransferible, con reembolso manual.
3. **`DELETE /api/domains/:id` dejaba el dominio en AWS renovándose a nuestra costa** para
   siempre (y el preapproval cobrándole al cliente algo que ya no tenía). Ahora da 409 si hay
   registración viva: la salida es el transfer-out, que ya existe.
4. **El aprovisionamiento adoptaba la fila de otro dueño.** Agregar un dominio no exige
   probar que es tuyo, sólo que nadie lo tenga: el transfer-in del dueño real activaba el
   dominio en la cuenta que se le había adelantado. Se comprueba en `/transfer/start` (antes
   de cobrar) y al principio de `finalizeDomainRegistration` (antes de tocar AWS).
5. **Editar DNS pedía `write`, y el rol `agent` lo tiene**: un invitado a responder correos
   podía repuntar la web del cliente o emitirse un certificado con un `_acme-challenge`. Las
   tres rutas de escritura pasan a `admin`; leer sigue en `read`.
6. Dos estados esperaban en silencio para siempre: `transfer_paid` sin auth code vigente
   (cobrado y sin transferencia — el `Map` no sobrevive a un deploy) y `registering` parado
   por el inventario sin aprobar. Los dos alertan ahora, una sola vez, vía `warnedAt`.
7. Un checkout abandonado bloqueaba el dominio con 409 **para siempre**, incluso para el
   propio cliente. Pasadas 24 h se cancela y se deja reintentar.
8. **Crear zona exige dominio activado**: cada hosted zone son $0.50 USD/mes que pagábamos
   nosotros, y una cuenta gratis podía abrir tantas como dominios agregara.
9. `checkTransferability` mapeaba `UNTRANSFERRABLE` con dos erres y AWS manda una: el cliente
   veía el enum crudo. También faltaban `DOMAIN_IN_OWN_ACCOUNT` y `DOMAIN_IN_ANOTHER_ACCOUNT`.
10. El guardián de DKIM salía de `dkimTokens`, que puede venir vacía o desfasada; ahora
    también se reconoce un CNAME de DKIM por su forma (token de 32 caracteres o destino
    `*.dkim.amazonses.com`). El DKIM de otro proveedor sigue siendo del cliente.
11. Un dominio que ya **no aparece** en `listRegisteredDomains()` es un transfer-out
    consumado: se marca `transferred_out` y se cancela su cobro. Es el único momento seguro
    para hacerlo, y antes dependía de que una persona leyera una alerta.

**Transfer-out** no es opcional: sin él, ofrecer migración entrante es asimétrico. El auth
code va **por correo y no en la respuesta** —entregarlo es entregar el dominio— con un enlace
de 30 minutos y un solo uso. `AutoRenew` se apaga sólo cuando la salida se confirma de
verdad, nunca antes: si la transferencia se cae, el dominio se pierde.

**Contacto WHOIS:** ya no es sólo el de MailMask. `whoisContact()` acepta los datos del
cliente (no hace falta cuenta de AWS suya, son sólo datos) y en transfer-in deberían ser los
suyos: el dominio ya era de él.

### ⏳ EN ESPERA — primera transferencia real: kandey.com.mx (24-sep-2026)

**Estado:** mandada a AWS el 24-sep a las 22:47 (operación
`3f62f782-b045-44c5-888d-aafd09cc44e6`), paso 7 de 14: *"esperando a que el registrador
actual la apruebe automáticamente"*. En .mx Hostinger no tiene botón de aprobar: la suelta
solo, hasta 10 días. Cliente: `fresnnyypublicidad@gmail.com` (WHOIS `rfc.rossy@gmail.com`).
Pago **manual** (`mpPaymentId: manual:bliss-2026-09-24`), fuera de MercadoPago.

**Fue un dolor de muelas para la clienta.** Ella sola no lo hubiera logrado; hicieron
falta bliss en WhatsApp y una sesión entera arreglando en producción. Lo que se topó, en
orden (todo arreglado ese día salvo lo marcado):

1. Teléfono `+525643868687` rechazado por no llevar el punto de Route 53 → se normaliza.
2. Cada error de captura gastaba el rate limit (3/min por IP) → por usuario y después de validar.
3. Reintentar daba 409 "transferencia en curso" durante 24 h → reusa la fila pendiente.
4. ❌ **El checkout de MercadoPago se colgó dos veces** sin llegar a crear el pago (ni
   rechazado): `COW00-YNTHGUYKKQGH`. Es el primer pago único de la historia de MailMask;
   **sigue sin investigar**.
5. El EPP vivía en memoria una hora y un deploy lo borraba → cifrado en `transfer_auth_codes`, 7 días.
6. AWS rechazó el estado "CDMX" (quiere `DF`) → `normalizeMxState`. Si MP hubiera cobrado,
   este era el peor: cobro hecho, transferencia rechazada, reembolso manual.
7. El inventario traía `mail.` como CNAME y A a la vez, que Route 53 rechaza → `dropCnameConflicts`.
8. Al terminar le íbamos a poner nuestro MX delante del de Hostinger y sus buzones se
   quedaban sin correo nuevo → en transfer-in el MX ajeno se deja intacto (`keepForeignMx`).
9. No había pantalla para aprobar el inventario → "Revisar y aprobar DNS" en la app.
10. ❌ Nada le dice al cliente qué hacer en su registrador (bloqueo, renovación, no pedir
    otro código). Hoy se lo explicamos por WhatsApp con capturas del hPanel.

**Riesgos abiertos, vigilar:**
- **Vence el 3-oct-2026 en Hostinger** con la autorrenovación apagada. Se le pidió
  encenderla como seguro. Si la transferencia no termina antes, revisarlo.
  **Choque de fechas:** Hostinger tiene hasta 10 días para soltarla (≈4-oct) y el dominio
  vence un día antes. Confirmar con la clienta que la autorrenovación quedó encendida, o
  que renueve ya. Revisado el 25-sep: AWS sigue en el paso 7/14 sin cambios desde las
  22:47 del 24-sep; el whois del .mx sigue en Registrar.eu (Hostinger), `ACTIVE`, y el
  NS y el MX siguen en Hostinger. Para revisar:
  `aws route53domains get-operation-detail --region us-east-1 --operation-id 3f62f782-b045-44c5-888d-aafd09cc44e6`.
- Que **no pida otro código** en Hostinger: invalida el que mandamos.
- La IP del apex es la CDN de Hostinger y rota en cada consulta: **antes de aprobar el
  inventario**, poner la IP que da el hPanel.
- Si Hostinger borra su zona DNS al soltar el dominio, el correo cae hasta que aprobemos:
  aprobar en cuanto llegue la alerta.
- El WHOIS quedó a nombre de Rosalba Flores; en Hostinger era Josue Kraves. Confirmar.

**Al completarse:** llega alerta `transferencia-completada:kandey.com.mx` a
`admin@mailmask.studio` y a la clienta el correo "Revisa el DNS". Revisar el inventario
con ella, aprobar, y comprobar después que `dig MX kandey.com.mx` sigue en Hostinger y que
la web carga.

**Pendiente de producto:** ficha del dominio en la app con la de Hostinger como
referencia (caducidad con alerta, renovación automática, nameservers, titular WHOIS,
bloqueo de transferencia, código de autorización) y el paso de la transferencia traducido
("Hostinger la libera sola, hasta 10 días"); y una compra real de punta a punta del
checkout de MP de pagos únicos.

### Antes de venderlo

1. ~~IAM~~ **ya está**: el usuario `pulso_easybits` (476114113638) trae
   `AmazonRoute53DomainsFullAccess` y `AmazonRoute53FullAccess`, así que cubre todo lo nuevo
   —`GetDomainDetail`, `TransferDomain`, `RetrieveDomainAuthCode`,
   `ListResourceRecordSets`, `ChangeResourceRecordSets`…—. Verificado el 7-sep-2026 con
   `get-domain-detail` y `list-hosted-zones` reales. Ojo: `route53domains` **sólo responde
   en us-east-1**.
2. **Nada que tocar en el panel de MP.** Los pagos únicos de dominio (registro y
   transferencia) entran por `/api/webhooks/mercadopago`, el mismo de siempre, en una rama
   `type === "payment"` que delega en `procesarPagoDominio`. Hubo un momento en que vivían
   en `/api/webhooks/mercadopago-domain`, y era una bomba: **el panel acepta una sola URL
   por aplicación**, así que esa ruta sólo funcionaba mientras MP respetara el
   `notification_url` que mandamos en cada Preference — y MP a veces lo pierde, que es justo
   la razón de que exista el cron de reconciliación. Un pago de dominio perdido es cobrarle
   al cliente y no registrarle nada.
3. ~~Hosted zones duplicadas~~ **no hay**: la cuenta tiene tres zonas y una sola por
   dominio (`mailmask.studio`, `easybits.cloud`, `ghosty.studio`). El bug del `Date.now()`
   nunca llegó a morder porque no se registró ningún dominio por este camino.
4. ~~Contrastar `TLD_PRICES`~~ **hecho el 7-sep-2026** contra `route53domains list-prices`.
   Los costos que había eran estimaciones y varias se quedaban cortas por mucho (`.io` vale
   $71 USD y decía $39; `.mx` $67 y decía $35; `.info` $30 y decía $12 — **ese se vendía a
   $549 MXN costando ~$630, o sea con pérdida**). Y transferir no siempre vale lo mismo que
   renovar: en `.click` y `.link` la transferencia cuesta $10 USD contra $3 y $5, así que
   cobrar el precio de renovación por un transfer-in perdía dinero en cada uno; por eso hay
   `transferUsdCents`/`transferMxnCents` aparte.

   **El precio al público es costo × 1.2**, y eso es una decisión, no un descuido: un dominio
   es una commodity con precio público —`.com.mx` está en $729 contra los $708 de
   Squarespace— y el cliente lo comprueba en diez segundos. El margen del negocio son los
   $99/mes de activación; el dominio es la conveniencia de que quede configurado solo. Un
   margen de producto normal (1.8×) ponía `.com.mx` en $1099 y volvía la primera compra del
   embudo el punto donde el cliente descubre que somos caros. `.click` y `.link` se salen del
   1.2 por el piso de $60: a ese margen dejarían menos que la comisión de MercadoPago.

   **El tipo de cambio se actualiza solo cada hora** (`fx.ts`, tabla `fx_rates`, cron `7 * * * *`).
   Antes era `process.env.USD_MXN ?? 21` y el real era **16.89**: nadie actualiza un número
   así, y sobre él se calculaba el precio de todos los dominios. Tres cosas no obvias:
   (1) se **cotiza sobre el máximo de los últimos 30 días**, no sobre el de este segundo,
   porque cotizar de menos se paga durante todos los años que dure la suscripción y cotizar
   de más sólo encarece el dominio un poco; (2) una lectura fuera de `[10, 40]` se
   **descarta** — una API que contesta `1` vendería un `.io` de $71 USD en $85 MXN; (3) la
   alerta salta por quedarse sin dato fresco (>26 h), no por un fallo suelto, porque las APIs
   públicas se caen y el máximo de 30 días aguanta el hueco. Los 12 curados llevan precio a
   mano y **no** se mueven solos; el tipo de cambio sólo afecta a los otros 401 TLD.

   ⚠️ **El monto de un PreApproval de MercadoPago no se puede cambiar después**: el precio de
   renovación se fija al contratar y tiene que aguantar años de tipo de cambio. Por eso el
   margen no baja de 1.2 aunque se pueda. **Los precios de AWS cambian: revísalos con ese
   comando antes de cada campaña.** El front tenía su propia copia de la tabla y se quedó
   desfasada; ahora la pide a `GET /api/domains/tlds`.
5. Una compra real de un `.click` ($139) de punta a punta, y un transfer-in de un dominio
   propio.
6. Términos: qué pasa si deja de pagar la renovación, y reembolsos de un transfer-in fallido
   por culpa del registrador de origen.

Fuera de la v1 a propósito: registros ALIAS (sólo apuntan a recursos de AWS, no sirven para
Vercel ni Netlify, que es el 90% de los casos), routing ponderado/latency/failover, DNSSEC,
parser de archivos de zona BIND, historial de cambios DNS y caché de RRSets en SQLite.

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
- **Login con Google** (sep-2026): `GET /api/auth/google` → `GET /api/auth/google/callback`, OAuth 2.0 con authorization code y scope `openid email`. La cuenta es **una por correo**: entrar con Google en un correo que ya tiene contraseña es la misma fila, y quien nace con Google recibe un hash aleatorio y puede fijar contraseña con "olvidé mi contraseña". Google deja `emailVerified` en true. El `state` va en `tokens` (kind `oauth-state`, 10 min, un solo uso) y carga `ref` y `coupon`. Env: `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET`; las URIs de redirección (prod y `http://localhost:8000`) están en la consola de Google Cloud. **No uses `Response.redirect()` en rutas**: sus headers son inmutables y `onAfterHandle` revienta con `TypeError: immutable`; construye el 302 a mano. Dominio verificado en Search Console con TXT en Route 53 (junto al SPF: un UPSERT de TXT debe conservar los valores previos).
- **Tema del sitio público** (sep-2026, dirección "lucha libre": crema + rojo de máscara + dorado sólo en la máscara, titulares en Bricolage Grotesque 800; el verde `mask-*` queda para la app y para estados OK): landing, pricing, login y registro usan tokens semánticos (`bg-bg`, `bg-bg-elev`, `text-fg`, `text-fg-muted`, `border-line`, `text-accent-text`, `bg-accent`) definidos en `public/css/input.css` y expuestos en `tailwind.config.ts`. Claro por default; `public/js/theme.js` (en `<head>`, sin `defer`) aplica `data-theme` guardado en `localStorage` y sin elección manda `prefers-color-scheme`. Piezas repetidas: `.btn-primary`, `.btn-secondary`, `.card`, `.mock`, `.chip`, `.eyebrow`, `.faq`. **No uses `zinc-*` en esas cuatro páginas.** Desde el 6-sep-2026 **`/bandeja` también usa los tokens**: sus 14 variables `--mesa-*` derivan de `--bg`, `--bg-elev`, `--bg-inset`, `--line`, `--fg*`, así que hereda el tema claro/oscuro y lleva `theme.js` en su `<head>`. El acento de la app sigue siendo el verde `mask-*` a propósito —es el "esto va bien"— y el rojo de máscara se queda en el sitio público. **`/app` migró a los tokens el 7-sep-2026** (mapa zinc→`bg-bg/bg-bg-elev/bg-bg-inset/border-line/text-fg*`, chips de estado en `mask-500/15`, `amber-500/15`, `red-500/10`; `.app-*` en `input.css` sin `white/[…]`), lleva `theme.js` y el toggle en la cabecera. Cualquier clase nueva exige `npm run build:css`. Fuentes Inter + JetBrains Mono desde Google Fonts (la CSP ya lo permite). El video de Brenda en la home es lite-embed: thumbnail local y `frame-src` con `youtube-nocookie.com`.
- **Precios (7-sep-2026)**: no hay planes. `ADDONS` en `plans.ts` = `domain`, `storage50`, `sends100`, todos $99 y **por dominio** (`addons.domain_id`). `PLANS` sólo etiqueta suscripciones legado. Todo límite sale de `derechosDeDominio()` en `db.ts`; ver la sección "Modelo de precios".
- **Límites**: se cuentan **por dominio** (`getSendCount()`, el rate limit de forwarding y `monthlyForwards` se llavean con `domainId`). Son dos distintos: `sends` (saliente que origina el usuario, por día) y `forwardPerHour`/`monthlyForwards` (reenvío de entrada, el caso de uso principal).
- **Regex de usuario**: las reglas con `match: "regex"` pasan por `revisarPatron()` de `regex-guard.ts` al guardarse (POST y PUT de reglas), y el texto se acota con `acotarTexto()` antes de evaluarlo en `forwarding.ts`. Es la única defensa posible: en tiempo de evaluación no se puede interrumpir un `RegExp.test()` porque es síncrono — el `setTimeout` que había alrededor devolvía a los 20 s con un tope de 50 ms. Explicado para el público en `/blog/que-es-redos-expresiones-regulares`.
- **Recursos SES por dominio**: un dominio necesita tres cosas en SES —identidad, regla de recepción en el rule set y config set— y "verificado" sólo mira la identidad. Sin la regla, SES contesta `550 5.1.1 mailbox unavailable` a todo y MailMask no se entera. `ensureDomainInbound()` en `ses.ts` reconcilia base contra SES al arrancar y en `POST /api/domains/:id/verify`. Nació de brendago.design (sep-2026): el DELETE limpió SES, la fila revivió de un respaldo y la reparación manual de agosto sólo devolvió la identidad. El config set lleva además un **event destination** al tópico `SNS_OUTBOUND_TOPIC_ARN` (rebotes y quejas → `/api/webhooks/ses-events`, firmado igual que el de entrada); sin ese secret la lista de supresión no se alimenta nunca. `ensureConfigSetEventDestination()` rellena el destino en sets viejos.
- **Lista de supresión**: la alimenta el webhook de eventos (rebote `Permanent` y queja), se consulta y edita por API (`/api/domains/:id/suppressions`, reason `manual`) y la aplican **los tres envíos del usuario (incluidos cc/bcc) y también el reenvío** (`doForward` en `forwarding.ts` descarta con `status: "discarded"` y lo anota en el log del dominio). Insistir a un buzón que rebotó Permanent daña la reputación del dominio en SES.
- **Tareas programadas**: nunca llames a `cron.schedule()` directo — usa `programar()` de `scheduler.ts`, que sólo agenda si el proceso arrancó `main.ts`. `node-cron` se re-agenda cada segundo, así que un solo `schedule` al importar un módulo dejaba vivo para siempre el proceso de pruebas. Eso obligaba a `--test-force-exit`, que truncaba el reporte: `npm test` decía 244 tests en una corrida y 293 en la siguiente, siempre en verde. Por la misma razón el `app.listen()` y las reparaciones de arranque de `main.ts` van bajo `esServidor`.

- **Migraciones**: el snapshot de drizzle sigue desincronizado respecto a `api_keys`. `drizzle-kit generate` pedirá input interactivo y quiere emitir un `ALTER TABLE api_keys` que **rompería producción**. Hasta que se reconcilie, escribe las migraciones a mano en `drizzle/` y agrégalas a `meta/_journal.json`.
- **`api_keys` se repara sola al arrancar** (`pg.ts`, justo después de `migrate()`). El paso de llaves en claro a SHA-256 se aplicó a producción con `scripts/migrate-api-keys-hash.ts`, un script suelto que nunca entró a las migraciones: por eso **toda base nueva —tests, dev, un despliegue limpio— nacía con la tabla vieja y `createApiKey` moría** con `no column named key_hash`. Producción funcionaba y nadie lo veía. La reparación es idempotente (sólo actúa si existe la columna `key`), conserva las llaves hasheándolas y no toca una base ya migrada. Va en código y no en un `.sql` porque hay bases en los dos estados y SQL no puede preguntar por una columna. El script suelto queda como referencia histórica.

## Bandeja compartida (v1.0, 6-sep-2026)

Es lo que justifica el plan Equipo frente a Front/Help Scout ($25 USD por asiento). Todo esto está en producción; los detalles no obvios:

- **Búsqueda en el cuerpo**: FTS5 (`messages_fts`, creada en `pg.ts` y **no** en una migración: un `CREATE VIRTUAL TABLE` que falle dentro del journal tumba el arranque entero). `tokenize = "unicode61 remove_diacritics 2"` es obligatorio — el producto es en español. La consulta va en **dos pasos** (`searchConversations` en `db.ts`): `snippet()` y `bm25()` sólo funcionan con la FTS consultada sola, sin alias ni join, y el filtro **autoritativo** por dominio es el segundo paso contra `conversations`, no la columna denormalizada. El texto del usuario se **neutraliza**, no se escapa (`search-query.ts`). El backfill es un trabajador en proceso (`search-backfill.ts`), reanudable vía `search_index_state`; script suelto no, por lo de `migrate-api-keys-hash.ts`.
- **Paginación por keyset**, no OFFSET: `last_message_at` cambia mientras el usuario baja, así que OFFSET se salta o repite filas. Cursor compuesto `(lastMessageAt, id)`.
- **RBAC**: todo endpoint de Bandeja pasa por `requireBandeja()` (401/400/404/plan/rol en un solo sitio). Antes se repetía `isOwner || getAgentByEmail(...)` **ignorando el rol** y cualquier agente podía borrar conversaciones. `agent` = `read`+`write` (responde, anota, cierra). Permiso **`moderate`** = borrar/restaurar conversaciones, para owner y admin: `admin` se reserva a lo del dueño (borrar el dominio, credenciales SMTP).
- **SSE en todas las mutaciones**, cada evento con `actor` para que quien lo hizo no repinte su propia acción. El cliente **parchea la fila** (`patchConv`/`renderConvRow`), nunca recarga la lista.
- **Leído por persona**: tabla `conversation_reads`; sin fila = nunca leído, así que no hay que sembrar nada al invitar. El flag sale del mismo LEFT JOIN que la lista, para que contador y filas no puedan discrepar.
- **Presencia (colisión)**: en memoria del proceso (`sse-hub.ts`), TTL 35 s viendo / 12 s escribiendo, clave por correo. ⚠️ **SSE y presencia son locales al proceso: no escalar `fly.toml` a 2+ máquinas sin resolver antes el bus.** `/api/bandeja/presence` está exento de CSRF porque el aviso de salida va por `sendBeacon`, que no puede poner encabezados.
- **Posponer**: el invariante `status="snoozed" ⟺ snoozedUntil != null` lo fuerza `updateConversation`, no los llamadores; por esa misma línea el correo entrante despierta el hilo. La fecha debe ser futura y de menos de 90 días, o el hilo se pierde para siempre.
- **HTML entrante** en `<iframe sandbox>` sin `allow-scripts` (CSP con `frame-src 'self'`). Alto fijo: medir el contenido exigiría ejecutar JS dentro.
- **Métricas** (`getBandejaMetrics`): los percentiles se calculan en TS (SQLite no los tiene) y los días vacíos se rellenan con cero. El reparto por persona usa `assignedTo` y **no** `messages.from`, que en un saliente es el alias del dominio. La duración se etiqueta "duración del hilo", no "tiempo hasta el cierre": no existe `closed_at`.
- **Atajos**: el guardia mira `isContentEditable`, no sólo `tagName` — el compositor es Tiptap y con `tagName` los atajos se disparaban mientras escribías.

### Cuerpo del entrante y S3

El cuerpo del correo entrante **no se guarda en `messages.body` a propósito**: vive en S3 y su texto plano en el índice FTS. `fetchEmailFromS3` clasifica el fallo (`NOT_FOUND` / `DENIED` / `OTHER`, `S3FetchError` en `ses.ts`) y el detalle degrada en tres estados distintos — rescatado del índice, ya no disponible, o error de verdad.

**Retención de 90 días (decidido el 15-sep-2026).** El bucket tiene la lifecycle rule
`expire-inbound-90d` sobre `inbound/`: el correo original (HTML y adjuntos) vive 90 días; el
hilo, el asunto y el texto plano del índice FTS se quedan. Los planes no prometen respaldo
permanente, y la copia de landing/pricing ya lo dice ("adjuntos 90 días"). Pasado el plazo el
detalle devuelve `bodyDegraded: "expired"` / `"expired_gone"` (log `info`, no `error`);
`"index"`/`"gone"` siguen significando que algo se perdió **antes** de tiempo.
Historia: del 23-ago al 6-sep la regla era `expire-24h` (puesta con aws-cli por `easybits`,
visto en CloudTrail) y borraba cada correo al día siguiente: eso fue lo de fancyfiles.app y
los `NOT_FOUND` de brendago.design de esa ventana. Sin versionado, ese correo no se recupera.

### Firma y logo

La firma es **markdown** (`appendSignature` en `email-html.ts`), así que sólo se aplica cuando el cliente manda `markdown` — con `html` o `body` sale sin firma, y está documentado en `docs.html`. El logo va **por URL, no incrustado**: Microsoft 365, Exchange 2019, OWA y Outlook.com muestran las imágenes incrustadas como adjuntos, y con `cid:` cada correo del dominio llevaría icono de clip. Vive en el prefijo permanente `domain-assets/`; **no agregarlo a `sweepOrphanEmailImages`**, que es lo que lo volvería efímero. Su ancho se fuerza a 200 px deduciéndolo de la ruta, porque `md` corre con `html:false` y heredaría los 600 px del cuerpo.

## Captcha

`POST /api/auth/register` y `/api/auth/forgot-password` verifican **Cloudflare Turnstile** (`turnstile.ts`). Lo que protege no es el widget sino el **canje del token** contra siteverify: un widget cuyo token nadie valida deja el formulario igual de abierto, y Cloudflare lo reporta como "siteverify isn't being called". Por eso: si siteverify no responde se **rechaza**, y sin `TURNSTILE_SECRET` se falla **abierto fuera de producción** (para que la suite corra) y **cerrado en producción**. `turnstile.test.ts` atraviesa las dos rutas reales y falla si el token no se canjeó.

La clave del sitio es pública y vive en el HTML; la secreta es `TURNSTILE_SECRET` en Fly.

## Billing
- MercadoPago PreApproval API for subscriptions
- Two checkout flows: guest (no account) and authenticated
- Guest checkout creates a pending-checkout token with 24h TTL
- MP webhook (`/api/webhooks/mercadopago`) handles payment notifications with HMAC validation
- Known: `payer_email` cannot match the MP collector account ("Payer and collector cannot be the same user")
- **App de MP correcta: `7311798029787174` ("Mailmask", integración Suscripciones).** Hasta sep-2026 el token era de la app `4821224211754985`, cuyo webhook apuntaba a `denik.me` y sin los tópicos de pagos: **ningún `subscription_authorized_payment` se procesó jamás en producción**. El plan de una clienta "venció" en la base aunque MP sí había cobrado, el cron de 04:00 le canceló en MP el add-on de envíos (irreversible) y `forwarding.ts` descartó su correo dos días. Los eventos de un preapproval van a la app que lo creó, así que un preapproval viejo **no se arregla cambiando la configuración**: se migra con `scripts/migrate-subscription.ts`, que crea uno nuevo con `auto_recurring.start_date` en la fecha ya pagada (autorizar no cobra) y `external_reference: "migrate:<email>"`; la rama `migrate:` del webhook cambia el `subMpId`, cancela el viejo y no registra orden. Un add-on con `start_date` futura se activa hasta `start_date + 35` sin recibo; el recibo llega con el cobro real.
- Al tocar el panel de MP: URL `https://www.mailmask.studio/api/webhooks/mercadopago`, eventos "Planes y suscripciones" + "Pagos (legacy)", y `MP_WEBHOOK_SECRET` = la **clave secreta de Webhooks**, no el Client Secret de la app (son distintas; con la equivocada el log dice `invalid signature`). El botón "Simular" del panel manda `data.id=123456`: el 404 que sigue es normal.

## Add-ons y envío de correo nuevo (agosto 2026)

**Modelo comercial.** El plan Básico ($49) **no envía correo nuevo** (`sends: 0`); sí responde desde la Bandeja, que está incluida en todos los planes. Enviar se compra aparte:

| Concepto | Precio |
|---|---|
| Básico | $49 · 1 dominio · 10 máscaras · Bandeja personal · API |
| **Equipo** (sep-2026) | $299 · 5 dominios · máscaras ilimitadas · 200 envíos/día por dominio · Bandeja compartida 5 personas · reglas, webhooks, SMTP relay · historial 90 días |
| Envíos 25/día | +$49 |
| Envíos 100/día | +$99 (excluyentes entre sí) |
| Dominio extra | +$79 c/u, acumulable, en ambos planes |

**Rediseño de tiers (5-sep-2026).** Freelancer ($449), Developer ($999), Pro y Agencia quedan como **legado** en `PLANS` (`LEGACY_PLANS`, `isLegacyPlan`): al momento del cambio no tenían ningún suscriptor (3 usuarios, todos Básico; 2 add-ons de dominio a $99 que hay que migrar o dejar al precio viejo). El checkout los rechaza con 400 y las páginas sólo muestran `PLANS_FOR_SALE`. Razón: el reenvío puro lo regalan ImprovMX ($9 USD por 30 dominios) y ForwardEmail ($3 USD ilimitado); lo que se cobra es la Bandeja compartida por dominio frente a Workspace ($140 MXN/usuario) y Help Scout ($25 USD/asiento). La escalera está calculada para que Equipo convenga desde el tercer dominio: Básico + 2 extras = $207 sin envíos, $306 con envíos, contra $299. Un add-on de 1,000 envíos/día quedó fuera a propósito (reputación SES compartida): la página dice "escríbenos". El add-on de envíos se compra una vez y aplica a todos los dominios; el tope cuenta **por dominio y por día**.

**Estado de entrega (sep-2026).** `sendFromDomain` devuelve `{ messageId, sesMessageId }`: el primero es nuestro header `Message-ID` (hilos), el segundo el id interno de SES, que es el que viene en sus eventos. Todo saliente (send, bulk, redactar, responder) se anota en `email_logs` con status `sent` y `ses_message_id` (`logOutbound`), y los de la Bandeja además en `messages.ses_message_id`. El webhook de eventos (`applyDeliveryStatus`) los mueve a `delivered`/`bounced`/`complained`, avisa por SSE `delivery_status` y la Bandeja pinta la palomita. Un rebote transitorio sólo actualiza el detalle. El evento trae `commonHeaders.messageId`: si termina en `amazonses.com` SES reescribió nuestro Message-ID y el log lo dice (`SES rewrote our Message-ID header`), lo que cierra la duda de `VIGILAR-BRENDI.md`.

**Cómo se envía.** `POST /send` acepta `cc`/`bcc` (máx 20), `inReplyTo`/`references`, `attachments` (llaves de `POST /attachments`, mismo `collectAttachments` que la Bandeja, se borran de S3 al enviar) y el header `Idempotency-Key` (24 h en `tokens`, kind `idempotency`, llaveado por usuario: devuelve la respuesta guardada con `Idempotent-Replayed: true` sin consumir cuota). Tres caminos, todos con tope: `POST /api/domains/:id/send` (unitario), `/send-bulk` (job asíncrono) y `POST /api/bandeja/conversations` (redactar desde la UI, botón "Redactar" o tecla `c`). Responder en la Bandeja **no** consume cuota — tiene su propio tope de abuso de 200/hora por dominio.

**Dos cosas no obvias del código:**
- Las conversaciones guardan `from` = contacto externo y `to` = nuestro alias, **también al redactar**. La lista, el filtro de alias y el remitente del reply dependen de esa convención invertida.
- El `Message-ID` lo genera `sendFromDomain` y se guarda en `threadReferences`; es lo que engancha la respuesta del contacto. **SES podría reescribirlo** — sin verificar. Ver `VIGILAR-BRENDI.md`.

**Cobro.** PreApproval propio por add-on con `external_reference: "addon:{id}"`, atendido en una rama temprana del webhook que sale con `return` antes de la detección de plan. Es obligatorio: el add-on de $49 vale lo mismo que el plan básico y el fallback por monto lo activaría como plan.

**Sin verificar en producción** (ver `VIGILAR-BRENDI.md`): la compra real en MercadoPago y el threading de punta a punta.

## TODO

- [ ] **Renombrar identificadores en español a inglés** (anotado 15-sep-2026). Regla del repo: código en
  inglés, comentarios y strings en español. Se coló mucho legado: `derechosDeDominio`, `porDominio`,
  `suscripcionLegadoVigente`, `dominioMasAntiguo`, `esGratis`/`bloqueado`/`activado` en `DerechosDominio`,
  `revisarPatron`, `acotarTexto`, `programar`, `precioDeTransferencia`, `asegurarDominio`, `crearBuzon`,
  `purgarConversacionesGratis`, `procesarPagoDominio`, `bytesDeBuzonesDelDominio`, `corteRetencion`,
  `ajustarIframe`, `convsNuevasEnVivo`, `seleccionadas`… Inventariar con
  `grep -rnoE "(function|const|let) [a-z]+[áéíóúñ]?[A-Za-z]*(ar|er|ir|ado|ida|ion|os|as)\b"` y revisar a mano.
  Ojo: `porDominio`/`derechos` viajan en el JSON de `/api/auth/me` y los lee el front — renombrar los dos
  lados en el mismo commit, y el MCP/SDK si exponen alguno. Sin cambiar comportamiento; `npm test` en verde.

## Modelo de precios: gratis + $99 por dominio (construido el 7-sep-2026)

Se tira el modelo de planes. **Todas las cuentas son gratis** y se compran tres cosas,
todas a $99/mes y **por dominio** (los add-ons pasan a llevar `domainId`):

| | Gratis | Dominio activado |
|---|---|---|
| Precio | $0 | **$99/mes** (anual $999) |
| Máscaras | 5 | ilimitadas |
| Personas en la Bandeja | 1 | ilimitadas |
| Bandeja | 7 días visibles, 30 guardados (recuperables al pagar), luego se borra | completo |
| Responder desde la Bandeja | sí | sí |
| Correo nuevo (API, Redactar, SMTP, Apple Mail) | no | **50/día** · +$99 por +100 |
| Buzones IMAP | no | ilimitados, 10 GB · +$99 por +50 GB |
| Reenvíos al mes (`monthlyForwards`, pasa a ser por dominio) | 1,000 | 10,000 |
| Reglas, webhooks, SMTP relay | no | sí |
| Al cancelar | — | 30 días solo lectura + descarga `.mbox` |

Por qué: el ancla correcta no es ForwardEmail ($3 USD por reenviar) sino Google ($140 por
persona) y Help Scout ($25 USD por asiento); "$99 por dominio, todo incluido, personas
ilimitadas" es la frase entera. El plan gratis existe para que el MX apunte aquí: ése es el
foso. Los 50 envíos: hoy los contadores salientes están vacíos; 50 a mano es ilimitado y
deja que el bloque de +100 tenga sentido para quien manda por API.

Reglas de migración: **nadie que pague hoy paga más, nadie pierde una cortesía.** Brenda
(Básico $49 + sends25 $49 = $98) queda en $99 con un dominio pagado y `denik.me` de
cortesía; su `sends25` se cancela en MP (ya viene incluido). Los tres de Básico: cortesía.
Equipo desaparece (cero clientes).

Hueco a cerrar ANTES de publicar el tope de envíos: **Apple Mail manda por el 465 de
Stalwart directo a SES**, sin pasar por el contador de la app. El límite por dominio debe
aplicarse también en la cola de salida de Stalwart, o "50/día" es ficción.

**Cómo está hecho.** Una sola función, `derechosDeDominio(domain, owner)` en `db.ts`,
contesta "¿qué puede ESTE dominio?": `activado` (add-on `domain` vigente con su
`domainId`, o suscripción legado vigente del dueño — mientras MP le cobre lo de antes,
todos sus dominios cuentan como activados), `esGratis` (el dominio **más antiguo** del
dueño sin activar; el único gratis) o `bloqueado` (el 2.º sin pagar: se guarda en la
Bandeja, no se reenvía). `getUserPlanLimits` y `PLAN_MESA_LIMITS` ya no existen. Los
add-ons llevan `domain_id` (migración 0016); los viejos sin él (`sends25`, `mailbox`)
son legado del usuario y suman en todos sus dominios. `monthlyForwards` se llavea
`fwd:<domainId>`. La retención del gratis es **un corte en la consulta**
(`corteRetencion` en lista, búsqueda y no-leídos) y un cron a las 3:30 que borra a los
30 días con `purgarConversacionesGratis` (S3 + FTS incluidos). Los checkouts de plan
(`/api/billing/checkout`, `guest-checkout`) se eliminaron; el webhook conserva las ramas
de plan sólo para renovar preapprovals viejos y **su fallback por monto ya no conoce
el 99**. Migración de datos: `scripts/migrar-modelo-99.ts` (dry-run por defecto) asigna
las cortesías `domain` viejas a dominios concretos y aborta si algún dominio verificado
quedara bloqueado.

Deuda anotada: el tope de envíos **no** cubre el 465 de Stalwart (Apple Mail manda a SES
sin pasar por la app); hasta cerrarlo, "+100 envíos" no debe venderse como comprable.

## Buzones IMAP (7-sep-2026)

**Stalwart corre en producción** en una caja permanente de EasyBits (`sb_4c48dee1-…` desde el 12-sep-2026 —la anterior `sb_4ba99ed3` murió en un reboot del fierro—, template `mail-svc`, `persistent` y `protected`), con 993 y 465 alcanzables desde fuera por el router SNI, certificado ACME DNS-01 contra Route 53 y salida por SES (SPF y DKIM en verde). Un alias puede tener **buzón**, **reenvío**, o los dos; y un buzón sin reenvío es lo que convierte a MailMask en reemplazo de Gmail y no en una capa encima.

**Un buzón es un alias con buzón**, no una tabla aparte (columnas `mailbox_*` en `alias`) — es también el modelo de ForwardEmail. Se cobra con el add-on `mailbox` ($99/mes **por dominio**, 10 GB compartidos entre buzones **ilimitados** de ese dominio). **Ningún plan lo incluye**, y no es tacañería: meter un recurso sin medidor en una cuota fija ya salió caro una vez —es la razón de que exista `monthlyForwards`— y el almacenamiento tiene la misma forma: crece solo, nunca baja y no se puede purgar sin avisar.

### Lo que hay que saber para tocarlo

- **Nunca guardamos la contraseña de un buzón.** Stalwart autoriza al admin por petición, así que `Email/import` con un `accountId` ajeno funciona: una sola credencial de administrador entrega en todos los buzones. La contraseña se genera, se muestra una vez y se olvida. Esto **excluye a propósito el cifrado por usuario**: con cifrado, cambiar la contraseña exige la vieja para descifrar la llave privada, y un panel que no la pida destruye el correo en silencio. Nuestro cifrado es de almacenamiento, no privacidad frente al operador.
- **`Principal/query` devuelve lista vacía —no un error— si la dirección no existe**, y resuelve también los alias. Ese vacío es el **fail-closed** de `imap-store.ts`: sin buzón conocido no se deposita. Antes del 7-sep el depósito entregaba siempre en el INBOX de un usuario global ignorando al destinatario; con un solo dominio activado no se notaba, con dos habría sido una **fuga entre clientes**. Hay tres pruebas que lo fijan.
- **La administración NO va por REST**: `/api/principal` da 404 en 0.16. Todo es JMAP en `POST /jmap` (**sin barra final**: con ella redirige, se pierde el cuerpo y contesta `notRequest`) con `"using": ["urn:stalwart:jmap"]` y métodos `x:*`. El esquema completo está en `GET /api/schema` de la caja. La credencial de administrador está en `/etc/stalwart.env`.
- **`emailAddress` lo deriva el servidor**; mandarlo explícito revienta con `invalidPatch`.
- **Nunca mandes `null`** en un campo opcional: tumba la petición entera con `400 notRequest`, el mismo error engañoso que la barra final.
- **Rechaza contraseñas débiles con zxcvbn**, no con una regla de caracteres: hace falta entropía real, no "cumplir una política".
- Cuota: `quotas/maxDiskQuota` en bytes; el uso se lee en la **misma** llamada (`x:Account/get` con `usedDiskQuota`). **`mailbox_used_bytes` es una caché, jamás la verdad para facturar** — todo contador de cuota deriva, en Stalwart y en todo el mundo Dovecot. Se reconcilia a diario.
- El archivo de `--config` **sólo declara el data store**; listeners, blob store, dominios y cuentas viven DENTRO del store. Respaldar el store es respaldar la configuración. Corre como usuario `stalwart`; un directorio de root lo tumba con `unable to open database file`, que no menciona permisos.

### 🔴 El mapeo del hostname apunta a un puerto, y equivocarlo es invisible

El 6-sep el hostname quedó mapeado al **465** (submission, TLS implícito), así que Caddy hablaba HTTP en claro contra un socket TLS y `/.well-known/jmap` daba **502** con `\x15\x03\x03…` —una alerta TLS— en el detalle. **Todo depósito falló en silencio**, por diseño: el reenvío no depende del buzón. Debe apuntar a **8080** (HTTP plano de Stalwart), no a 443, que es donde termina Caddy. El cron de cada 5 minutos ahora lo caza.

### 🔴 La caja no está en la cuenta, y por eso no tiene respaldo

`sandbox_status` la reporta con `ownerId: "anonymous"`: no aparece en `list_machines` y `list_backups` viene vacío. EasyBits **sí** respalda cada noche, pero copia los `dataPaths` del runspec — sin dueño no hay runspec y no hay nada que copiar. **Hay que registrarla con un `dataPaths` que incluya `/opt/stalwart`** (store + `acme/`). Aparte, la cuenta paga $99/mes por `mailmask-imap` (`sb_7e5ef08a…`), que está en estado `lost`.

Todo el estado durable son **6.1 MB**, y `stalwart --export` lo vuelca en 20 s y 840 KB. El dump es KV por subespacio, **independiente del backend**. ⚠️ `--import` **se niega a escribir sobre una base no vacía** y el servidor debe estar **detenido** para exportar o importar.

**No mover el store a Postgres hoy.** Se puede (es backend de primera clase), pero con `SearchStore: Default` sobre Postgres el índice de texto **trunca los cuerpos a 650 KB** por el límite de `tsvector` — y `IMAP SEARCH BODY` es justo lo que validó el spike. Sería una regresión. La respuesta correcta el día que quieras dos máquinas, no antes.

### Los cuerpos viven en Tigris, no en AWS (7-sep-2026)

El blob store de Stalwart apunta a **Tigris** (`mailmask-buzones`, endpoint
`https://fly.storage.tigris.dev`, `keyPrefix: buzones/`, región `Custom` con
`customEndpoint`/`customRegion`), no al S3 de AWS. Razón: la caja está fuera de AWS y cada
cuerpo que Apple Mail baja era **egreso a $0.09 USD/GB**; Tigris cobra $0.02/GB y **cero
egreso a cualquier destino**. `inbound/`, `domain-assets/` y los respaldos siguen en AWS
porque SES sólo escribe ahí. Las llaves están en `.env` como `TIGRIS_*`; la app no las usa.
Los 170 objetos previos se copiaron con las mismas llaves antes de cambiar el apuntador.

⚠️ **Nunca corras `fly storage create` dentro de este repo.** Con `fly.toml` presente
engancha el bucket a la app y **sobrescribe `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/
`AWS_REGION`** con las de Tigris y reinicia producción. Pasó el 7-sep: dos minutos con SES
roto (`Startup repair failed: InvalidClientTokenId`). Créalo desde un directorio sin
`fly.toml`, con `--name`.

### Split delivery: el buzón puede escribirle a una máscara del mismo dominio (7-sep-2026)

Desde Apple Mail, `buzon@` → `hola@mailmask.studio` moría con `550 Mailbox does not exist`:
Stalwart tenía el dominio como **autoritativo** y `hola@` es una máscara que vive en SES.
Es el patrón "split delivery" (Workspace) / "internal relay domain" (Exchange), no un bug.
Dos ajustes en la caja: `x:Domain.allowRelaying: true` (el RCPT acepta a los desconocidos
del dominio) y la ruta de salida `is_local_address(rcpt) ? 'local' : 'ses'` (decide por
**dirección**, no por dominio). `asegurarDominio()` en `stalwart.ts` crea cada dominio
nuevo ya con `allowRelaying`, y `crearBuzon` lo llama — antes fallaba en cualquier dominio
distinto de `mailmask.studio`, que se creó a mano. El alta de máscara (`POST /alias`) acepta
`mailbox: true` sin destinos en dominio activado y crea el buzón en la misma petición.
Dos trampas más del alta de dominio: (1) hay que crearlo con `dkimManagement: Manual`, o
Stalwart genera firmas DKIM y firma el correo, SES vuelve a firmar y contesta
`554 Duplicate header 'DKIM-Signature'`; (2) la ruta `ses` de Stalwart usa el usuario IAM
**`mailmask-stalwart-relay`** (llaves en `.env`, `STALWART_RELAY_*`), con `SendRawEmail`
sobre cualquier identidad — la credencial anterior sólo autorizaba `From` de
`mailmask.studio`. Es seguro porque `mustMatchSender: true` en Stalwart obliga a que el
remitente sea el usuario autenticado.

### 🔴 Stalwart se baneó a sí mismo (7-sep-2026)

Todo el tráfico externo entra por el proxy de EasyBits con **una sola IP** (`172.20.0.1`).
Un escáner de internet pidió `/wp-json/` y Stalwart (`security.scan-ban`) baneó esa IP
**sin caducidad** — o sea, a todos los clientes, JMAP incluido: el depósito estuvo muerto
de 01:48 a 03:04 y el cron de salud lo cazó. Arreglo: `x:BlockedIp/set destroy` +
`x:AllowedIp/set create {address: "172.20.0.1"}` **y reiniciar**: la lista de bloqueo vive
en memoria y el cambio por API no la recarga. Pendiente de fondo: que el proxy pase la IP
real (PROXY protocol en el L4, `X-Forwarded-For` de confianza en HTTP); mientras, la
protección anti-escaneo de Stalwart es inútil y peligrosa a la vez.

### 🔴 La caja no se sabe reconstruir (7-sep-2026)

El template `mail-svc` **no trae Stalwart** — su Dockerfile dice "lo instala el operador"—,
no hay ningún release (`currentReleaseId` vacío), y ni el binario (104 MB), ni `lego`
(68 MB), ni las unidades de systemd están en los `dataPaths`. **Hoy hay datos y nada con
qué leerlos.** Falta `scripts/stalwart-bootstrap.sh` (binarios, usuario `stalwart`,
directorios con su dueño, units) y un **simulacro cronometrado en una caja desechable**:
crear, bootstrap, restaurar el dump, comprobar IMAP, destruir. Sin ese número, el
respaldo es una promesa.

Respaldo consistente: `systemctl stop stalwart` + `--export` cuesta **22 s de caída** y da
840 KB en 19 subespacios. El reenvío y la Bandeja no se enteran (van por SES). Falta
comprobar que **restaura** (`--import` en un store vacío) y automatizarlo con `programar()`.

**No recrear la caja para cambiar de tier.** En `mail-svc` el tier es `custom` (2 vCPU,
2 GB): "bajar a micro" da la misma VM. Y recrear cambia el `sandboxId`, que se lleva por
delante `l4:…:993`, `l4:…:465` y el mapeo de dominio al 8080 — no migran solos.

### Sigue pendiente

**Probado de punta a punta el 7-sep-2026 (madrugada), en producción:** máscara creada desde
la app con buzón (`mijo@fancyfiles.app`, dominio creado solo en Stalwart) → perfil de Apple →
envío desde Apple Mail por SES (firmado por el dominio) → respuesta de Gmail recibida en la
Bandeja **y** en el buzón. Es el producto entero funcionando sobre un dominio de cliente.

**Antes de vender el primer buzón, en este orden:**
1. **SES Tenants** (un cliente no puede tumbar la reputación de todos). Verificar de entrada
   si el tenant se puede indicar por SMTP; si no, Stalwart debe entregar a la app en vez de
   a SES — un solo camino de salida que además da el contador de envíos y el log.
2. **Contador del 465**: hoy lo que sale de Apple Mail no descuenta de los 50/día. Hasta
   entonces "+100 envíos" no se publica como comprable.
3. **Una compra real en MercadoPago** del add-on `domain` (nunca se ha ejercitado contra MP;
   el webhook con `addon:` sí).
4. **Bootstrap reproducible de la caja** + simulacro cronometrado, y comprobar que el dump
   restaura. Sin eso, un incidente de disco es esta sesión otra vez.
5. **Medir índice/GB de buzón** con correo real: decide si 10 GB por $99 y +50 GB por $99
   se sostienen.
6. **Correo de recuperación de carrito a Oswaldo** (checkout `pending` del 26-ago; ahora empezar es gratis).
7. Blog (25 posts con precios viejos), campañas por mes (+5,000/$99, aprobación manual),
   borrar el secreto `IMAP_ENABLED_DOMAINS` en Fly, rotar `EASYBITS_API_KEY`,
   `TURNSTILE_SECRET` y el admin de Stalwart (viajaron por el chat).

### 🔥 Contexto original del análisis (agosto 2026)
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

- [x] ~~Revisar la lifecycle policy de `s3://mailmask-inbound`~~: era `expire-24h` del 23-ago al 6-sep; hoy 90 días y es decisión de producto (ver "Cuerpo del entrante y S3").
- [ ] **Rotar `TURNSTILE_SECRET`** en el panel de Cloudflare: la clave viajó por el chat el 6-sep-2026.
- [ ] **Probar la Bandeja en pareja, media hora.** Todos los bugs del 6-sep salieron de usarla diez minutos, no de las 485 pruebas: los atajos disparándose dentro del compositor, la lista latiendo sola por una animación en bucle, el plan "activo" con fecha vencida. Sin verificar todavía: la **colisión con dos personas de verdad**, el **logo de la firma en Gmail y Outlook** (se eligió URL sobre `cid:` justo para que no salga icono de adjunto) y el **contraste del tema claro** en la app — sospechosos: fila seleccionada, `<mark>` del resaltado de búsqueda y la barra ámbar de presencia.
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
- [ ] **S3 bucket permissions**: Verificar que no hay acceso público, policies mínimas. Aprovechar para mirar la lifecycle policy (ver arriba).
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
- [ ] **Definir estrategia de historial/almacenamiento**: retención por plan, flush automático, add-on de almacenamiento, UI de uso. Diferenciador clave vs competencia — discutir antes de implementar. **Estado real (6-sep-2026): no hay retención de ningún tipo.** `logDays` (`plans.ts`) sólo caduca filas de `email_logs`, que es el registro de reenvíos; los mensajes de la Bandeja no los borra nada salvo la papelera a los 15 días. La home decía "Historial de 15 / 90 días" y prometía MENOS de lo que damos: ya se corrigió a "Bandeja con el historial completo · registro de reenvíos N días". Si algún día se implementa retención de verdad, hay que volver a tocar esa copia (landing y pricing) **y el JSON-LD del FAQ**, que repite los mismos textos.
- [ ] **Configurar SES multi-tenancy y estrategia de reputación**: Sesión de investigación para definir arquitectura de tenants SES, configuration sets por dominio, políticas de envío (Standard vs Strict), métricas de reputación a monitorear, y plan de acción para aislar dominios de clientes. Estudiar docs de SES Tenants, VDM, y EventBridge antes de implementar.
- [ ] Evaluar pattern de almacenamiento de mensajes en Bandeja: ¿leer body de S3 on demand vs duplicar en SQLite? Investigar otros patterns (cache intermedio, pre-procesado a formato ligero, CDN/signed URLs). Concluir cuál es el mejor approach antes de implementar. **Ya no es teórico**: el 6-sep-2026 se perdieron los objetos de S3 de un dominio entero y el único rescate fue el texto plano del índice FTS (32 KB, sin formato ni adjuntos). Depender de S3 como fuente única del cuerpo tiene un costo demostrado.
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

  **Los tres de la sesión del 6-sep-2026**, que son los mejores del lote porque los tres tienen hallazgo real, código y síntoma medible, y los tres salieron de usar la app diez minutos, no de las 485 pruebas:
  1. **Los atajos de teclado que se escapan de un editor `contenteditable`.** El guardia miraba `tagName`, y Tiptap sustituye el `<textarea>` por un `<div>`: escribir "Ap" en una respuesta disparaba asignar y redactar, y `#` habría borrado la conversación a media frase. Antipatrón concreto con su snippet, que es la receta que funcionó en el de ReDoS.
  2. **Una animación en bucle sobre una clase reutilizada.** `is-new` existía para avisar de lo que acaba de llegar y traía un punto latiendo en bucle infinito; reusarla para "no leído" la puso en las treinta filas y la lista latía sola. Se junta con la segunda mitad: seleccionar reconstruía la lista entera, así que la animación de entrada se reproducía en todas a la vez.
  3. **Un plan "activo" que no activa nada.** `status: active` con `currentPeriodEnd` vencido devuelve cero de todo en `getUserPlanLimits`, así que el panel decía `equipo · active` mientras el correo se descartaba con "Forwarding blocked: no active plan". Cierra con la lección de diseño: un estado que se contradice a sí mismo debe avisar, no guardarse en silencio.
- **Checklist de meta tags para cada post nuevo** (auditado 2-sep-2026; 27 páginas salieron sin `twitter:site`). Copiar el `<head>` de `dominio-verificado-que-rebota-anatomia-ses.html`, que es la referencia completa, y verificar: `<title>` ≤ 60 caracteres con sufijo ` — MailMask`; `description` ≤ 160; `canonical`; Open Graph completo (`og:title`, `og:description`, `og:type=article`, `og:url`, `og:locale=es_MX`, `og:site_name`, `og:image` 1200×630 JPG con `width/height/alt/secure_url/type`); `article:published_time`, `article:modified_time`, `article:section`, `article:tag`; Twitter (`card=summary_large_image`, `site` y `creator` = `@HectorBlisS`, `title`, `description`, `image`); JSON-LD de `BlogPosting`, `BreadcrumbList` y `FAQPage` con las mismas preguntas que los `h2`. El `og:image:alt` debe describir la portada real, no el tema. Después: tarjeta y `ListItem` en `blog/index.html`, y `npx tsx scripts/gen-sitemap.ts`. Comprobación rápida: `diff <(grep -oE '<meta (name|property)="[^"]+"' public/blog/dominio-verificado-que-rebota-anatomia-ses.html | sort -u) <(… el post nuevo …)` debe salir vacío.
- **Estándar para posts nuevos** (aplicar desde ya, no esperar a la auditoría): cada post nace con al menos un diagrama o ilustración original en el cuerpo — SVG inline, no stock. SVG porque escala, pesa poco, se adapta al tema oscuro y se puede animar. Además, formato pensado para motores generativos (GEO): 4-8 `<h2>`, cada uno respondiendo **una** pregunta completa sin depender del contexto anterior, con la respuesta directa en la primera oración y párrafos de 2-3 líneas. Eso es lo que citan los buscadores con IA.
- [ ] **Evaluar qué features de IA añadir y promocionar** (sesión dedicada, con investigación previa). Punto de partida: hay **cero código de IA** en el repo, pero ya se publicaron dos posts que crean expectativa — `clasificador-automatico-emails-ia.html` y `respuestas-sugeridas-ia.html`, ambos en futuro ("estamos explorando", "cuándo estará disponible"). O sea, la demanda ya está sembrada y sin cobrar.

  Criterios para decidir: (1) qué se apoya en lo que **ya es sólido** — la Bandeja con historial persistente es el activo diferenciador, porque ningún competidor guarda contenido; (2) qué **valora y paga** la comunidad de verdad, no lo que está de moda — investigar antes de elegir; (3) qué se puede montar sobre los agentes de Formmy, que es la vía ya explorada en esos posts.

  Candidatos ya escritos en este backlog: clasificación automática de correos, respuestas sugeridas, el Radar de Actividad por alias (resumen semanal en lenguaje natural) y búsqueda semántica con pgvector. Falta priorizarlos con datos, no por intuición.

- [ ] **Guías de automatización con IA + aliases**: Blog posts y/o sección educativa enseñando a usuarios a automatizar workflows usando aliases específicos de MailMask + herramientas de IA. Ejemplos: alias dedicado para recibir notificaciones de n8n/Make/Zapier, alias como trigger de workflows AI, alias para clasificación automática de leads, alias temporal para campañas con análisis automático. Doble propósito: educar usuarios existentes y atraer audiencia técnica vía SEO. Investigar y documentar patrones concretos antes de escribir.

### Backlog (priorizado)
0. [x] ~~**`monthlyForwards`**~~ **Implementado 5-sep-2026**: tope **por cuenta y por mes** en `PLANS` (Básico 3,000; Equipo 30,000; legado 30k/100k). Contador en `send_counts` con llave `fwd:<correo>` y mes `YYYY-MM` (`incrementMonthlyForwards`/`getMonthlyForwards`). En `forwarding.ts`, al cruzar un alias: al 80% se manda `forwardCapWarning` una vez por mes (`claimOnce` en `tokens`), al 100% se manda `forwardCapReached`, se alerta al admin y el correo se **guarda en la Bandeja pero no se reenvía** (log `discarded` con "Tope mensual"). Peor caso Equipo: ~30k correos ≈ $110 MXN de SES contra $299 de ingreso; antes era ilimitado (~$13,000 MXN/mes teóricos). El dashboard muestra `forwards.current/limit` de `/api/auth/me`. Las tarjetas dicen "Hasta N correos reenviados al mes". Lo de abajo queda como historia del análisis.

   ~~**`monthlyForwards` — tope mensual para proteger margen. ⚠️ REVISITAR PARA ENTENDERLO MEJOR ANTES DE IMPLEMENTAR.**~~

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
- [x] ~~**SMTP relay**~~: Implementado. Credenciales SMTP para enviar desde código/SaaS (no clientes de correo). Plan Equipo (antes Developer). IAM user por credencial con policy scoped al dominio.
- [x] ~~**IMAP/POP (Dovecot)**~~: descartado. Se eligió **Stalwart** (Rust, S3 nativo, JMAP) y ya está corriendo; ver la sección de IMAP arriba. Dovecot no se evaluó más allá de la comparación inicial. Permitiría configurar clientes de correo (Apple Mail, Outlook, Thunderbird) con recepción + envío. Proyecto separado a futuro, no incluir en marketing actual.
- [ ] Probar checkout autenticado con email diferente al collector de MP
2. [ ] **SDK**: Cliente JS/TS para consumir la API de MailMask (crear aliases, listar dominios, etc.). Publicar en npm. Disponible en todos los planes.
3. [x] ~~**Webhooks**~~: API y entrega hechas (sep-2026). UI en el dashboard (pestaña Webhooks, `loadWebhooks` en `app.js`): **no crea** —el secreto debe quedar en el código del cliente, así que muestra el snippet del SDK—; lista, últimas 5 entregas con código HTTP/intentos/error, y botones Probar, Pausar y Eliminar. `webhooks.ts`: `emitEvent()` sólo encola en `webhook_deliveries`; el cron de cada minuto (`deliverPending`) hace el POST con `X-MailMask-Signature: sha256=HMAC(secret, timestamp.body)` y reintenta 1m/5m/30m/2h/12h (5 intentos). Eventos: `email.received` (forwarding), `email.sent` (send y bulk), `email.delivered`/`email.bounced`/`email.complained` (webhook de SES). `ensureConfigSetEventDestination` ahora también **actualiza** destinos viejos para que suscriban `delivery` (`CONFIG_SET_EVENT_TYPES` en `ses.ts`): corre al arrancar y en verify, así que tras el deploy todos los dominios lo emiten. Rutas `/api/domains/:id/webhooks[...]`, plan `webhooks: true` (Equipo), sólo https públicas (`isPrivateUrl`), máx 10 por dominio. El SDK exporta `verifyWebhookSignature` (WebCrypto).
- [ ] **Flush de historial / almacenamiento**: Basico/Freelancer tienen franja de 15-30 días de retención, después se hace flush automático. Developer incluye almacenamiento base para conservar todo su historial, y puede comprar más cuando se acabe (add-on por GB o por bloque). Definir: UI para ver uso de almacenamiento, alerta cuando se acerca al límite, flujo de compra de almacenamiento adicional, export antes de flush. Investigar costos S3/Postgres para pricing. **Nota competitiva:** Ningún competidor directo (SimpleLogin, ImprovMX, ForwardEmail, addy.io) almacena contenido de emails ni ofrece historial — todos son forwarding puro sin retención. Bandeja + historial persistente es diferenciador único que posiciona a MailMask más cerca de Helpscout/Intercom pero a fracción del costo y con máscaras incluidas. El almacenamiento como add-on es feature sin competencia en el segmento.
- [x] ~~**Blog**~~: 12 posts SEO publicados + index + blog.css integrado en landing.
- [ ] **Calculadora interactiva (lead magnet)**: Página pública con sliders/range inputs donde el usuario calcula cuánto ahorra vs Google Workspace según número de usuarios, dominios y buzones. Muestra comparativa de costo mensual/anual y CTA a registro. Funciona como lead magnet para SEO y compartir en redes.
- [ ] **Campaña "dominio gratis"**: Diseñar y ejecutar campaña de marketing aprovechando el feature de registro de dominio integrado. Definir: oferta (dominio gratis primer año con plan X, etc.), landing page dedicada, copy para email/redes, segmento objetivo, métricas de éxito. Coordinar con implementación de registro de dominios (Route 53).
- [x] ~~**Schema markup (structured data)**: Agregar JSON-LD a landing, blog y páginas clave para SEO. Schemas: Organization, Product, FAQPage, BlogPosting, BreadcrumbList, SoftwareApplication, ItemList. Mejora visibilidad en Google y rich snippets.~~
- [ ] **pgvector + RAG**: Habilitar extensión `pgvector` en Postgres, agregar columnas `embedding vector(1536)` a mensajes/conversaciones. Implementar pipeline de embedding (OpenAI/Anthropic) al recibir emails y búsqueda semántica en Bandeja. Verificar soporte en hosting (Neon/Supabase soportan pgvector). Caso de uso: buscar conversaciones por contexto, respuestas sugeridas, knowledge base por dominio.
- [ ] **Bandeja: asignar con select de team**: Cambiar input de email en modal de asignar por `<select>` que liste agentes del dominio (ya existe `GET /api/domains/:id/agents`).
4. [ ] **Members y permisos por dominio**: UI completa para invitar miembros a un dominio, asignar roles (owner, editor, viewer), gestionar permisos. Incluye: modelo de datos (tabla members/invitations), endpoints CRUD, UI en dashboard para listar/invitar/remover miembros, control de acceso en todos los endpoints de dominio según rol. **Pendiente definir**: qué pueden ver los members (aliases, reglas, logs, bandeja), cómo se comparten dominios (invitación por email, link), qué ve un member en su dashboard cuando tiene acceso a dominios de otros usuarios.
5. [ ] **Registro de dominios integrado (Route 53)**: El usuario busca, paga y tiene dominio+email funcionando sin configurar nada. Flujo: (1) búsqueda de disponibilidad via `route53domains:CheckDomainAvailability`, (2) pago via MercadoPago (cargo anual separado de suscripción), (3) registro via `route53domains:RegisterDomain` con contacto del usuario, (4) configuración DNS automática en hosted zone — MX apuntando a SES inbound, TXT de verificación, CNAMEs de DKIM — via `route53:ChangeResourceRecordSets`, (5) verificación SES automática del dominio. SDKs: `@aws-sdk/client-route-53` + `@aws-sdk/client-route-53-domains`. UI: buscador de dominio en dashboard con precios por TLD, estado de registro, renovación automática. Billing: cargo anual por dominio (~$12-14 USD .com) cobrado como producto separado en MP o incluido en planes altos. Modelo DB: tabla `domain_registrations` (domainId, route53OperationId, registeredAt, expiresAt, autoRenew, contactInfo). **Diferenciador clave**: ningún competidor (SimpleLogin, ImprovMX, ForwardEmail, addy.io) ofrece registro+configuración integrada — todos requieren que el usuario vaya a su registrador y configure DNS manualmente. Esto convierte a MailMask en solución "todo en uno" para email profesional.

### Pendientes de la Bandeja (7-sep-2026, tarde)

- 🔴 **El alto del iframe del correo: cuatro intentos fallidos, revertido.** Cuatro
  fallidos: medir al insertar (mide el `about:blank` de 16 px), ocultar con
  `opacity` y alto 0 (sin alto no se maqueta y `scrollHeight` da 0), y el
  envoltorio colapsado con sondeo (`ajustarIframe` en `public/js/bandeja.js`).
  Sigue naciendo chico y creciendo a la vista. Antes de un cuarto intento a
  ciegas, **medir en el navegador de verdad** qué devuelve `scrollHeight` en
  cada paso: puede ser que `srcdoc` + `sandbox="allow-same-origin"` no dé
  acceso a `contentDocument` en Chrome y todo el sondeo esté leyendo cero
  siempre, cayendo al fallback de los 400 px. Alternativa sin medir: alto fijo
  generoso con "ver más", o mover el ajuste a un `postMessage` desde dentro,
  que exige `allow-scripts` y hay que sopesar contra XSS.
  El cuarto intento (envoltorio colapsado con el iframe a 2000 px) salió peor:
  el correo de TikTok usa `height:100%`, así que **rellena el alto de medición**
  y `scrollHeight` devuelve los 2000 px, no el alto real. Cualquier medida
  hecha dentro de un iframe alto hereda ese problema con correos de tabla al
  100%. Todo revertido en 650e3a5; vuelve el alto fijo de 420 px.
