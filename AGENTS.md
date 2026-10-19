# AGENTS.md

Instrucciones para agentes de código (formato abierto: https://agents.md).
Las reglas detalladas del proyecto viven en `CLAUDE.md`: léelo también.

## Comandos
- `npm ci` — instalar
- `npm run dev` — levantar en local
- `npm test` — pruebas

Antes de abrir un PR, todo lo anterior tiene que pasar en local.

El entorno de pruebas del paquete raíz (Node 22, SQLite en `data/`, sin Postgres ni Redis)
está declarado en [`.ghosty/factory.md`](.ghosty/factory.md): es lo que la fábrica lee para
dejar una caja limpia lista antes de correr la suite.

## Arquitectura
Monolito con Elysia (Node + `tsx`), servido desde `main.ts`; sin carpeta `src/`,
cada dominio vive en su propio archivo en la raíz (`auth.ts`, `db.ts`, `ses.ts`,
`route53.ts`, `forwarding.ts`, `webhooks.ts`, `mcp.ts`...). Persistencia en
SQLite vía Drizzle (`db.ts`), en un volumen único de Fly.io — por eso el deploy
tiene downtime estructural. AWS (SES/S3/Route53) para correo y dominios,
MercadoPago para cobros. `sdk/` es el cliente npm que también alimenta el
servidor MCP en `mcp.ts`. `cli/` es la CLI de terminal construida sobre ese
mismo SDK — paquete npm aparte, con su propio `package.json` (ver
`docs/agents/mailmask-cli.md`). `public/` sirve el dashboard y
`public/skills/` las Agent Skills (se generan en el build, no se commitean).
`scripts/` trae utilidades puntuales, no forman parte del server.

## Convenciones
- Cambios chicos y con pruebas; un PR por pedido.
- No agregues dependencias sin decirlo en el PR.

## Qué no tocar
- `.github/` (CI y reglas del repo): los cambios ahí los revisa una persona.
- Secretos y archivos `.env*`: nunca se suben al repo.
- El deploy (`fly deploy`): siempre desde un worktree limpio de HEAD, nunca
  desde un workdir con cambios sin commit — un deploy sucio ya tumbó producción.
- `sdk/` sin su contraparte en `sdk/../sdk.test.ts`: un método que no coincide
  con la ruta real del servidor salió roto a producción antes sin dar error.
- Lo generado bajo `public/skills/` (`index.json`, `*.tar.gz`): lo produce el
  build, no se commitea.

## Conocimiento
Fichas cortas en `docs/agents/`: decisiones, trampas y glosario que el código no dice solo.
Léelas antes de tocar su tema; si tu cambio fija una convención o descubres una trampa, escribe o
pon al día la ficha en el mismo PR y agrega aquí su renglón.
<!-- - [Tema](docs/agents/tema.md) — de qué trata, en una línea -->
- [CLI de MailMask](docs/agents/mailmask-cli.md) — convenciones de `cli/`: framework de comandos, auth, exit codes, la regla dura de no tocar DNS `managed`, `rules`/`suppressions`, `logo` sin `--url`, `dns import` de sólo lectura, `inbox`/`canned`/`signature` (get siempre en texto; attachment no crea archivo si falla), `send`/`logs` (por qué `send email`, `--from` sin `fromLocal`, confirmar antes de subir) y, para cobros y dominios registrados, liga impresa y nunca EPP; y en citty 0.2 los positionales van con `required: true as const`; y en textos visibles de la CLI el recurso es «dirección», nunca «alias» ni «máscara».
- [SEO de páginas públicas](docs/agents/seo-paginas-publicas.md) — las reglas viven en `seo-checks.ts` y las corren `public-seo.test.ts` (todas las páginas del sitemap, contra su lista `PENDIENTES`), `docs-seo.test.ts` y `pricing-seo.test.ts` (éste amarra los precios de `/pricing` a `plans.ts`); metas en un bloque, `@graph`, `dateModified` visible, imagen OG propia y `llms.txt` sin contradecir `/docs`; y `alternativa-google-workspace.test.ts` (la comparativa con Google Workspace: precios de MailMask atados a `plans.ts`, la tabla completa sólo ahí y los precios de Google citados con enlace y fecha) y `blog-enlaces-landings.test.ts` (cada artículo del blog enlaza su landing una sola vez, con ancla descriptiva y desde el cuerpo).
- [Landing de dominios](docs/agents/landing-dominios.md) — por qué `/dominios` no publica ninguna cifra por extensión (el precio se ve al buscar el dominio, no en una tabla de «desde»): la única cifra permitida es `DOMAIN_ANNUAL_PRICE` de `plans.ts`, y `dominios-seo.test.ts` la amarra; la sección de transferencia describe lo que de verdad hace `domain-transfer.ts` (requisitos antes de cobrar, inventario de DNS aprobado antes de mover nameservers).
- [Precio de transferencia de TLD](docs/agents/precios-tld.md) — la tabla curada manda, `alPrecioDeVenta` (×1.2 vs piso de 60 MXN) y las dos trampas de su suite: mockear ANTES de importar, y la caché que se comparte entre casos (el 0 sí se cachea, el null no).
- [Dependencias y CI](docs/agents/dependencias-ci.md) — actions por SHA en `ci.yml` y por tag en `deploy.yml`, `ci.yml` requerido, desfase Node 22/20 vs `@types/node` 26, `cli/` aparte, en `sdk/` TS 7 emite los tipos con `tsc` (job `verify-sdk`) y el build los baja a sintaxis que un TS 4.9 entiende, la regla de tailwindcss (major ignorado en Dependabot, se queda en 3.x hasta migrar por el issue #54) Deploy en rojo si prod no reporta el SHA en ~5 min (prod es la caja app-host, no Fly) y la regla de `recordOrder`: `onConflictDoNothing` siempre con `target` (sin destino, un choque de folio se leía como duplicado y apagaba el aviso de cobro fallido).
- [Firma de webhooks](docs/agents/firma-webhooks.md) — el mensaje firmado es `timestamp.body` con milisegundos en string, prefijo `sha256=` + 64 hex, tolerancia estricta de 5 min (el borde exacto pasa) y el chequeo de largo antes de `timingSafeEqual` (esa función lanza con largos distintos).
- [Modo preview](docs/agents/preview.md) — `PREVIEW=1` levanta la app sin efectos afuera: no programa crons, no corre el backfill ni el arranque con efectos, y SES, MercadoPago y Route 53 Domains contestan 503; el porqué del incidente del 11-oct-2026 y la regla de que todo cliente o bloque de arranque nuevo con efectos pasa por `preview.ts`.
- [Pruebas con módulos doblados y base compartida](docs/agents/pruebas-mocks.md) — mock.module sólo intercepta si el módulo se importa en caliente y con el módulo real esparcido; la base de pruebas es una sola (aísla por ids y URLs); deliverPending procesa todas las pendientes vencidas y Date.now mockeado no reprograma new Date(); renombrar un export obliga a tocar su nombre en `namedExports` de toda la suite (es una llave de texto: ni `tsc` ni la prueba avisan). Además: `mock.timers.enable({ apis: ["Date"] })` sí congela el reloj y no frena WebCrypto (para el borde exacto de una tolerancia), y el contrato con otro paquete se lee del fuente con regex —importar `cli/src/args.ts` da TS2307. Suma `dns-import.test.ts`: un built-in se dobla como cualquier módulo (`mock.module("node:dns/promises", …)` antes del import, con el real esparcido y un `Resolver` fiel a `{ ttl: true }`), y el `setTimeout` de 45 s que `snapshotDns` deja vivo se neutraliza con `mock.timers` (el `unref` de `test-setup.mjs` sólo alcanza los de más de un minuto, así que el de 45 s mantendría vivo el proceso). Suma `domain-sync.test.ts`: al SDK de AWS se le sustituye sólo `Route53DomainsClient` con el módulo esparcido, así que `constructor.name` sí es el del comando real y el cliente falso despacha por nombre; tiene que ser fiel (`Expiry`/`ExpirationDate` como `Date`, el dominio ausente como error con `name: "DomainNotFound"`) y llevar estado (el candado que se acaba de poner se ve en el detalle siguiente), y como `route53.ts` cachea el cliente en `_route53Domains` el doble va antes del primer import; contar los `ListDomainsCommand` es lo que demuestra que se siguió el `NextPageMarker`. Suma `scheduler.test.ts`: para probar que un proceso termina solo se lanza un hijo con `-e` (sin `argv[1]`, así `isServer` es `false`) y se compara contra un control que sí agenda un cron y por eso no muere; el doble de `node-cron` no puede llevar `default` en `namedExports` o el módulo sintético no compila. Suma `addon-sync.test.ts`: `reconcilePendingAddons` barre TODOS los add-ons `pending` con preapproval (en las pruebas se apagan en el `beforeEach` los que dejó el caso anterior y se afirma por id y por correo), su `./emails.ts` va doblado porque el `sendTemplate` real manda por SES y arrastra `sendAlert`, y el borde de 35 días se mide con ±1 h de margen porque `setDate` es en hora local. Suma S3 y SES: se dobla `@aws-sdk/client-*` y no `ses.ts` (`getS3` no se exporta, `getSesInbound` cachea el cliente), y la paginación se afirma con el `ContinuationToken` de la segunda llamada.

- [Pruebas de auth](docs/agents/pruebas-auth.md) — PBKDF2 de 600 000 iteraciones se paga una vez y los usuarios que sólo tienen que existir nacen con un `passwordHash` de relleno; el hash legado (`needsRehash`), el token de otro secreto y el vencido se fabrican a mano con `crypto.subtle`, porque `deriveKey` no se exporta, `JWT_SECRET` y su `CryptoKey` se cachean al importar y `exp < now` es estricto; `Secure` se decide al importar con `FLY_APP_NAME`, así que en pruebas no está. El enlace de verificación vive en `verify-email.test.ts`: el reenvío no invalida el anterior (bug conocido, fijado en la prueba).
- [App de ChatGPT](docs/agents/chatgpt-app-directorio.md) — requisitos del directorio de OpenAI y dónde se cumplen (`/.well-known/openai-apps-challenge` con `OPENAI_APPS_CHALLENGE`, `iss` RFC 9207, DCR con el redirect de ChatGPT, las tres pistas), riesgo de las ligas de pago, textos en inglés, 5+3 casos, íconos en `public/img/chatgpt-app/` y la cuenta de revisor pendiente.
- [Diseño de las landings públicas](docs/agents/diseno-landings.md) — la paleta del sitio público (tokens de `input.css` vía `bg-bg`/`text-fg`/`border-line`, rojo de máscara; nada de hex sueltos ni `zinc-*`, que son de `/app` y `/bandeja`), el tema claro/oscuro con `data-theme` de `theme.js`, las fuentes (Bricolage Grotesque en titulares, Inter de cuerpo, JetBrains Mono en `.eyebrow`), las piezas reutilizables (`.btn-primary`, `.card`, `.mock`…) con la regla de dejarlas fuera de `@layer` para que Tailwind no las purgue, la regla de recompilar y subir `styles.css` en el mismo PR (el Dockerfile no lo corre y el CI no compara el diff), las ilustraciones `-il.jpg` (1200×800, < 200 KB, línea negra gruesa) y la historia del luchador enmascarado contra los monstruos del correo.
- [Diálogos y avisos en /app](docs/agents/dialogos-app.md) — nunca confirm()/alert() en /app: confirmar() con el verbo exacto del botón (peligro:false sólo para lo no destructivo) y los errores por showToast(msg, true); la regla de Escape con el diálogo abierto y el scroll liberado una vez.
- [Bandeja: borrar con «Deshacer»](docs/agents/bandeja-deshacer.md) — borrar en la Bandeja no pide confirm(): la red es la papelera de 15 días y el aviso «Deshacer» (6 s); el lote se restaura id por id y sólo los ids que estaban vivos (un id ya borrado da 404), y un toast normal limpia el «Deshacer» previo.

## Pull requests
- Rama nueva desde `main`; el PR explica qué cambia y cómo se probó.
- El CI tiene que quedar en verde.
