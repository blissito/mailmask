# AGENTS.md

Instrucciones para agentes de código (formato abierto: https://agents.md).
Las reglas detalladas del proyecto viven en `CLAUDE.md`: léelo también.

## Comandos
- `npm ci` — instalar
- `npm run dev` — levantar en local
- `npm test` — pruebas

Antes de abrir un PR, todo lo anterior tiene que pasar en local.

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
- [CLI de MailMask](docs/agents/mailmask-cli.md) — convenciones de `cli/`: framework de comandos, auth, exit codes, la regla dura de no tocar DNS `managed`, `rules`/`suppressions`, `logo` sin `--url` y `dns import` de sólo lectura e `inbox`/`canned`/`signature` (get siempre en texto; attachment no crea archivo si falla).
- [SEO de páginas públicas](docs/agents/seo-paginas-publicas.md) — metas en un bloque, `@graph`, `dateModified` visible, imagen OG propia y `llms.txt` sin contradecir `/docs`.

## Pull requests
- Rama nueva desde `main`; el PR explica qué cambia y cómo se probó.
- El CI tiene que quedar en verde.
