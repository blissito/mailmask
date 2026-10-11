# Dependencias y CI

- **Fijado en `ci.yml`:** las actions van fijadas por SHA de commit con comentario de versión (`@<sha> # v7`). Al subir de versión, toma el SHA del tag (`git ls-remote https://github.com/actions/checkout 'refs/tags/vN*'`), no el de una rama.
- **`deploy.yml`:** las actions van por tag (`@v7`). Mantén el diff de ese archivo al mínimo: publica la imagen de prod en GHCR al mergear a main.
- **`ci.yml` es el check requerido de main.** Si un job se rompe, bloquea todos los PRs; valida cualquier cambio de CI en el propio PR antes de mergear.
- **Desfase de Node:** CI corre Node 22 y prod `node:20-alpine`. `@types/node` ^26 describe APIs de Node 26, así que typecheck verde no garantiza que la API exista en prod. Antes de usar una API reciente, confirma que existe en Node 20.
- **`cli/` es un paquete aparte** con su propio `package.json` y lock; se queda en `@types/node` ^22 a propósito (`engines: node >=18`). Súbelo por separado.
- **TypeScript:** el raíz (servidor) va en TS 7 (`typescript` ^7); `tsc` es el compilador nativo y no expone la API JS. `cli/` y `sdk/` siguen en TS 5 a propósito: `sdk` usa tsup con `dts: true`, que depende de la API JS de TypeScript. Súbelos por separado y sólo si esa dependencia deja de existir. Evidencia de versión: `npx tsc -v` tras `npm ci`.
