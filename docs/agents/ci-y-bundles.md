# CI y bundles del chat

**Qué:** el job `verify` de `.github/workflows/ci.yml` corre `npm run typecheck` (`tsc --noEmit -p .`),
las pruebas y `npm run build`, que compila el chat (`build:chat`). Los bundles
`public/js/docs-chat.js` (chat de /docs) y `public/js/asistente.js` se **suben compilados**: el
Dockerfile no los construye, así que producción sirve lo que esté en el repo.

**Por qué importa:** subir `@formmy.app/chat`, `react` o `streamdown` en `package.json` no cambia
nada en producción hasta recompilar y subir los bundles. Un bump de dependabot compila en CI pero
deja el chat viejo.

**Cómo aplicarlo:**
1. Tras un bump de formmy/react/streamdown (o un cambio en `docs-chat.tsx` / `asistente/`), corre
   `npm run build:chat` y sube los dos `.js`.
2. Abre /docs en la preview y haz una pregunta al chat: compilar no prueba que el protocolo con
   www.formmy.app siga igual.
3. El paso «Bundles del chat al día» del CI compara los bundles con lo recompilado y deja un
   `::warning` si no coinciden. **Avisa, no bloquea** (`continue-on-error`): dependabot no puede
   empujar bundles a su rama y bloquear dejaría en rojo cada bump. Si el aviso sale siempre aun
   recién recompilado, esbuild no es reproducible entre máquinas: quita el paso, deja la compilación.

**Trampa:** `declaration: true` en `tsconfig.json` oculta errores TS4xxx mientras haya errores
semánticos; al arreglar los primeros pueden aparecer otros (pasó con `pg.ts`).
