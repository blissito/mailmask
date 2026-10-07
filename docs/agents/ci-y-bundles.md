# CI y bundles del front

**Qué:** el job `verify` de `.github/workflows/ci.yml` corre `npm run typecheck`, las pruebas y
`npm run build`. `typecheck` revisa tres cosas:
- el servidor (`tsconfig.json`, los `.ts` de la raíz);
- el front que esbuild compila **sin** revisar tipos (`tsconfig.web.json`: `public/js/**/*.ts(x)`,
  o sea el chat de /docs, el asistente y el composer);
- el SDK (`sdk/`, con `--skipLibCheck` porque comparte `node_modules` con la raíz).

`build` compila el chat (`build:chat`) y el composer (`build:composer`). Los bundles
`public/js/docs-chat.js`, `asistente.js` y `composer.js` se **suben compilados**: el Dockerfile no
los construye, así que producción sirve lo que esté en el repo.

**Fuera del typecheck, a propósito:** `scripts/` (operaciones de una vez, se corren con `tsx`). Hoy
tres no compilan: `migrate-subscription.ts` usa el add-on `sends25` que ya no existe y
`setup-agent.ts`/`upload-docs.ts` no ven `Formmy` porque los tipos de `@formmy.app/chat` 0.0.20
reexportan sin extensión (`export * from "./core/client"`) y NodeNext no los resuelve. Si un script
vuelve a ser de uso diario, arréglalo y súmalo a `typecheck`.

**Por qué importa:** subir `@formmy.app/chat`, `react` o `streamdown` en `package.json` no cambia
nada en producción hasta recompilar y subir los bundles. Un bump de dependabot compila en CI pero
deja el chat viejo.

**Cómo aplicarlo:**
1. Tras un bump de formmy/react/streamdown/tiptap (o un cambio en `docs-chat.tsx`, `asistente/` o
   `composer.ts`), corre `npm run build` y sube los `.js`.
2. Abre /docs en la preview y haz una pregunta al chat: compilar no prueba que el protocolo con
   www.formmy.app siga igual.
3. El paso «Bundles del front al día» del CI compara los bundles con lo recompilado y deja un
   `::warning` si no coinciden. **Avisa, no bloquea** (`continue-on-error`): dependabot no puede
   empujar bundles a su rama y bloquear dejaría en rojo cada bump. Si el aviso sale siempre aun
   recién recompilado, esbuild no es reproducible entre máquinas: quita el paso, deja la compilación.

**Trampa:** `declaration: true` en `tsconfig.json` oculta errores TS4xxx mientras haya errores
semánticos; al arreglar los primeros pueden aparecer otros (pasó con `pg.ts`).

**Trampa 2:** `tiptap-markdown` no declara su storage en el tipo `Storage` de tiptap 3; `composer.ts`
lo declara con `declare module "@tiptap/core"`. Sin eso `editor.storage.markdown` no compila.
