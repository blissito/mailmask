# Pruebas con módulos doblados y base de datos compartida

Cómo se prueban cosas que hablan con S3 o con la red sin salir a internet, y qué se da por
sentado de la base de pruebas. Nace de `webhooks-delivery.test.ts` y `backup.test.ts`.

## Doblar un módulo: el doble va ANTES del import, y con el módulo real esparcido

```ts
const realSes = await import("./ses.ts");
mock.module("./ses.ts", { namedExports: { ...realSes, putBackupBinaryToS3, deleteOldBackups } });
const backup = await import("./backup.ts");   // en caliente: si ya se importó, el doble llega tarde
```

- `mock.module` sólo intercepta si el módulo se resuelve **después** de declararlo. El módulo
  bajo prueba y todo lo que lo importe van con `await import()` dentro de `before()`.
- Los `namedExports` **sustituyen** el módulo entero: declarar sólo tus dos funciones deja sin lo
  suyo a cualquiera que importe otra cosa de `ses.ts` — y `db.ts`, y medio repo, lo hacen.
  Esparce el módulo real y pisa nada más lo que doblas.
- Los imports del código dicen `./ses.js` y el doble se declara sobre `./ses.ts`: tsx los resuelve
  al mismo módulo (así lo hace `domain-renewal.test.ts`). No lo cambies a `.js`.
- **Renombrar un export rompe los dobles, y `tsc` no lo ve**: el nombre en `namedExports` es una
  llave de texto, no un símbolo. Si el módulo real pasa de `delegacionActiva` a `getDelegationStatus`
  y el doble sigue declarando el nombre viejo, sin `...real` el módulo doblado se queda **sin** ese
  export y truena al llamarlo; con `...real` es peor, porque el doble deja de interceptar **en
  silencio** y la prueba sigue verde corriendo la implementación de verdad. Al renombrar un export,
  busca su nombre en `namedExports` de toda la suite (`grep -rn 'nombreViejo' *.test.ts`).
- Hace falta `--experimental-test-module-mocks`, que ya viene en el script `test`.

## La base de pruebas es UNA para toda la suite

`--test-concurrency=1` corre los archivos de uno en uno, pero lo que deja uno lo encuentra el
siguiente: nunca asumas base vacía. Aísla con ids, dominios y **URLs** únicos, y filtra por los
tuyos al afirmar.

## `deliverPending` procesa TODAS las entregas vencidas, no las tuyas

Levanta de la tabla todo lo `pending` con `nextAt` vencido, así que el `fetch` falso recibe también
entregas de otras pruebas. Inyecta el `fetch` falso y cuenta sólo las llamadas a **la URL de tu
webhook** — incluido el «no se le llamó» del webhook apagado.

## Reprogramar sin congelar el reloj

Un reintento deja `nextAt` en el futuro (primer backoff: 60 s), así que la llamada siguiente ya no
lo ve vencido. Para probar el intento siguiente, muévelo al pasado con un update directo:

```ts
db.update(webhookDeliveries).set({ nextAt: new Date(Date.now() - 1000).toISOString() })
  .where(eq(webhookDeliveries.id, id)).run();
```

Y para comprobar el backoff, acota con un rango medido alrededor de la llamada
(`[antes, después] + RETRY_DELAYS_MS[n]`). Ojo: `mock.method(Date, "now")` no congela `new Date()`,
que es justo lo que usan `emitEvent` y `deliverPending` para armar `nextAt`.

## Dos pedidos que crean el mismo archivo nuevo chocan siempre

Git no puede fusionar un `add/add` del mismo camino: dos PRs que crean `webhooks.test.ts` chocan
aunque su contenido sea distinto. Si el archivo ya está tomado, usa otro nombre en vez de esperar
el merge.

## Congelar el reloj con `mock.timers` (y por qué `mock.method(Date, "now")` no basta)

Para el borde exacto de una ventana de tiempo (`|ahora - ts| > tolerancia`) hace falta que
`Date.now()` NO avance entre el cálculo del timestamp y la verificación, y arriba ya quedó dicho que
`mock.method(Date, "now")` sólo sustituye ese método. `mock.timers.enable({ apis: ["Date"], now: T0 })`
congela el reloj entero (`mock.timers.reset()` lo suelta en el `afterEach`): así el caso justo en el
límite pasa y `+1 ms` se rechaza sin depender de lo que tarde la máquina. Lo usa `sdk-verify.test.ts`.

**No frena WebCrypto.** `verifyWebhookSignature` del SDK (`sdk/src/verify.ts`) firma con
`crypto.subtle` y es `async`; congelar sólo `Date` no toca las promesas, así que la verificación
resuelve normal (probado en Node 22). Si algún día dejara de resolver, el plan B es pasar
`toleranceMs` explícito y usar timestamps relativos con margen amplio en vez del borde exacto.

## Un contrato con otro paquete: leer el fuente, no importarlo

`cli/src/args.ts` hace `import type` de `@easybits.cloud/mailmask`, que no está en el root: importarlo
desde una prueba del root da TS2307 y rompe `npm run typecheck`. Para vigilar una constante del CLI
(`BILLING_KINDS`) sin importarlo, se lee el archivo como texto y se extrae con regex
(`plans.test.ts`), igual que `docs-cli.test.ts` lee los comandos. Con `assert.ok(match)` y una lista
no vacía ANTES de comparar, la prueba falla —en vez de pasar vacía— si la constante cambia de forma.

