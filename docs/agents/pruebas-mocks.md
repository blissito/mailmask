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
