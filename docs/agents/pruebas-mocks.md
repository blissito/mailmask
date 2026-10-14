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

## Doblar un built-in (`node:dns/promises`) y el timer que `snapshotDns` deja vivo

`dns-import.test.ts` prueba el inventario de DNS sin tocar la red. Dos trampas que no salen en
las fichas de arriba:

- **El built-in se dobla igual que un módulo del repo**: el doble va antes y con el real esparcido,
  `mock.module("node:dns/promises", { namedExports: { ...await import("node:dns/promises"), Resolver: FakeResolver } })`,
  y `await import("./dns-import.ts")` dentro de `before()`. El doble guarda lo que recibe
  `setServers` y lee una tabla `"nombre|TIPO" → valor`; lo que no está lanza un error con
  `code: "ENOTFOUND"` (o `ENODATA`). Tiene que ser **fiel al `Resolver` real**: `resolve4(nombre)`
  sin `{ ttl: true }` devuelve direcciones pelonas y con él `{ address, ttl }`. Si el doble siempre
  devolviera la forma con TTL, `snapshotDns` recibiría objetos donde espera strings al resolver las
  IPs de los nameservers, y elegiría mal a quién preguntarle — con las pruebas en verde.
- **El `setTimeout` de `TOTAL_TIMEOUT_MS` (45 s) de `snapshotDns` no se limpia nunca** (es el bug
  que reporta el PR, no algo que se arregle desde la prueba). `test-setup.mjs` sólo hace `unref` de
  los timers de más de un minuto, así que con timers de verdad cada caso dejaría el proceso vivo
  otros 45 s: `beforeEach` hace `mock.timers.enable({ apis: ["setTimeout"] })` y `afterEach`
  `mock.timers.reset()`. Para ejercer el camino `truncado: true` a propósito: un doble que nunca
  responde y `mock.timers.tick(45_000)`, con un `setImmediate` en medio — `snapshotDns` consulta
  los NS (que sí contestan) ANTES de armar el corte, y sin dejar pasar ese instante el tick no
  encuentra todavía el timer.

## Un contrato con otro paquete: leer el fuente, no importarlo

`cli/src/args.ts` hace `import type` de `@easybits.cloud/mailmask`, que no está en el root: importarlo
desde una prueba del root da TS2307 y rompe `npm run typecheck`. Para vigilar una constante del CLI
(`BILLING_KINDS`) sin importarlo, se lee el archivo como texto y se extrae con regex
(`plans.test.ts`), igual que `docs-cli.test.ts` lee los comandos. Con `assert.ok(match)` y una lista
no vacía ANTES de comparar, la prueba falla —en vez de pasar vacía— si la constante cambia de forma.


## `pending_agent_actions` va con FK: crea el usuario antes de archivar

`pending_agent_actions.user_email` es FK a `users.email` con `ON DELETE CASCADE`, y `pg.ts` enciende
`foreign_keys`, así que archivar una acción (`requireConfirmation` con `via: "turn"`) truena con
`FOREIGN KEY constraint failed` si ese email no existe. En `agent-actions.test.ts` cada prueba se
lleva su propio usuario: `createUser(email, "x")` de `db.ts` antes de tocar el módulo.

## Doblar el cliente de AWS (no `route53.ts`)

`domain-renewal.test.ts` y `transfer-lock.test.ts` doblan `./route53.ts` entero, así que nunca pasan
por la forma en que AWS contesta. `domain-sync.test.ts` hace lo contrario: `route53.ts` corre REAL y
lo único falso es el SDK.

- **Se sustituye sólo `Route53DomainsClient`, con el módulo esparcido.** Los `ListDomainsCommand`,
  `GetDomainDetailCommand` y `EnableDomainTransferLockCommand` que recibe el cliente falso son los
  de verdad, así que `cmd.constructor.name` trae el nombre bueno y el despacho es un `switch` por ese
  nombre. Registrar cada comando en una lista es lo que permite afirmar que se LLEGÓ a la segunda
  página: dos `ListDomainsCommand` = siguió el `NextPageMarker`.
- **Fidelidad o la prueba miente.** `ListDomains` contesta `{ Domains: [{ DomainName, Expiry, AutoRenew }], NextPageMarker? }`
  con `Expiry` como **`Date`** y no como texto (`route53.ts` hace `new Date(res.Expiry).toISOString()`);
  `GetDomainDetail` manda `ExpirationDate` como `Date`, `StatusList` —la ÚNICA fuente del candado— y
  `Nameservers: [{ Name }]`; y un dominio que no está en la cuenta lanza un error con
  **`name: "DomainNotFound"`**, que es lo que algún día distinguirá «no está» de «no pude preguntar».
  Un error de otra clase (throttling) se dobla también por `name` para poder probar ese camino.
- **El cliente se cachea por proceso.** `route53.ts` guarda el cliente en `_route53Domains`, así que
  el doble se declara ANTES de importar cualquier cosa que lo llame (el `await import("./domain-sync.ts")`
  va en `before()`, como en las demás pruebas del repo). Cada archivo corre en su propio proceso: el
  doble no ensucia a los otros.
- **El cliente falso lleva estado.** Al recibir `EnableDomainTransferLockCommand` marca el dominio como
  protegido, y el `GetDomainDetail` que `lockTransfer` pide justo después ya lo ve: así se fija que se
  guarda lo que AWS reporta, no lo que pedimos. Sin estado, la prueba del candado vencido pasaría sin
  probar nada.
- **`PREVIEW` no puede estar en `1`** en el proceso de pruebas: `getRoute53Domains()` llama
  `assertNoPreview` y truena antes de llegar al doble.

- **Una prueba de la lista vacía sólo prueba algo si el detalle TAMBIÉN falla.** Con
  `GetDomainDetail` contestando, la segunda opinión salva al dominio y la prueba pasa aunque la
  guarda de `enLaCuenta?.size` no esté: el escenario fiel es unas credenciales apuntando a OTRA
  cuenta (lista vacía *y* `DomainNotFound`). Se comprueba con el mutante `if (enLaCuenta && …)`.

## Probar que un proceso TERMINA SOLO (y que la prueba lo notaría)

`scheduler.test.ts` vigila que importar `cron.ts` y `forwarding.ts` ni agende un cron ni deje vivo
el proceso. Tres trampas:

- **El hijo va con `-e`, no con un archivo.** `node --import tsx --input-type=module -e "await import('./cron.ts')"`:
  sin `argv[1]`, `isServer` —que compara `process.argv[1]` contra `main.ts`— vale `false`, igual que
  dentro de la suite. Lanzar `main.ts` haría que el hijo agendara los crons y la prueba no probaría nada.
- **El control es obligatorio.** Un hijo que hace `cron.schedule("* * * * *", …)` directo tiene que
  seguir vivo tras unos segundos de reloj real; sin él, la prueba podría estar pasando porque un hijo
  lanzado con `-e` termina siempre, agende o no.
- **El hijo hereda `NODE_OPTIONS`** —o sea `test-setup.mjs`, con su `unref` de los timers de más de un
  minuto—, que es el mismo entorno que una prueba real. Se le quita `PREVIEW` para que no pase por
  `esPreview()` en vez de por `isServer`, lleva `DATABASE_PATH` en un `mkdtemp` porque importar
  `cron.ts` abre la base, y el tope se cierra con `SIGKILL` en el `finally`: un hijo colgado no se
  queda a vivir con el runner.

Y el doble del built-in, con `mock.module`: `defaultExport` con el real esparcido, pero los
`namedExports` **sin** la llave `default` — el módulo sintético no compila y truena con
«Unexpected token 'default'».

## `reconcilePendingAddons` barre TODOS los pendientes, y su `emails.ts` va doblado

`addon-sync.test.ts` fija la red de seguridad del webhook (el add-on que MP sí autorizó y nunca
notificó). Tres cosas que no se ven en el código:

- **El barrido es de la tabla entera**, no de «los tuyos» —el mismo caso que `deliverPending`—:
  levanta todo add-on `pending` con `mp_preapproval_id`. En un archivo con varios casos, lo que
  deja `pending` el caso anterior se vuelve a consultar en el siguiente, así que el `beforeEach` los
  apaga (`UPDATE addons SET status = 'expired' WHERE status = 'pending' AND mp_preapproval_id IS NOT NULL`)
  y las afirmaciones se filtran por id y por correo, nunca por el total de llamadas.
- **`./emails.ts` va doblado, con el módulo real esparcido**: el `sendTemplate` de verdad manda por
  SES (en pruebas `AWS_ENDPOINT_URL=http://localhost:1`) y eso arrastra `sendAlert`. El doble sólo
  cuenta los envíos. El `fetch` falso es una tabla `preapprovalId → respuesta`; el camino de error
  HTTP contesta `new Response(…, { status: 500 })` **en vez de lanzar**, porque lanzar ejercería el
  `catch` externo de la corrida, que es otro camino.
- El fin de periodo se calcula con `setDate(+35)` en **hora local**: se afirma por rango medido
  alrededor de la llamada con ±1 h de margen, no con el reloj congelado (`mock.method(Date, "now")`
  no frena `new Date()`).
