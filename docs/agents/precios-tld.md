# Precio de transferencia de un TLD (`tld-pricing.ts`)

**Qué:** de dónde sale el precio que se cobra por mover un dominio, y las dos trampas que
hacen fallar —o pasar en falso— su suite (`tld-pricing.test.ts`).

**El orden del cálculo:** tabla curada (`TLD_PRICES` de `db.ts`) → precio vivo de AWS
(`route53.js#listTldPrice`) → `alPrecioDeVenta` = `max(costo×1.2, costo+60 MXN)` redondeado a
decenas menos uno. `0` o `null` de AWS es «sin precio», no una ganga. Los montos esperados en
las pruebas van como literales hechos a mano (51 USD × 20 = 1020 → **1229 MXN**), nunca
reimplementando la fórmula: una prueba que copia la lógica pasa siempre.

## Trampa 1: `mock.module` va ANTES de importar el módulo

`fx.js` se importa de forma **estática** y `cache` es un `Map` a nivel de módulo. Mockea
`./fx.ts` y `./route53.ts` y sólo entonces `await import("./tld-pricing.ts")`; si mockeas
después, el módulo real ya quedó cargado y las pruebas cotizan con el tipo de cambio real.

## Trampa 2: la caché se comparte entre casos, y no todos los «sin precio» se cachean

- Usa **un TLD distinto por caso** (la caché es `Map` de módulo): si no, el caso siguiente
  hereda el precio —o el «no hay precio»— del anterior y la prueba pasa por el motivo equivocado.
- Un `null` o una excepción de AWS **no** se guardan: la siguiente llamada vuelve a preguntar.
- Un **`0` sí** se guarda (el `cache.set` va antes de descartar el cero): la segunda llamada no
  toca AWS. Afirmar lo contrario pone el CI en rojo.

## Bug abierto (documentado, sin arreglar)

Cuando el precio calculado cae **exacto en una decena**, el `-1` del redondeo queda 1 MXN por
debajo del piso: costo de 200 MXN → 259 MXN en vez de 260 (`Math.ceil(260/10)*10 - 1 = 259`).
Está fijado con `{ todo: true }` en la suite; el día que se arregle, se quita el `todo`. Lo
mismo pasa con el `×1.2` cuando su resultado es múltiplo de 10 (no pierde contra el piso, pero
sí contra lo que promete el comentario de «hacia arriba, nunca hacia abajo»).

**Cómo aplicarlo:** el precio termina en un PreApproval de MercadoPago que ya no se puede
cambiar, así que cobrar bajo se repite en cada renovación. Antes de tocar `alPrecioDeVenta`,
`MARGEN`, `MARGEN_MINIMO_MXN` o `CACHE_MS`, corre `npx tsx --test "tld-pricing.test.ts"` y
espera los literales de la suite.
