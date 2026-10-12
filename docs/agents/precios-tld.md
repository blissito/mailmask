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
debajo de lo prometido, en las dos ramas: costo de 200 MXN → 259 MXN en vez de 260
(`Math.ceil(260/10)*10 - 1 = 259`), y 400 MXN × 1.2 = 480 → 479 MXN. Lo fijan **dos pruebas
`{ todo: true }`**, una por rama; las pruebas «buenas» del cruce usan a propósito costos que no
caen en decena (208 y 420 MXN), para no fijar el defecto como esperado. El día que se arregle
el redondeo se quitan los dos `todo`; mientras, quitar sólo uno deja la contradicción de que la
suite afirme 25900 donde la otra prueba exige 26000.

**Cómo aplicarlo:** el precio termina en un PreApproval de MercadoPago que ya no se puede
cambiar, así que cobrar bajo se repite en cada renovación. Antes de tocar `alPrecioDeVenta`,
`MARGEN`, `MARGEN_MINIMO_MXN` o `CACHE_MS`, corre `npx tsx --test "tld-pricing.test.ts"` y
espera los literales de la suite.
