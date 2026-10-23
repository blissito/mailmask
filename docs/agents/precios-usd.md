# Precios en USD de referencia en /pricing

**Qué:** el selector MXN / USD de `/pricing`. Es sólo una referencia de pantalla: el cobro sigue
en MXN por MercadoPago, y la página lo dice («Se cobra en MXN por MercadoPago; tu banco hace la
conversión»). El monto en dólares sale como `≈ US$X.XX` con el tipo de cambio del día.

**Por qué no se cobra en USD:** MercadoPago (cuenta MX) sólo cobra en MXN. Cambiar la moneda de
cobro pediría otra cuenta y otro flujo; esta versión sólo cambia cómo se leen los montos.

## Cómo está armado

- `GET /api/fx` (main.ts) responde `{ rate, fetchedAt }` desde **`ultimaLectura()`** de `fx.ts`,
  con `Cache-Control` de 1 h, y 404 si no hay ninguna lectura. La página entonces se queda en MXN.
- `public/js/pricing-fx.js` tiene `aUsd(mxn, tipo)` pura (redondea al centavo, sin truncar) y
  `precioEnMoneda(mxn)`, que `landing.js` usa para el toggle anual.
- Cada monto guarda su valor en MXN en `data-mxn` (con `data-prefijo` para el «+»). Así el texto
  que ya cambió nunca se lee de vuelta: leer `textContent` del toggle anual con la página en USD
  daría un número mal.

## Trampas

- **Mostrar, no cotizar:** para el monto en pantalla va `ultimaLectura()`. `tipoDeCambio()` es el
  máximo de 30 días y es el que cotiza el cobro; usarlo aquí mostraría un precio que no es el del día.
- **El JSON-LD queda en MXN** (`priceCurrency: "MXN"`) y el checkout no cambia. `pricing-usd.test.ts`
  falla si alguien pone `priceCurrency": "USD"`.
- **`hidden` contra `flex`:** el selector usa la clase `hidden`, no el atributo `hidden`, y lleva
  `flex` antes; Tailwind pone `.hidden` después y gana. Con sólo `flex-col` no tiene efecto.
- Sin tipo de cambio el selector no aparece: no hay que mostrarlo deshabilitado.
