# Modo preview

Una preview es la app servida **para mirarla**, no un segundo entorno de producción. Con
`PREVIEW=1` el proceso levanta igual —escucha en `PORT`, responde `/`, deja navegar— pero no
puede tener efectos afuera: ni manda correo, ni cobra, ni compra o renueva un dominio.

## Por qué existe

El 11-oct-2026 una preview arrancó con el `.env` real: al levantar reparó las receipt rules
de SES, tocó el tópico SNS de producción y programó los crons. Un envío o un cobro desde esa
copia se cobra de verdad, y el webhook de pago puede registrar o transferir un dominio en
Route 53, que cuesta dinero real y es irreversible.

## Qué se apaga

| Qué | Dónde está la compuerta |
|---|---|
| Arranque con efectos: reparación SES/SNS, tipo de cambio, reconciliación de dominios y suscripciones SNS | `main.ts`, bloque de arranque, tras `debeArrancarEfectos` |
| Backfill de búsqueda (baja correo de S3) | `cron.ts:312`, tras `debeArrancarEfectos` |
| Todos los crons | `scheduler.ts` → `programar()`, que ya pasa por `debeProgramar` |
| SES: salida, inbound, receipt rules, `sendAlert` | getters `getSesOutbound`/`getSesInbound` de `ses.ts` |
| MercadoPago: alta y cancelación de cobros (`PreApproval`, `Preference`, PUT a `/preapproval`) | `assertNoPreview("mercadopago")` en las rutas y en `cancelMpPreapproval` (`main.ts`) |
| Route 53 Domains: registrar, transferir y renovar | getter `getRoute53Domains()` de `route53.ts` |

Lo que **no** se apaga: las lecturas y las demás escrituras a AWS que dispara una persona a
mano (crear una hosted zone, una identidad SES, subir a S3) siguen funcionando; bloquearlas
dejaría media consola inservible en la preview. Tampoco se apaga `app.listen` — la preview
tiene que responder. Y ojo: la compuerta de Route 53 Domains va en el cliente, así que en
preview también se caen sus lecturas (buscar disponibilidad, leer el detalle de un dominio).

## Cómo aplicarlo

- Un cliente de AWS nuevo va detrás de un getter que llame a `assertNoPreview(...)`, nunca con
  un `new XClient(...)` suelto dentro de una ruta.
- Un bloque de arranque con efectos usa `debeArrancarEfectos(esServidor, esPreview())` y deja
  una línea de log que diga que se omitió.
- Los endpoints traducen `PreviewDeshabilitado` a 503: los `catch` que se comen el error
  llaman a `preview503(err)` primero, y el `onError` global cubre a los que no lo atrapan.

Pruebas: `preview.test.ts` (el interruptor y las funciones puras), `preview-guards.test.ts`
(los clientes de AWS), `preview-boot.test.ts` (arranca `main.ts` con `PREVIEW=1`: 200 en `/` y
cero peticiones a AWS, más el control sin `PREVIEW`) y `preview-mp.test.ts` (cobros por HTTP).
