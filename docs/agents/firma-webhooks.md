# Firma de webhooks

El contrato entre `deliverPending` (lo que mandamos) y el receptor (lo que verifica). Las
pruebas que lo fijan están en `webhooks.test.ts` (raíz).

- **El mensaje firmado es `${timestamp}.${body}`** con HMAC-SHA256 y el secreto del webhook;
  la firma sale como `sha256=` + 64 hex (71 caracteres). El timestamp son **milisegundos en
  string** (`String(Date.now())`), no segundos ni ISO: un receptor que asuma otra unidad
  rechaza todo.
- **Cambiar el formato rompe a todos los receptores a la vez.** Por eso el formato y la
  ventana son contrato, no detalle: la suite lo fija contra un HMAC calculado aparte de
  `signPayload` (si la firma sólo se comparara contra sí misma, cambiar el mensaje a
  `${body}.${timestamp}` seguiría en verde), y un refactor que conserve el formato la deja
  en verde igual.
- **La tolerancia es estricta y el timestamp entra dos veces:** el valor numérico se compara
  con `Math.abs(Date.now() - ts) > toleranceMs` (por defecto 5 min) y el string original
  entra en el mensaje firmado. Justo a 5 min **pasa**; se rechaza al pasarse por 1 ms.
- **El timestamp que no es número regresa `false`, no lanza:** `Number("abc")` es `NaN` y
  `!Number.isFinite` corta antes de firmar.
- **Trampa: el chequeo de largo va antes de `timingSafeEqual`.** Esa función lanza si los
  buffers miden distinto, y el largo de la firma lo elige quien llama. Una firma truncada,
  vacía o con relleno debe dar `false` sin excepción — si alguien reordena esas dos líneas,
  la entrada maliciosa tumba la verificación. Lo cubre el caso de firmas de otro largo.
- **Ojo con el nombre:** `webhook.test.ts` (singular) es del webhook de MercadoPago/SNS, otro
  archivo. Éste es `webhooks.ts` (plural), los webhooks por dominio.
