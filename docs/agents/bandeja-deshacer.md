# Bandeja: borrar sin confirm() y con «Deshacer»

Borrar en la Bandeja no pide confirmación. La red es la papelera de 15 días (soft-delete,
`deletedAt`) y el aviso «Deshacer», que dura 6 s y restaura lo borrado con un clic. Prueba:
`bandeja-deshacer.test.ts` (estática: `bandeja.js` no tiene `confirm(` y ambos flujos llaman a `/restore`).

## Qué hace cada pieza
- `deleteConversation()` (la abierta) y `borrarSeleccionadas()` (el lote) muestran `toastDeshacer(msg, onUndo)`.
- El lote se restaura **id por id** con `Promise.allSettled`: `bulk-delete` sólo devuelve el conteo
  (`deleted`), no qué ids borró.

## Trampas
- **Un id ya borrado no se restaura.** La lista lo pinta «eliminado» y puede seleccionarse. El
  servidor sólo restaura lo que tiene `deletedAt` y responde 404 al resto. Por eso el lote deshace
  sólo los ids que estaban vivos ANTES del borrado.
- **Un toast normal limpia el «Deshacer» previo** (su botón y su timer). Si no, heredaría el botón o
  lo apagaría antes de los 6 s.
- **El dominio se captura al empezar la acción.** «Deshacer» restaura en ese dominio, aunque la
  persona cambie de dominio durante los 6 s.
- Si una restauración falla, en el lote el aviso dice cuántas no se pudieron restaurar.

Fuera de alcance: los `confirm()` de `app.js`, la vista de papelera y una ruta `bulk-restore`.
