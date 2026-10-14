# Diálogos y avisos en /app

En `/app` no se usan `confirm()` ni `alert()` del navegador: salen como ventana del sistema, sin la
marca, con «Aceptar» en lugar del verbo, y algunos navegadores permiten silenciarlos.

## Cómo se hace

- **Confirmar una acción** (borrar, quitar, revocar, cancelar):
  `if (!(await confirmar({ titulo: "Eliminar dominio", mensaje: "¿…?", accion: "Eliminar dominio" }))) return;`
  La función que lo llama tiene que ser `async`. `accion` es el verbo exacto del botón; nunca
  «Aceptar» ni «OK».
- **`peligro: false`** sólo para lo que no borra ni revoca (hoy: generar contraseña nueva, que deja
  sin efecto la anterior pero no borra datos). El botón rojo es el default.
- **Errores**: `showToast(mensaje, true)`, el aviso rojo de la esquina.

## Por qué así

- `confirmar()` no bloquea: `confirm()` detenía el código y una función que dependía de ese paro hay
  que revisarla.
- Es un `<dialog id="confirm-dialog">` abierto con `showModal()`: foco atrapado y fondo inerte
  nativos. El scroll se libera en su evento `close`, una vez por apertura (`openModals` cuenta).
- Escape dentro del diálogo no debe cerrar también el modal de debajo (p. ej. el del buzón): el
  atajo global de `app.js` lo ignora mientras `#confirm-dialog` está abierto.

## Cómo se prueba

`app-dialogos.test.ts` lee `app.js` y `app.html` (sin DOM): no quedan `confirm(`/`alert(`, existe el
diálogo, cada acción usa su verbo y ninguna dice «Aceptar». Foco, Escape y clic fuera se verifican a
mano en la preview.

Si cambias clases de Tailwind en el diálogo, corre `npm run build:css` y sube `styles.css` en el mismo PR.
