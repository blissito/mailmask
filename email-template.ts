// Plantilla del HTML de correo.
//
// La estructura de tablas anidadas y la hoja de estilos siguen los Postmark
// transactional templates (MIT, github.com/activecampaign/postmark-templates),
// que son la referencia probada de la comunidad para Outlook, Gmail y Apple Mail.
//
// Aquí el CSS se escribe LEGIBLE, con selectores normales. `juice` lo convierte a
// atributos `style=` inline antes de enviar, porque Gmail recorta el `<head>` —y
// con él cualquier `<style>`— en mensajes de más de ~102 KB. Nadie debería
// escribir estilos inline a mano en este archivo.

/**
 * Los colores del correo, en un solo lugar: cambiar uno aquí lo cambia en toda la
 * hoja, y una prueba lo vigila (cada valor aparece una sola vez en este archivo).
 *
 * Los tonos de las cajas de color NO van aquí: son su propia tabla (`ALERT_TONOS`),
 * que es donde se agrega un tipo nuevo.
 */
export const PALETA = {
  /** Texto principal: párrafos, encabezados, listas y cuerpo de las cajas. */
  texto: "#1c1917",
  /** Texto secundario: citas y antetítulo de las cajas. */
  textoSuave: "#57534e",
  /** Fondo de la página y de los encabezados de tabla. */
  fondo: "#faf6ee",
  /** Fondo de los bloques de código. */
  fondoCodigo: "#f2ecdf",
  /** Líneas: separadores, bordes de tabla y el filo de la cita. */
  borde: "#e4dccd",
  /** Enlaces. */
  enlace: "#b31f33",
} as const;

/**
 * Un tono por tipo de caja de color (la sintaxis "> [!NOTE]" de GitHub). Agregar un
 * tipo es agregar su renglón aquí: el CSS de cada uno lo arma `emailAlertStyles()`,
 * que mantiene juntas la regla de la celda y la del título.
 */
export const ALERT_TONOS = {
  note: { borde: "#b31f33", fondo: "#eff6ff", titulo: "#1d4ed8" },
  tip: { borde: "#16a34a", fondo: "#f0fdf4", titulo: "#15803d" },
  important: { borde: "#7c3aed", fondo: "#faf5ff", titulo: "#6d28d9" },
  warning: { borde: "#d97706", fondo: "#fffbeb", titulo: "#b45309" },
  caution: { borde: "#dc2626", fondo: "#fef2f2", titulo: "#b91c1c" },
} as const;

/**
 * El CSS de las cinco cajas de color, generado desde `ALERT_TONOS` y en el mismo
 * orden en que estaba escrito a mano. El borde izquierdo grueso es lo que sigue
 * leyéndose como "caja" si el cliente ignora el fondo.
 */
function emailAlertStyles(): string {
  return Object.entries(ALERT_TONOS)
    .map(
      ([tipo, tono]) =>
        `  .alert-cell-${tipo} { border-left-color: ${tono.borde}; background-color: ${tono.fondo}; }\n` +
        `  .alert-cell p.alert-title-${tipo} { color: ${tono.titulo}; }`,
    )
    .join("\n");
}

/**
 * Estilos del cuerpo del correo. Reglas que NO se pueden usar aquí, porque el
 * Outlook de Windows renderiza con el motor de Word y las ignora o las rompe:
 * flexbox, grid, float, position, calc(), propiedades lógicas.
 *
 * El espaciado va con `padding` en celdas y `margin` en bloques de texto; Word
 * respeta el margen vertical de `p`/`h2`/`ul`, pero no el de un `div` de layout.
 */
export const EMAIL_STYLES = `
  body {
    margin: 0;
    padding: 0;
    background-color: ${PALETA.fondo};
    -webkit-font-smoothing: antialiased;
  }
  .email-wrapper {
    width: 100%;
    background-color: ${PALETA.fondo};
  }
  .email-content {
    width: 100%;
    max-width: 600px;
    margin: 0 auto;
  }
  .email-body {
    padding: 24px 12px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    font-size: 16px;
    line-height: 1.6;
    color: ${PALETA.texto};
    word-break: break-word;
  }
  p {
    margin: 0 0 16px 0;
    font-size: 16px;
    line-height: 1.6;
    color: ${PALETA.texto};
  }
  h1 {
    margin: 0 0 16px 0;
    font-size: 26px;
    line-height: 1.25;
    font-weight: 700;
    color: ${PALETA.texto};
  }
  h2 {
    margin: 24px 0 12px 0;
    font-size: 22px;
    line-height: 1.3;
    font-weight: 700;
    color: ${PALETA.texto};
  }
  h3 {
    margin: 20px 0 10px 0;
    font-size: 18px;
    line-height: 1.3;
    font-weight: 700;
    color: ${PALETA.texto};
  }
  a {
    color: ${PALETA.enlace};
    text-decoration: underline;
  }
  strong { font-weight: 700; }
  em { font-style: italic; }
  ul, ol {
    margin: 0 0 16px 0;
    /* En px y no en em: Word no aplica el padding por defecto de la lista y las
       viñetas quedan pegadas al borde izquierdo. */
    padding-left: 24px;
  }
  li {
    margin: 0 0 6px 0;
    font-size: 16px;
    line-height: 1.6;
    color: ${PALETA.texto};
  }
  blockquote {
    margin: 0 0 16px 0;
    padding: 4px 0 4px 16px;
    border-left: 3px solid ${PALETA.borde};
    color: ${PALETA.textoSuave};
  }
  code {
    font-family: Consolas, Monaco, 'Courier New', monospace;
    font-size: 14px;
    background-color: ${PALETA.fondoCodigo};
    padding: 2px 5px;
    border-radius: 3px;
  }
  pre {
    margin: 0 0 16px 0;
    padding: 12px;
    background-color: ${PALETA.fondoCodigo};
    border-radius: 6px;
    font-family: Consolas, Monaco, 'Courier New', monospace;
    font-size: 14px;
    line-height: 1.5;
    /* pre-wrap y no scroll: en un correo no hay barra de desplazamiento. */
    white-space: pre-wrap;
  }
  hr {
    border: 0;
    border-top: 1px solid ${PALETA.borde};
    margin: 24px 0;
  }
  img {
    /* El atributo width= del <img> lo pone el renderizador; esto es el refuerzo
       para los clientes que sí entienden CSS. */
    max-width: 100%;
    height: auto;
    border: 0;
    outline: none;
    text-decoration: none;
    display: block;
  }
  /* Cajas de color (sintaxis "> [!NOTE]" de GitHub). El fondo va en la celda, no en
     la tabla: Word lo pinta de forma más consistente ahí. */
  table.alert { margin: 0 0 16px 0; }
  .alert-cell {
    padding: 12px 16px;
    border-left: 4px solid #78716c;
    background-color: ${PALETA.fondo};
    font-size: 15px;
    line-height: 1.55;
    color: ${PALETA.texto};
  }
  .alert-cell p.alert-title {
    margin: 0 0 4px 0;
    font-size: 13px;
    font-weight: 700;
    letter-spacing: .02em;
    text-transform: uppercase;
    color: ${PALETA.textoSuave};
  }
  .alert-cell p { margin: 0 0 8px 0; font-size: 15px; }
  .alert-cell p:last-child { margin-bottom: 0; }

${emailAlertStyles()}

  table.data {
    width: 100%;
    border-collapse: collapse;
    margin: 0 0 16px 0;
  }
  table.data th, table.data td {
    padding: 8px 10px;
    border: 1px solid ${PALETA.borde};
    text-align: left;
    font-size: 15px;
  }
  table.data th {
    background-color: ${PALETA.fondo};
    font-weight: 700;
  }
`;

/**
 * Envuelve el cuerpo ya renderizado en el shell de tablas. La tabla exterior a
 * 100% con `align="center"` es lo que centra el contenido en Word, que ignora
 * `margin: 0 auto` sobre un div.
 */
export function wrapEmailHtml(bodyHtml: string): string {
  return `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<style>${EMAIL_STYLES}</style>
</head>
<body>
<table class="email-wrapper" role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
<tr>
<td align="center">
<table class="email-content" role="presentation" cellpadding="0" cellspacing="0" border="0" width="600">
<tr>
<td class="email-body">${bodyHtml}</td>
</tr>
</table>
</td>
</tr>
</table>
</body>
</html>`;
}
