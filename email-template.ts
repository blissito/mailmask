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
    background-color: #ffffff;
    -webkit-font-smoothing: antialiased;
  }
  .email-wrapper {
    width: 100%;
    background-color: #ffffff;
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
    color: #18181b;
    word-break: break-word;
  }
  p {
    margin: 0 0 16px 0;
    font-size: 16px;
    line-height: 1.6;
    color: #18181b;
  }
  h1 {
    margin: 0 0 16px 0;
    font-size: 26px;
    line-height: 1.25;
    font-weight: 700;
    color: #18181b;
  }
  h2 {
    margin: 24px 0 12px 0;
    font-size: 22px;
    line-height: 1.3;
    font-weight: 700;
    color: #18181b;
  }
  h3 {
    margin: 20px 0 10px 0;
    font-size: 18px;
    line-height: 1.3;
    font-weight: 700;
    color: #18181b;
  }
  a {
    color: #2563eb;
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
    color: #18181b;
  }
  blockquote {
    margin: 0 0 16px 0;
    padding: 4px 0 4px 16px;
    border-left: 3px solid #e4e4e7;
    color: #52525b;
  }
  code {
    font-family: Consolas, Monaco, 'Courier New', monospace;
    font-size: 14px;
    background-color: #f4f4f5;
    padding: 2px 5px;
    border-radius: 3px;
  }
  pre {
    margin: 0 0 16px 0;
    padding: 12px;
    background-color: #f4f4f5;
    border-radius: 6px;
    font-family: Consolas, Monaco, 'Courier New', monospace;
    font-size: 14px;
    line-height: 1.5;
    /* pre-wrap y no scroll: en un correo no hay barra de desplazamiento. */
    white-space: pre-wrap;
  }
  hr {
    border: 0;
    border-top: 1px solid #e4e4e7;
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
     la tabla: Word lo pinta de forma más consistente ahí. El borde izquierdo grueso
     es lo que sigue leyéndose como "caja" si el cliente ignora el fondo. */
  table.alert { margin: 0 0 16px 0; }
  .alert-cell {
    padding: 12px 16px;
    border-left: 4px solid #71717a;
    background-color: #fafafa;
    font-size: 15px;
    line-height: 1.55;
    color: #18181b;
  }
  .alert-cell p.alert-title {
    margin: 0 0 4px 0;
    font-size: 13px;
    font-weight: 700;
    letter-spacing: .02em;
    text-transform: uppercase;
    color: #52525b;
  }
  .alert-cell p { margin: 0 0 8px 0; font-size: 15px; }
  .alert-cell p:last-child { margin-bottom: 0; }

  .alert-cell-note { border-left-color: #2563eb; background-color: #eff6ff; }
  .alert-cell p.alert-title-note { color: #1d4ed8; }
  .alert-cell-tip { border-left-color: #16a34a; background-color: #f0fdf4; }
  .alert-cell p.alert-title-tip { color: #15803d; }
  .alert-cell-important { border-left-color: #7c3aed; background-color: #faf5ff; }
  .alert-cell p.alert-title-important { color: #6d28d9; }
  .alert-cell-warning { border-left-color: #d97706; background-color: #fffbeb; }
  .alert-cell p.alert-title-warning { color: #b45309; }
  .alert-cell-caution { border-left-color: #dc2626; background-color: #fef2f2; }
  .alert-cell p.alert-title-caution { color: #b91c1c; }

  table.data {
    width: 100%;
    border-collapse: collapse;
    margin: 0 0 16px 0;
  }
  table.data th, table.data td {
    padding: 8px 10px;
    border: 1px solid #e4e4e7;
    text-align: left;
    font-size: 15px;
  }
  table.data th {
    background-color: #fafafa;
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
