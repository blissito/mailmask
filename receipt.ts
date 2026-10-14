// Recibo imprimible de una orden (/recibo/:folio). Comprobante de pago, no CFDI: la
// factura sigue siendo por correo a soporte con el folio.
import type { Order } from "./db.js";
import { escHtml, SUPPORT_EMAIL } from "./emails.js";

// Sólo letras, números y guiones: es lo que acepta `next` del login para volver aquí.
export const RECEIPT_PATH = /^\/recibo\/[A-Za-z0-9-]{1,40}$/;

const KIND_LABEL: Record<Order["kind"], string> = {
  charge: "Pagado",
  failed_charge: "Cargo rechazado",
  courtesy: "Cortesía",
  cancellation: "Cancelación",
};

const fmtDate = (iso: string) =>
  new Date(iso).toLocaleDateString("es-MX", { day: "numeric", month: "long", year: "numeric", timeZone: "America/Mexico_City" });

const fmtMoney = (cents: number, currency: string) =>
  `$${(cents / 100).toLocaleString("es-MX", { minimumFractionDigits: 2, maximumFractionDigits: 2 })} ${currency}`;

export function renderReceipt(order: Order): string {
  const period = order.periodStart && order.periodEnd
    ? `${fmtDate(order.periodStart)} – ${fmtDate(order.periodEnd)}`
    : order.periodEnd ? `hasta el ${fmtDate(order.periodEnd)}` : "";
  const reference = order.mpPaymentId ?? order.mpAuthorizedPaymentId ?? order.mpPreapprovalId;
  const row = (label: string, value: string) =>
    `<tr><th>${label}</th><td>${value}</td></tr>`;

  return `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Recibo ${escHtml(order.number)} — MailMask</title>
<style>
  :root { color-scheme: light; }
  body { margin: 0; background: #f4f1ea; color: #1c1917; font: 15px/1.5 -apple-system, "Segoe UI", Inter, sans-serif; }
  main { max-width: 640px; margin: 32px auto; background: #fff; border: 1px solid #e7e2d8; border-radius: 12px; padding: 40px; }
  header { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; border-bottom: 1px solid #e7e2d8; padding-bottom: 24px; }
  header img { height: 32px; }
  .folio { text-align: right; font-size: 13px; color: #57534e; }
  .folio strong { display: block; font: 600 16px ui-monospace, "JetBrains Mono", monospace; color: #1c1917; }
  h1 { font-size: 20px; margin: 24px 0 4px; }
  .total { font-size: 32px; font-weight: 700; margin: 8px 0 24px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 10px 0; border-bottom: 1px solid #f0ece4; vertical-align: top; }
  th { width: 38%; font-weight: 500; color: #57534e; }
  td { word-break: break-word; }
  .mono { font-family: ui-monospace, "JetBrains Mono", monospace; font-size: 13px; }
  footer { margin-top: 28px; font-size: 12px; color: #78716c; }
  .actions { max-width: 640px; margin: 0 auto 32px; text-align: right; }
  .hint { font-size: 12px; color: #78716c; margin-top: 6px; }
  button { font: inherit; padding: 8px 18px; border-radius: 8px; border: 1px solid #1c1917; background: #1c1917; color: #fff; cursor: pointer; }
  @media (max-width: 680px) { main { margin: 0; border-radius: 0; border: 0; padding: 24px 16px; } .actions { padding: 0 16px; } }
  /* Carta vertical: el diálogo de impresión la toma como diseño por defecto. */
  @page { size: letter portrait; margin: 18mm 20mm; }
  @media print {
    body { background: #fff; font-size: 12pt; }
    main { max-width: none; margin: 0; border: 0; padding: 0; }
    header img { height: 40px; }
    h1 { font-size: 18pt; margin-top: 32px; }
    .total { font-size: 30pt; margin-bottom: 32px; }
    th, td { padding: 12px 0; }
    footer { font-size: 10pt; margin-top: 40px; }
    .actions { display: none; }
  }
</style>
</head>
<body>
<main>
  <header>
    <img src="/img/brand/wordmark.svg" alt="MailMask">
    <div class="folio">Recibo<strong>${escHtml(order.number)}</strong></div>
  </header>
  <h1>${escHtml(order.description)}</h1>
  <div class="total">${fmtMoney(order.amountCents, order.currency)}</div>
  <table>
    ${row("Estado", KIND_LABEL[order.kind] ?? escHtml(order.kind))}
    ${row("Fecha", fmtDate(order.occurredAt))}
    ${period ? row("Periodo", period) : ""}
    ${row("Cliente", escHtml(order.userEmail))}
    ${reference ? row("Referencia de pago", `<span class="mono">MercadoPago ${escHtml(reference)}</span>`) : ""}
    ${order.note ? row("Nota", escHtml(order.note)) : ""}
    ${row("Emitido por", "MailMask · www.mailmask.studio")}
  </table>
  <footer>Este recibo es un comprobante de pago, no una factura. ¿Necesitas CFDI? Escríbenos a ${escHtml(SUPPORT_EMAIL)} con tu RFC, razón social, régimen fiscal, código postal, uso de CFDI y el folio ${escHtml(order.number)}.</footer>
</main>
<div class="actions"><button id="print">Imprimir o guardar PDF</button><div class="hint">Tamaño carta, vertical.</div></div>
<script src="/js/recibo.js"></script>
</body>
</html>`;
}
