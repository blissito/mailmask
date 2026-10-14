// Recibo imprimible de una orden (/recibo/:folio). Comprobante de pago, no CFDI: la
// factura sigue siendo por correo a soporte con el folio.
import type { Order } from "./db.js";
import { escHtml, SUPPORT_EMAIL } from "./emails.js";

// Sólo letras, números y guiones: es lo que acepta `next` del login para volver aquí.
export const RECEIPT_PATH = /^\/recibo\/[A-Za-z0-9-]{1,40}$/;

// Sello por tipo de movimiento: el rojo de máscara sólo para lo pagado.
const STAMP: Record<Order["kind"], { label: string; tone: string }> = {
  charge: { label: "Pagado", tone: "paid" },
  failed_charge: { label: "Rechazado", tone: "muted" },
  courtesy: { label: "Cortesía", tone: "gold" },
  cancellation: { label: "Cancelado", tone: "muted" },
};

const fmtDate = (iso: string) =>
  new Date(iso).toLocaleDateString("es-MX", { day: "numeric", month: "long", year: "numeric", timeZone: "America/Mexico_City" });

const fmtMoney = (cents: number, currency: string) =>
  `$${(cents / 100).toLocaleString("es-MX", { minimumFractionDigits: 2, maximumFractionDigits: 2 })} ${currency}`;

export interface LineItem { concept: string; cents: number }

// Desglose a partir de la nota de la orden: «… (Concepto A) ($999 MXN) y (Concepto B) ($589 MXN).»
// Sólo se usa si los importes suman el total; si no, el recibo lleva un solo renglón.
export function breakdownFromNote(note: string | undefined, totalCents: number): LineItem[] | null {
  if (!note) return null;
  const items: LineItem[] = [];
  const re = /([^()$]+?)\s*\(\$([\d,]+(?:\.\d{1,2})?) MXN\)/g;
  for (const m of note.matchAll(re)) {
    const concept = m[1].replace(/^(?:\s*(?:incluye|y|,)\s+)+/i, "").replace(/^[\s,.;]+|[\s,.;]+$/g, "");
    if (!concept) return null;
    items.push({ concept: concept[0].toUpperCase() + concept.slice(1), cents: Math.round(Number(m[2].replace(/,/g, "")) * 100) });
  }
  if (items.length < 2 || items.reduce((s, i) => s + i.cents, 0) !== totalCents) return null;
  return items;
}

// `domain`: el dominio al que pertenece el cargo, resuelto por la ruta (el libro sólo
// guarda el id del add-on o de la registración).
// `domainExpiresAt`: vencimiento del registro del dominio, cuando lo registramos nosotros.
// `customerName`: nombre del perfil, si lo puso.
export function renderReceipt(
  order: Order,
  opts: { domain?: string | null; domainExpiresAt?: string | null; customerName?: string | null } = {},
): string {
  // Sin `periodStart` el periodo arranca el día del cargo: así lo da el webhook.
  const start = order.periodStart ?? (order.kind === "charge" ? order.occurredAt : undefined);
  const period = start && order.periodEnd
    ? `${fmtDate(start)} – ${fmtDate(order.periodEnd)}`
    : order.periodEnd ? `hasta el ${fmtDate(order.periodEnd)}` : "";
  const domain = opts.domain ? escHtml(opts.domain) : "";
  const reference = order.mpPaymentId ?? order.mpAuthorizedPaymentId ?? order.mpPreapprovalId;
  const stamp = STAMP[order.kind] ?? { label: escHtml(order.kind), tone: "muted" };
  const money = (c: number) => fmtMoney(c, order.currency);

  const items = breakdownFromNote(order.note, order.amountCents);
  const lines = items
    ? items.map((i) => ({ concept: escHtml(i.concept), sub: "", cents: i.cents }))
    : [{ concept: escHtml(order.description), sub: order.note ? escHtml(order.note) : "", cents: order.amountCents }];
  const itemRows = lines.map((l) => `
      <tr>
        <td>${l.concept}${domain && !items ? `<div class="sub">${domain}</div>` : ""}${l.sub ? `<div class="sub">${l.sub}</div>` : ""}</td>
        <td class="num">${money(l.cents)}</td>
      </tr>`).join("");

  const fact = (label: string, value: string, wide = false) =>
    `<div class="fact${wide ? " wide" : ""}"><dt>${label}</dt><dd>${value}</dd></div>`;

  return `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Recibo ${escHtml(order.number)} — MailMask</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,700;12..96,800&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@500&display=swap">
<style>
  :root {
    color-scheme: light;
    --bg: #faf6ee; --paper: #fffdf9; --inset: #f2ecdf; --line: #e4dccd;
    --fg: #1c1917; --muted: #57534e; --subtle: #78716c;
    --accent: #d7263d; --accent-text: #b31f33; --gold: #f2b705;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--fg); font: 15px/1.5 Inter, -apple-system, "Segoe UI", sans-serif;
    -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .display { font-family: "Bricolage Grotesque", Inter, sans-serif; font-weight: 800; letter-spacing: -0.02em; }
  .mono { font-family: "JetBrains Mono", ui-monospace, monospace; }
  main { max-width: 720px; margin: 32px auto; background: var(--paper); border: 2px solid var(--fg); border-radius: 14px;
    overflow: hidden; box-shadow: 8px 8px 0 var(--fg); }

  /* Banda en tinta y no en rojo: la máscara del logo es roja y se perdería. */
  .band { background: var(--fg); color: #fff; padding: 26px 36px 22px; display: flex; justify-content: space-between; align-items: center; gap: 16px;
    border-bottom: 6px solid var(--accent); }
  .band .folio { color: var(--gold); }
  .band img { height: 34px; display: block; }
  .band .doc { text-align: right; }
  .band .eyebrow { font-size: 11px; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; opacity: .85; }
  .band .folio { font-size: 18px; font-weight: 500; margin-top: 2px; }

  .body { padding: 30px 36px 28px; }
  .hero { display: flex; justify-content: space-between; align-items: flex-end; gap: 20px; }
  .hero .eyebrow { font-size: 11px; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; color: var(--accent-text); }
  .hero h1 { font-size: 26px; line-height: 1.1; margin: 6px 0 0; }
  .hero .amount { font-size: 44px; line-height: 1; margin-top: 14px; }
  .hero .amount small { font-family: Inter, sans-serif; font-size: 15px; font-weight: 600; color: var(--muted); letter-spacing: 0; }
  .stamp { flex: none; transform: rotate(-8deg); border: 3px solid currentColor; border-radius: 10px; padding: 8px 14px 6px; text-align: center;
    font-family: "Bricolage Grotesque", sans-serif; font-weight: 800; font-size: 22px; letter-spacing: .08em; text-transform: uppercase; line-height: 1; }
  .stamp span { display: block; font-family: Inter, sans-serif; font-size: 10px; font-weight: 600; letter-spacing: .06em; margin-top: 4px; }
  .stamp.paid { color: var(--accent); }
  .stamp.gold { color: #a87b00; }
  .stamp.muted { color: var(--subtle); }

  .parties { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin: 26px 0 22px; }
  .party { background: var(--inset); border-radius: 10px; padding: 14px 16px; }
  .party h2 { margin: 0 0 6px; font-size: 11px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; color: var(--subtle); }
  .party p { margin: 0; font-size: 14px; word-break: break-word; }
  .party strong { display: block; font-size: 15px; }

  table { width: 100%; border-collapse: collapse; }
  .items thead th { background: var(--fg); color: #fff; font-size: 11px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; text-align: left; padding: 9px 14px; }
  .items thead th:first-child { border-radius: 8px 0 0 8px; }
  .items thead th:last-child { border-radius: 0 8px 8px 0; }
  .items td { padding: 12px 14px; border-bottom: 1px solid var(--line); vertical-align: top; }
  .items .num { text-align: right; white-space: nowrap; width: 1%; padding-left: 20px; }
  .sub { font-size: 13px; color: var(--muted); margin-top: 2px; }
  .totals { display: flex; justify-content: flex-end; margin-top: 12px; }
  .totals div { min-width: 260px; display: flex; justify-content: space-between; align-items: baseline; gap: 20px;
    border-top: 3px solid var(--fg); padding: 10px 14px 0; }
  .totals span { font-size: 12px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; }
  .totals strong { font-size: 24px; }

  dl.facts { display: grid; grid-template-columns: 1fr 1fr; gap: 0 24px; margin: 26px 0 0; }
  .fact { border-top: 1px solid var(--line); padding: 10px 0; }
  .fact.wide { grid-column: 1 / -1; }
  .fact dt { font-size: 11px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; color: var(--subtle); }
  .fact dd { margin: 2px 0 0; font-size: 14px; }

  footer { margin-top: 22px; padding: 14px 16px; border: 1.5px dashed var(--line); border-radius: 10px; font-size: 12px; color: var(--muted); }
  footer b { color: var(--fg); }
  .thanks { margin-top: 18px; display: flex; justify-content: space-between; align-items: center; font-size: 13px; color: var(--muted); }
  .thanks .display { font-size: 18px; color: var(--fg); }

  .actions { max-width: 720px; margin: 0 auto 40px; text-align: right; }
  .hint { font-size: 12px; color: var(--subtle); margin-top: 6px; }
  button { font: 600 15px Inter, sans-serif; padding: 10px 20px; border-radius: 10px; border: 2px solid var(--fg); background: var(--accent); color: #fff;
    cursor: pointer; box-shadow: 4px 4px 0 var(--fg); }
  button:active { transform: translate(2px, 2px); box-shadow: 2px 2px 0 var(--fg); }

  @media (max-width: 720px) {
    main { margin: 0; border-radius: 0; border-width: 0; box-shadow: none; }
    .band, .body { padding-left: 16px; padding-right: 16px; }
    .hero { flex-direction: column; align-items: flex-start; }
    .hero .amount { font-size: 36px; }
    .parties, dl.facts { grid-template-columns: 1fr; }
    .actions { padding: 0 16px; }
  }

  /* Carta vertical y una sola hoja: el diálogo de impresión la toma como diseño por defecto. */
  @page { size: letter portrait; margin: 12mm 14mm; }
  @media print {
    body { background: #fff; font-size: 10pt; }
    main { max-width: none; margin: 0; box-shadow: none; border-width: 1.5px; }
    .band { padding: 18px 26px 16px; }
    .band img { height: 28px; }
    .body { padding: 20px 26px 18px; }
    .hero h1 { font-size: 19pt; }
    .hero .amount { font-size: 32pt; margin-top: 8px; }
    .parties { margin: 16px 0 14px; }
    .items td { padding: 8px 14px; }
    dl.facts { margin-top: 14px; }
    .fact { padding: 6px 0; }
    footer { margin-top: 14px; font-size: 8.5pt; }
    .thanks { margin-top: 12px; }
    main, table, tr, .fact { break-inside: avoid; }
    .actions { display: none; }
  }
</style>
</head>
<body>
<main>
  <div class="band">
    <img src="/img/brand/wordmark-on-dark.svg" alt="MailMask">
    <div class="doc">
      <div class="eyebrow">Recibo de pago</div>
      <div class="folio mono">${escHtml(order.number)}</div>
    </div>
  </div>

  <div class="body">
    <div class="hero">
      <div>
        <div class="eyebrow">${escHtml(order.description)}</div>
        <h1 class="display">${domain || escHtml(order.description)}</h1>
        <div class="amount display">${money(order.amountCents).replace(/ (\w+)$/, " <small>$1</small>")}</div>
      </div>
      <div class="stamp ${stamp.tone}">${stamp.label}<span>${fmtDate(order.occurredAt)}</span></div>
    </div>

    <div class="parties">
      <div class="party">
        <h2>Emitido por</h2>
        <p><strong>MailMask</strong>www.mailmask.studio<br>${escHtml(SUPPORT_EMAIL)}</p>
      </div>
      <div class="party">
        <h2>Cliente</h2>
        <p>${opts.customerName ? `<strong>${escHtml(opts.customerName)}</strong>` : ""}${escHtml(order.userEmail)}${domain ? `<br>${domain}` : ""}</p>
      </div>
    </div>

    <table class="items">
      <thead><tr><th>Concepto</th><th class="num">Importe</th></tr></thead>
      <tbody>${itemRows}
      </tbody>
    </table>
    <div class="totals"><div><span>Total</span><strong class="display">${money(order.amountCents)}</strong></div></div>

    <dl class="facts">
      ${fact("Fecha de pago", fmtDate(order.occurredAt))}
      ${fact("Estado", stamp.label)}
      ${period ? fact("Vigencia del servicio", period, true) : ""}
      ${opts.domainExpiresAt ? fact("Registro del dominio vigente hasta", fmtDate(opts.domainExpiresAt), true) : ""}
      ${reference ? fact("Referencia de pago", `<span class="mono">MercadoPago ${escHtml(reference)}</span>`, true) : ""}
    </dl>

    <footer><b>Este recibo es un comprobante de pago, no una factura.</b> ¿Necesitas CFDI? Escríbenos a ${escHtml(SUPPORT_EMAIL)} con tu RFC, razón social, régimen fiscal, código postal, uso de CFDI y el folio ${escHtml(order.number)}.</footer>
    <div class="thanks"><span class="display">Gracias por confiar en MailMask.</span><span>Tu correo, con tu dominio.</span></div>
  </div>
</main>
<div class="actions"><button id="print">Imprimir o guardar PDF</button><div class="hint">Tamaño carta, vertical.</div></div>
<script src="/js/recibo.js"></script>
</body>
</html>`;
}
