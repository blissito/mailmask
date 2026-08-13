/**
 * Plantillas de correo transaccional.
 *
 * Existe porque no había ninguna: los ocho correos del sistema eran template strings
 * sueltos, cada uno repetía `process.env.ALERT_FROM_EMAIL ?? "noreply@..."`, y cron.ts
 * hasta usaba un dominio por defecto distinto que main.ts. El único que mandaba HTML
 * era el de "primer correo recibido", con un `<p>` pelón.
 *
 * Reglas del HTML de correo, todas aprendidas a golpes y ninguna negociable:
 *
 *  - **Fondo claro, no oscuro.** Gmail-Android y Outlook.com aplican inversión forzada
 *    de color. Un correo diseñado en oscuro se invierte a gris sobre gris con el verde
 *    hecho lodo, y no hay forma confiable de optarse fuera. Uno claro con `color` y
 *    `background-color` explícitos en cada elemento sobrevive legible a los tres
 *    algoritmos (Apple no invierte, Gmail invierte parcial, Outlook invierte todo).
 *  - **Sin imágenes, ni el logo.** `sendFromDomain` no arma multipart/mixed, así que no
 *    hay adjuntos ni CID; Outlook bloquea las remotas por defecto y Gmail no renderiza
 *    SVG. La marca es un wordmark de texto sobre una banda esmeralda: cero bytes, cero
 *    bloqueo, se ve en todos lados.
 *  - Tablas con `role="presentation"`, estilos inline, sin flex ni grid, 600px máximo.
 *  - `line-height` en el `<td>` *y* en el `<p>`: Outlook ignora uno de los dos.
 *  - Botones como tabla de una celda con `bgcolor`; un `<a>` con padding pierde el
 *    padding en el motor Word de Outlook.
 *  - Cada plantilla arma también su versión de texto, con la URL escrita completa.
 *    `sendFromDomain` pone el texto primero en el multipart/alternative, así que esa
 *    parte tiene que sostenerse sola — nada de "haz clic aquí".
 */
// Del catálogo puro, no de `db.ts`: así las plantillas se pueden renderizar y probar
// sin abrir SQLite ni correr migraciones. `ses.ts` se importa perezosamente dentro de
// `sendTemplate` por lo mismo — arrastra `pg.ts` y el SDK de AWS, y renderizar un
// correo no tiene por qué hacer eso.
import { PLANS, ADDONS, planLabel, addonLabel } from "./plans.js";

export const ALERT_FROM = process.env.ALERT_FROM_EMAIL ?? "noreply@mailmask.studio";
export const FROM_HEADER = `MailMask <${ALERT_FROM}>`;
export const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL ?? "hola@mailmask.studio";

// La mascarita, servida desde el sitio. Va como imagen remota porque no hay otra vía:
// `sendFromDomain` no arma multipart/mixed, así que no se puede adjuntar por CID, y el
// SVG del sitio no lo renderiza Gmail. Outlook bloquea las remotas por defecto — por eso
// el wordmark de texto se queda al lado en vez de reemplazarse por la imagen: si la
// bloquean, la marca sigue ahí y la mascarita degrada a su texto alternativo.
export const LOGO_URL = "https://www.mailmask.studio/img/logo.png";

export function baseUrl(): string {
  const raw = process.env.MAIN_DOMAIN ?? "www.mailmask.studio";
  const bare = raw.replace(/^https?:\/\//, "").replace(/\/+$/, "");
  return `https://${bare}`;
}

// No existía escapado del lado del servidor. Los nombres de dominio y de alias son
// entrada del usuario y se interpolan en estas plantillas.
export function escHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// El asunto va a `encodeHeader` en ses.ts, pero un \r\n aquí rompería el header antes
// de llegar allá.
function cleanSubject(value: string): string {
  return value.replace(/[\r\n]+/g, " ").trim();
}

export function money(cents: number, currency = "MXN"): string {
  return `$${(cents / 100).toLocaleString("es-MX", { minimumFractionDigits: 2, maximumFractionDigits: 2 })} ${currency}`;
}

// En UTC a propósito. Los periodos se guardan como instantes UTC, así que formatear en
// la zona de la máquina hacía que un `...T00:00:00Z` se viera como el día anterior —
// un recibo que dice "hasta el 1 de septiembre" cuando la base dice 2 es una llamada a
// soporte. Además vuelve el render determinista entre local, CI y producción.
export function shortDate(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleDateString("es-MX", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });
}

export interface Email {
  subject: string;
  text: string;
  html: string;
}

const C = {
  band: "#047857",
  bandText: "#ffffff",
  accent: "#a7f3d0",
  text: "#18181b",
  muted: "#52525b",
  line: "#e4e4e7",
  pageBg: "#f4f4f5",
  cardBg: "#ffffff",
  softBg: "#fafafa",
  okBg: "#ecfdf5",
  okLine: "#a7f3d0",
  warnBg: "#fffbeb",
  warnLine: "#fde68a",
  dangerBg: "#fef2f2",
  dangerLine: "#fecaca",
};

const FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";

export function p(text: string): string {
  return `<p style="margin:0 0 14px;font-family:${FONT};font-size:16px;line-height:24px;color:${C.text};">${escHtml(text)}</p>`;
}

/** Un `<p>` que ya trae HTML confiable dentro (generado aquí, nunca del usuario). */
export function pRaw(html: string): string {
  return `<p style="margin:0 0 14px;font-family:${FONT};font-size:16px;line-height:24px;color:${C.text};">${html}</p>`;
}

export function detailTable(rows: [string, string][]): string {
  const body = rows.map(([k, v], i) => `
      <tr>
        <td style="padding:10px 14px;${i ? `border-top:1px solid ${C.line};` : ""}font-family:${FONT};font-size:14px;line-height:20px;color:${C.muted};background-color:${C.softBg};">${escHtml(k)}</td>
        <td align="right" style="padding:10px 14px;${i ? `border-top:1px solid ${C.line};` : ""}font-family:${FONT};font-size:14px;line-height:20px;color:${C.text};font-weight:600;background-color:${C.softBg};">${escHtml(v)}</td>
      </tr>`).join("");
  return `<table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="width:100%;border:1px solid ${C.line};border-radius:8px;margin:0 0 18px;">${body}</table>`;
}

export function calloutBox(text: string, tone: "info" | "warn" | "danger" = "info"): string {
  const bg = tone === "danger" ? C.dangerBg : tone === "warn" ? C.warnBg : C.okBg;
  const line = tone === "danger" ? C.dangerLine : tone === "warn" ? C.warnLine : C.okLine;
  return `<table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="width:100%;margin:0 0 18px;">
      <tr><td style="padding:14px 16px;background-color:${bg};border:1px solid ${line};border-radius:8px;font-family:${FONT};font-size:15px;line-height:22px;color:${C.text};">${escHtml(text)}</td></tr>
    </table>`;
}

function ctaButton(label: string, url: string): string {
  return `<table role="presentation" border="0" cellpadding="0" cellspacing="0" style="margin:4px 0 8px;">
      <tr><td bgcolor="${C.band}" style="border-radius:8px;">
        <a href="${escHtml(url)}" target="_blank" rel="noopener noreferrer" style="display:block;padding:13px 28px;font-family:${FONT};font-size:16px;font-weight:600;color:#ffffff;text-decoration:none;">${escHtml(label)}</a>
      </td></tr>
    </table>`;
}

interface LayoutOpts {
  preheader: string;
  heading: string;
  body: string;
  cta?: { label: string; url: string };
  footerNote?: string;
  /** Los correos que no son de cobro no necesitan el bloque de facturación. */
  billing?: boolean;
}

export function layout(o: LayoutOpts): string {
  const url = baseUrl();
  const invoiceLine = o.billing
    ? `<p style="margin:0 0 10px;font-family:${FONT};font-size:13px;line-height:20px;color:${C.muted};">¿Necesitas factura (CFDI)? Escríbenos a <a href="mailto:${SUPPORT_EMAIL}" style="color:${C.band};">${SUPPORT_EMAIL}</a> con tu RFC, razón social, uso de CFDI y el folio de este correo. Te la enviamos por correo.</p>`
    : "";
  return `<!doctype html>
<html lang="es"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<meta name="supported-color-schemes" content="light">
<title>${escHtml(o.heading)}</title>
</head>
<body style="margin:0;padding:0;background-color:${C.pageBg};">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">${escHtml(o.preheader)}</div>
<table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="width:100%;background-color:${C.pageBg};">
<tr><td align="center" style="padding:24px 12px;">
  <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="600" style="width:100%;max-width:600px;background-color:${C.cardBg};border:1px solid ${C.line};border-radius:12px;">
    <tr><td style="background-color:${C.band};border-radius:12px 12px 0 0;padding:18px 28px;">
      <table role="presentation" border="0" cellpadding="0" cellspacing="0"><tr>
        <td style="padding-right:10px;line-height:0;">
          <img src="${LOGO_URL}" width="36" height="36" alt="MailMask" style="display:block;width:36px;height:36px;border:0;outline:none;text-decoration:none;">
        </td>
        <td style="font-family:${FONT};font-size:20px;font-weight:700;color:${C.bandText};line-height:24px;">Mail<span style="color:${C.accent};">Mask</span></td>
      </tr></table>
    </td></tr>
    <tr><td style="padding:28px;font-family:${FONT};font-size:16px;line-height:24px;color:${C.text};">
      <h1 style="margin:0 0 18px;font-family:${FONT};font-size:22px;line-height:28px;font-weight:700;color:${C.text};">${escHtml(o.heading)}</h1>
      ${o.body}
      ${o.cta ? ctaButton(o.cta.label, o.cta.url) : ""}
    </td></tr>
    <tr><td style="padding:0 28px;"><hr style="border:0;border-top:1px solid ${C.line};margin:0;"></td></tr>
    <tr><td style="padding:20px 28px 28px;font-family:${FONT};font-size:13px;line-height:20px;color:${C.muted};">
      ${o.footerNote ? `<p style="margin:0 0 10px;font-family:${FONT};font-size:13px;line-height:20px;color:${C.muted};">${escHtml(o.footerNote)}</p>` : ""}
      ${invoiceLine}
      <p style="margin:0 0 10px;font-family:${FONT};font-size:13px;line-height:20px;color:${C.muted};">¿Dudas? Responde este correo o escribe a <a href="mailto:${SUPPORT_EMAIL}" style="color:${C.band};">${SUPPORT_EMAIL}</a>.</p>
      <p style="margin:0;font-family:${FONT};font-size:13px;line-height:20px;color:${C.muted};"><a href="${escHtml(url)}/app" target="_blank" rel="noopener noreferrer" style="color:${C.muted};">Administrar mi cuenta</a> &middot; MailMask &middot; mailmask.studio</p>
    </td></tr>
  </table>
</td></tr></table>
</body></html>`;
}

/** Pie de la versión de texto, en paralelo al del HTML. */
function textFooter(billing: boolean): string {
  const lines = [""];
  if (billing) {
    lines.push(`¿Necesitas factura (CFDI)? Escríbenos a ${SUPPORT_EMAIL} con tu RFC, razón social, uso de CFDI y el folio de este correo.`);
  }
  lines.push(`¿Dudas? Responde este correo o escribe a ${SUPPORT_EMAIL}.`);
  lines.push(`Administra tu cuenta en ${baseUrl()}/app`);
  lines.push("");
  lines.push("— MailMask");
  return lines.join("\n");
}

function textBlock(parts: (string | null | undefined)[], billing = false): string {
  return parts.filter(Boolean).join("\n\n") + "\n" + textFooter(billing);
}

function textRows(rows: [string, string][]): string {
  return rows.map(([k, v]) => `${k}: ${v}`).join("\n");
}

// --- Datos que comparten los recibos ---

export interface OrderLike {
  number: string;
  amountCents: number;
  currency: string;
  periodStart?: string;
  periodEnd?: string;
  mpPaymentId?: string;
  occurredAt: string;
}

function receiptRows(concept: string, order: OrderLike, nextChargeAt?: string | null): [string, string][] {
  const rows: [string, string][] = [
    ["Concepto", concept],
    ["Monto", money(order.amountCents, order.currency)],
    ["Folio", order.number],
    ["Fecha", shortDate(order.occurredAt)],
  ];
  if (order.periodStart && order.periodEnd) {
    rows.push(["Periodo cubierto", `${shortDate(order.periodStart)} – ${shortDate(order.periodEnd)}`]);
  } else if (order.periodEnd) {
    rows.push(["Cubierto hasta", shortDate(order.periodEnd)]);
  }
  if (nextChargeAt) rows.push(["Próximo cargo", shortDate(nextChargeAt)]);
  rows.push(["Método de pago", order.mpPaymentId ? `MercadoPago · pago #${order.mpPaymentId}` : "MercadoPago"]);
  return rows;
}

// --- Plantillas de facturación ---

export function paymentConfirmation(d: {
  plan: string;
  order: OrderLike;
  nextChargeAt?: string | null;
  referralBonusDays?: number;
}): Email {
  const label = planLabel(d.plan);
  const concept = `Plan ${label} (mensual)`;
  const rows = receiptRows(concept, d.order, d.nextChargeAt);
  // El mes extra por referido hoy es invisible: el cliente ve un fin de periodo que no
  // cuadra con lo que pagó y asume que es un bug.
  const bonus = d.referralBonusDays
    ? `Incluimos ${d.referralBonusDays} días extra por tu referido, así que tu próximo cargo es hasta el ${shortDate(d.nextChargeAt)}.`
    : null;

  return {
    subject: cleanSubject(`Pago confirmado — Plan ${label} — MailMask`),
    html: layout({
      preheader: `Recibo de tu pago de ${money(d.order.amountCents, d.order.currency)} · folio ${d.order.number}`,
      heading: `Tu plan ${label} está activo`,
      body: p("Recibimos tu pago. Aquí está el detalle para tus registros.")
        + detailTable(rows)
        + (bonus ? calloutBox(bonus, "info") : ""),
      cta: { label: "Ir a mi panel", url: `${baseUrl()}/app` },
      footerNote: "Este correo es tu comprobante de pago. No es un CFDI.",
      billing: true,
    }),
    text: textBlock([
      `Tu plan ${label} está activo.`,
      "Recibimos tu pago. Aquí está el detalle para tus registros:",
      textRows(rows),
      bonus,
      `Ir a tu panel: ${baseUrl()}/app`,
      "Este correo es tu comprobante de pago. No es un CFDI.",
    ], true),
  };
}

export function addonPurchase(d: {
  addonLabel: string;
  order: OrderLike;
  nextChargeAt?: string | null;
}): Email {
  const rows = receiptRows(d.addonLabel, d.order, d.nextChargeAt);
  return {
    subject: cleanSubject(`Add-on activado: ${d.addonLabel} — MailMask`),
    html: layout({
      preheader: `${d.addonLabel} activo · ${money(d.order.amountCents, d.order.currency)} · folio ${d.order.number}`,
      heading: `${d.addonLabel} ya está activo`,
      body: p("Recibimos tu pago y el add-on ya aplica en tu cuenta. Aquí está el detalle para tus registros.")
        + detailTable(rows),
      cta: { label: "Ver mi cuenta", url: `${baseUrl()}/app` },
      footerNote: "Este correo es tu comprobante de pago. No es un CFDI.",
      billing: true,
    }),
    text: textBlock([
      `${d.addonLabel} ya está activo en tu cuenta.`,
      textRows(rows),
      `Ver tu cuenta: ${baseUrl()}/app`,
      "Este correo es tu comprobante de pago. No es un CFDI.",
    ], true),
  };
}

export function renewalReceipt(d: {
  concept: string;
  order: OrderLike;
  nextChargeAt?: string | null;
}): Email {
  const rows = receiptRows(d.concept, d.order, d.nextChargeAt);
  return {
    subject: cleanSubject(`Renovación — ${d.concept} — ${money(d.order.amountCents, d.order.currency)}`),
    html: layout({
      preheader: `Cobramos ${money(d.order.amountCents, d.order.currency)} · folio ${d.order.number}`,
      heading: "Renovamos tu suscripción",
      body: p("Este es un cargo recurrente. No tienes que hacer nada.")
        + detailTable(rows),
      cta: { label: "Ver mi cuenta", url: `${baseUrl()}/app` },
      footerNote: "Este correo es tu comprobante de pago. No es un CFDI.",
      billing: true,
    }),
    text: textBlock([
      "Renovamos tu suscripción. Este es un cargo recurrente, no tienes que hacer nada.",
      textRows(rows),
      `Ver tu cuenta: ${baseUrl()}/app`,
      "Este correo es tu comprobante de pago. No es un CFDI.",
    ], true),
  };
}

export function chargeFailed(d: {
  concept: string;
  attemptedCents: number;
  currency?: string;
  accessUntil?: string | null;
  reason?: string | null;
}): Email {
  const amount = money(d.attemptedCents, d.currency ?? "MXN");
  // Tres preguntas, en este orden: qué pasó, qué sigue y cuándo, qué hacer ahora.
  // "Perderías el acceso" no le dice nada a quien no tiene el modelo mental del
  // producto: hay que decir que las máscaras dejan de reenviar correo.
  const consecuencia = d.accessUntil
    ? `Conservas el servicio hasta el ${shortDate(d.accessUntil)}. Después de esa fecha tus máscaras dejan de reenviar correo y los mensajes que te manden no llegarán a tu bandeja.`
    : "Mientras tanto tus máscaras siguen funcionando, pero si el cobro no se completa dejarán de reenviar correo.";
  const rows: [string, string][] = [
    ["Concepto", d.concept],
    ["Monto intentado", amount],
    ...(d.reason ? [["Motivo", d.reason] as [string, string]] : []),
    ...(d.accessUntil ? [["Servicio activo hasta", shortDate(d.accessUntil)] as [string, string]] : []),
  ];

  return {
    subject: cleanSubject("No pudimos procesar tu pago — MailMask"),
    html: layout({
      preheader: `El cargo de ${amount} fue rechazado. Tienes tiempo para resolverlo.`,
      heading: "No pudimos procesar tu pago",
      body: p(`MercadoPago rechazó el cargo de ${amount} por ${d.concept}.`)
        + detailTable(rows)
        + calloutBox(consecuencia, "danger")
        + p("MercadoPago reintenta el cobro automáticamente durante los próximos días. Para que funcione, revisa que tu tarjeta tenga fondos y no esté vencida. Si cambiaste de tarjeta, actualízala desde tu panel."),
      cta: { label: "Actualizar mi pago", url: `${baseUrl()}/app` },
      billing: true,
    }),
    text: textBlock([
      `MercadoPago rechazó el cargo de ${amount} por ${d.concept}.`,
      textRows(rows),
      consecuencia,
      "MercadoPago reintenta el cobro automáticamente durante los próximos días. Revisa que tu tarjeta tenga fondos y no esté vencida.",
      `Actualiza tu pago: ${baseUrl()}/app`,
    ], true),
  };
}

export function guestWelcome(d: {
  plan: string;
  setPasswordUrl: string;
  order?: OrderLike | null;
}): Email {
  const label = planLabel(d.plan);
  // Lleva la tabla de pago porque es el único recibo que esta persona va a recibir.
  const rows = d.order ? receiptRows(`Plan ${label} (mensual)`, d.order) : null;
  return {
    subject: cleanSubject("¡Bienvenido a MailMask! Configura tu contraseña"),
    html: layout({
      preheader: `Tu plan ${label} está activo. Solo falta tu contraseña.`,
      heading: "¡Bienvenido a MailMask!",
      body: p(`Tu suscripción al plan ${label} está activa. Configura tu contraseña para entrar a tu cuenta.`)
        + (rows ? detailTable(rows) : ""),
      cta: { label: "Configurar mi contraseña", url: d.setPasswordUrl },
      footerNote: "Este enlace vence en 7 días.",
      billing: !!rows,
    }),
    text: textBlock([
      `¡Bienvenido a MailMask! Tu suscripción al plan ${label} está activa.`,
      `Configura tu contraseña aquí:\n${d.setPasswordUrl}`,
      "Este enlace vence en 7 días.",
      rows ? textRows(rows) : null,
    ], !!rows),
  };
}

export function expiryWarning(d: { endDate: string; hasMpSubscription: boolean }): Email {
  const fecha = shortDate(d.endDate);
  if (d.hasMpSubscription) {
    // Tono informativo: a esta persona el cobro automático le va a funcionar. El asunto
    // viejo ("está por vencer") asustaba a quien tenía todo en orden y generaba soporte.
    return {
      subject: cleanSubject(`Tu plan de MailMask se renueva el ${fecha}`),
      html: layout({
        preheader: `Renovación automática el ${fecha}. No tienes que hacer nada.`,
        heading: `Tu plan se renueva el ${fecha}`,
        body: p(`Tu suscripción se renueva automáticamente el ${fecha} con el método de pago que tienes en MercadoPago.`)
          + p("Si tu pago está al día no tienes que hacer nada. Si quieres revisar o cambiar tu método de pago, entra a tu panel."),
        cta: { label: "Ver mi cuenta", url: `${baseUrl()}/app` },
        billing: true,
      }),
      text: textBlock([
        `Tu suscripción de MailMask se renueva automáticamente el ${fecha}.`,
        "Si tu pago está al día no tienes que hacer nada.",
        `Ver tu cuenta: ${baseUrl()}/app`,
      ], true),
    };
  }
  return {
    subject: cleanSubject(`Tu plan de MailMask vence el ${fecha}`),
    html: layout({
      preheader: `Sin suscripción activa, el ${fecha} pierdes el servicio.`,
      heading: `Tu plan vence el ${fecha}`,
      body: p(`Tu plan vence el ${fecha} y no tiene una suscripción activa que lo renueve.`)
        + calloutBox(`Ese día tus máscaras dejan de reenviar correo y los mensajes que te manden no llegarán a tu bandeja.`, "warn")
        + p("Activa tu suscripción para no quedarte sin servicio."),
      cta: { label: "Activar mi suscripción", url: `${baseUrl()}/app` },
      billing: true,
    }),
    text: textBlock([
      `Tu plan de MailMask vence el ${fecha} y no tiene una suscripción activa que lo renueve.`,
      "Ese día tus máscaras dejan de reenviar correo.",
      `Activa tu suscripción aquí: ${baseUrl()}/app`,
    ], true),
  };
}

export function addonShutdown(d: { addonLabels: string[]; planEndedAt?: string | null }): Email {
  const lista = d.addonLabels.join(", ");
  return {
    subject: cleanSubject("Cancelamos tus add-ons — MailMask"),
    html: layout({
      preheader: `Tu plan base venció, así que cancelamos ${lista}.`,
      heading: "Cancelamos tus add-ons",
      body: p(`Tu plan base venció${d.planEndedAt ? ` el ${shortDate(d.planEndedAt)}` : ""}, así que cancelamos también tus add-ons para que MercadoPago deje de cobrarlos.`)
        + detailTable(d.addonLabels.map((l) => [l, "Cancelado"] as [string, string]))
        + calloutBox("Reactivar tu plan no restaura los add-ons automáticamente: tendrías que volver a comprarlos.", "warn"),
      cta: { label: "Reactivar mi plan", url: `${baseUrl()}/app` },
      billing: true,
    }),
    text: textBlock([
      `Tu plan base venció${d.planEndedAt ? ` el ${shortDate(d.planEndedAt)}` : ""}, así que cancelamos también tus add-ons para que MercadoPago deje de cobrarlos.`,
      `Add-ons cancelados: ${lista}`,
      "Reactivar tu plan no los restaura automáticamente: tendrías que volver a comprarlos.",
      `Reactivar: ${baseUrl()}/app`,
    ], true),
  };
}

export function courtesyGranted(d: {
  addonLabel: string;
  until?: string | null;
  listPriceCents?: number | null;
  note?: string | null;
}): Email {
  const vigencia = d.until ? `hasta el ${shortDate(d.until)}` : "mientras tu plan esté activo";
  const rows: [string, string][] = [
    ["Add-on", d.addonLabel],
    ["Costo", "$0.00 MXN"],
    ["Vigencia", d.until ? shortDate(d.until) : "mientras tu plan esté activo"],
  ];
  if (d.listPriceCents) rows.push(["Valor normal", `${money(d.listPriceCents)}/mes`]);

  return {
    subject: cleanSubject(`Te regalamos ${d.addonLabel} en MailMask`),
    html: layout({
      preheader: `${d.addonLabel} sin costo, ${vigencia}.`,
      heading: "Un regalo de nuestra parte",
      body: p(`Activamos ${d.addonLabel} en tu cuenta, sin costo.`)
        + detailTable(rows)
        + calloutBox("No se te va a cobrar nada por esto. No aparece en tu recibo y no se renueva solo.", "info")
        + (d.note ? p(`Nota: ${d.note}`) : "")
        + p(d.until
          ? "Te avisamos antes de que termine. Si para entonces lo quieres conservar, puedes comprarlo desde tu panel."
          : "Si algún día deja de aplicar, te avisamos antes."),
      cta: { label: "Ver mi cuenta", url: `${baseUrl()}/app` },
    }),
    text: textBlock([
      `Activamos ${d.addonLabel} en tu cuenta, sin costo.`,
      textRows(rows),
      "No se te va a cobrar nada por esto.",
      d.note ? `Nota: ${d.note}` : null,
      `Ver tu cuenta: ${baseUrl()}/app`,
    ]),
  };
}

// --- Plantillas que no son de facturación ---

export function verifyEmail(d: { verifyUrl: string }): Email {
  return {
    subject: cleanSubject("Verifica tu email — MailMask"),
    html: layout({
      preheader: "Confirma tu correo para activar tu cuenta.",
      heading: "Verifica tu email",
      body: p("Confirma tu correo para activar tu cuenta de MailMask."),
      cta: { label: "Verificar mi email", url: d.verifyUrl },
      footerNote: "Tienes 7 días para verificar tu cuenta. Si no creaste esta cuenta, ignora este correo.",
    }),
    text: textBlock([
      "Verifica tu email para activar tu cuenta de MailMask:",
      d.verifyUrl,
      "Tienes 7 días para verificar tu cuenta. Si no creaste esta cuenta, ignora este correo.",
    ]),
  };
}

export function passwordReset(d: { resetUrl: string }): Email {
  return {
    subject: cleanSubject("Restablecer contraseña — MailMask"),
    html: layout({
      preheader: "Enlace para elegir una contraseña nueva.",
      heading: "Restablecer tu contraseña",
      body: p("Recibimos una solicitud para cambiar la contraseña de tu cuenta."),
      cta: { label: "Elegir contraseña nueva", url: d.resetUrl },
      footerNote: "El enlace vence en 7 días. Si no pediste esto, ignora este correo: tu contraseña no cambia.",
    }),
    text: textBlock([
      "Recibimos una solicitud para cambiar la contraseña de tu cuenta de MailMask.",
      `Elige una contraseña nueva aquí:\n${d.resetUrl}`,
      "El enlace vence en 7 días. Si no pediste esto, ignora este correo: tu contraseña no cambia.",
    ]),
  };
}

export function mesaInvite(d: {
  inviterEmail: string;
  domain: string;
  role: string;
  name?: string | null;
  acceptUrl: string;
}): Email {
  const saludo = d.name ? `Hola ${d.name},` : "Hola,";
  return {
    subject: cleanSubject(`Invitación a Mesa — ${d.domain}`),
    html: layout({
      preheader: `${d.inviterEmail} te invita como ${d.role} en ${d.domain}.`,
      heading: `Te invitaron a ${d.domain}`,
      body: p(saludo)
        + p(`${d.inviterEmail} te invita a colaborar como ${d.role} en la Mesa del dominio ${d.domain}.`),
      cta: { label: "Aceptar invitación", url: d.acceptUrl },
      footerNote: "La invitación vence en 7 días.",
    }),
    text: textBlock([
      saludo,
      `${d.inviterEmail} te invita a colaborar como ${d.role} en la Mesa del dominio ${d.domain}.`,
      `Acepta la invitación aquí:\n${d.acceptUrl}`,
      "La invitación vence en 7 días.",
    ]),
  };
}

export function firstEmailReceived(d: { alias: string; domain: string; from: string; subject: string }): Email {
  const direccion = `${d.alias}@${d.domain}`;
  return {
    subject: cleanSubject(`Primer email recibido en ${direccion}`),
    html: layout({
      preheader: `Tu máscara ${direccion} ya está recibiendo correo.`,
      heading: "Tu máscara ya funciona",
      body: p(`Acaba de llegar el primer correo a ${direccion} y lo reenviamos a tu bandeja.`)
        + detailTable([["De", d.from], ["Asunto", d.subject]]),
      cta: { label: "Ver en mi panel", url: `${baseUrl()}/app` },
      footerNote: "Solo te avisamos del primero. Los siguientes llegan directo, sin este aviso.",
    }),
    text: textBlock([
      `Acaba de llegar el primer correo a ${direccion} y lo reenviamos a tu bandeja.`,
      textRows([["De", d.from], ["Asunto", d.subject]]),
      "Solo te avisamos del primero. Los siguientes llegan directo, sin este aviso.",
    ]),
  };
}

// --- Envío ---

/**
 * Manda una plantilla. Además de la marca, arregla tres cosas que faltaban en *todos*
 * los correos del sistema: nombre de remitente (llegaban de un `noreply@` pelón),
 * `Reply-To` a soporte (no había forma de contestar) y `configSet`, sin el cual un
 * recibo que rebota es un fallo de cobranza invisible.
 */
export async function sendTemplate(to: string, email: Email, opts?: { from?: string }): Promise<string> {
  const { sendFromDomain } = await import("./ses.js");
  return sendFromDomain(opts?.from ?? FROM_HEADER, to, email.subject, email.text, {
    html: email.html,
    replyTo: SUPPORT_EMAIL,
    ...(process.env.SES_CONFIG_SET ? { configSet: process.env.SES_CONFIG_SET } : {}),
  });
}

/** Catálogo para el script de preview y para las pruebas. */
export const TEMPLATE_FIXTURES: Record<string, () => Email> = {
  paymentConfirmation: () => paymentConfirmation({
    plan: "basico",
    order: {
      number: "MM-2608-7F3A", amountCents: 4900, currency: "MXN",
      periodStart: "2026-08-13T00:00:00.000Z", periodEnd: "2026-09-12T00:00:00.000Z",
      mpPaymentId: "123456789", occurredAt: "2026-08-13T00:00:00.000Z",
    },
    nextChargeAt: "2026-09-12T00:00:00.000Z",
    referralBonusDays: 30,
  }),
  addonPurchase: () => addonPurchase({
    addonLabel: ADDONS.sends100.label,
    order: {
      number: "MM-2608-3D5E", amountCents: 9900, currency: "MXN",
      periodEnd: "2026-09-17T00:00:00.000Z", mpPaymentId: "555000111",
      occurredAt: "2026-08-13T00:00:00.000Z",
    },
    nextChargeAt: "2026-09-13T00:00:00.000Z",
  }),
  renewalReceipt: () => renewalReceipt({
    concept: "Plan Básico (mensual)",
    order: {
      number: "MM-2609-B21C", amountCents: 4900, currency: "MXN",
      periodStart: "2026-09-12T00:00:00.000Z", periodEnd: "2026-10-12T00:00:00.000Z",
      mpPaymentId: "987654321", occurredAt: "2026-09-12T00:00:00.000Z",
    },
    nextChargeAt: "2026-10-12T00:00:00.000Z",
  }),
  chargeFailed: () => chargeFailed({
    concept: "Plan Básico (mensual)", attemptedCents: 4900,
    accessUntil: "2026-09-02T00:00:00.000Z", reason: "Fondos insuficientes",
  }),
  guestWelcome: () => guestWelcome({
    plan: "freelancer", setPasswordUrl: "https://www.mailmask.studio/set-password?token=abc",
    order: {
      number: "MM-2608-9911", amountCents: 44900, currency: "MXN",
      periodEnd: "2026-09-12T00:00:00.000Z", occurredAt: "2026-08-13T00:00:00.000Z",
    },
  }),
  expiryWarningAuto: () => expiryWarning({ endDate: "2026-09-02T00:00:00.000Z", hasMpSubscription: true }),
  expiryWarningManual: () => expiryWarning({ endDate: "2026-09-02T00:00:00.000Z", hasMpSubscription: false }),
  addonShutdown: () => addonShutdown({ addonLabels: ["Envíos 25/día", "Dominio extra"], planEndedAt: "2026-09-02T00:00:00.000Z" }),
  courtesyGranted: () => courtesyGranted({
    addonLabel: ADDONS.domain.label, until: "2027-12-31T00:00:00.000Z",
    listPriceCents: ADDONS.domain.price, note: "Compensación por la falla de cobro del 29 de julio",
  }),
  verifyEmail: () => verifyEmail({ verifyUrl: "https://www.mailmask.studio/api/auth/verify-email?token=abc" }),
  passwordReset: () => passwordReset({ resetUrl: "https://www.mailmask.studio/set-password?token=abc" }),
  mesaInvite: () => mesaInvite({
    inviterEmail: "hugo@ejemplo.com", domain: "ejemplo.com", role: "agente",
    name: "Brenda", acceptUrl: "https://www.mailmask.studio/api/agents/accept?token=abc",
  }),
  firstEmailReceived: () => firstEmailReceived({
    alias: "hola", domain: "ejemplo.com", from: "cliente@gmail.com", subject: "Cotización",
  }),
};

export { PLANS, ADDONS, planLabel, addonLabel };
