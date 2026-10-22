// Plantillas fijas de Mascarito IA para contestar su correo. El modelo sólo elige el id y,
// como mucho, un nombre de pila validado (ver mascarito-mail.ts): nunca redacta, nunca cita
// el correo entrante y toda URL sale de aquí. Ver docs/agents/mascarito-correo-seguridad.md.

export const TEMPLATE_IDS = ["what_is", "add_domain", "pricing", "create_address", "mailbox", "handoff"] as const;
export type TemplateId = (typeof TEMPLATE_IDS)[number];

const SITE = "https://www.mailmask.studio";

type Block = { text: string; link?: { label: string; url: string } };

const BODIES: Record<TemplateId, Block[]> = {
  what_is: [
    { text: "MailMask te da correo con tu propio dominio (por ejemplo hola@tunegocio.com): recibes y respondes desde la Bandeja, y si quieres, también te llega a tu correo de siempre." },
    { text: "Empezar es gratis.", link: { label: "Crea tu cuenta", url: `${SITE}/register` } },
  ],
  add_domain: [
    { text: "Para conectar tu dominio: crea tu cuenta, entra al panel y elige «Agregar dominio». Te mostramos los registros DNS que van en tu proveedor, o puedes cambiar tus nameservers a MailMask para que quede configurado solo." },
    { text: "Paso a paso en la documentación.", link: { label: "Ver la guía", url: `${SITE}/docs` } },
  ],
  pricing: [
    { text: "La cuenta es gratis: hasta 5 direcciones en tu dominio, y recibes y respondes desde la Bandeja." },
    { text: "Al activar un dominio ($99 MXN al mes) tienes direcciones ilimitadas, envío de correo nuevo y buzones para Apple Mail u Outlook.", link: { label: "Ver precios", url: `${SITE}/pricing` } },
  ],
  create_address: [
    { text: "Para crear una dirección: en tu panel, abre tu dominio y elige «Nueva dirección». Puede llegar sólo a la Bandeja o reenviarse a tu correo de siempre." },
    { text: "Tu panel está aquí.", link: { label: "Abrir el panel", url: `${SITE}/app` } },
  ],
  mailbox: [
    { text: "Un buzón es una cuenta de correo completa en tu dominio que abres en Apple Mail, Outlook o el teléfono. Se crea desde el panel en un dominio activado." },
    { text: "Precios y detalles aquí.", link: { label: "Ver precios", url: `${SITE}/pricing` } },
  ],
  handoff: [
    { text: "Tu mensaje lo va a leer una persona del equipo de MailMask, y te contesta en este mismo hilo." },
  ],
};

const INTRO = "Te contesto yo, Mascarito IA (un agente de inteligencia artificial), no una persona. 🤖";
const HUMAN = "¿Prefieres hablar con una persona? Responde a este correo con la palabra HUMANO.";
const SIGNATURE = "— Mascarito IA · agente de inteligencia artificial de MailMask";

const esc = (t: string) => t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

export function renderTemplate(id: TemplateId, firstName?: string): { text: string; html: string } {
  const hello = firstName ? `Hola, ${firstName}:` : "Hola:";
  const blocks = BODIES[id];
  const tail = id === "handoff" ? [SIGNATURE] : [HUMAN, SIGNATURE];
  const text = [
    hello, "", INTRO, "",
    ...blocks.flatMap((b) => [b.link ? `${b.text} ${b.link.label}: ${b.link.url}` : b.text, ""]),
    ...tail.flatMap((t) => [t, ""]),
  ].join("\n").trim();
  const p = (inner: string) => `<p style="margin:0 0 14px">${inner}</p>`;
  const html = `<div style="font-family:system-ui,-apple-system,sans-serif;font-size:15px;line-height:1.5">` +
    `<img src="${SITE}/mascot.png" width="72" height="72" alt="Mascarito IA" style="display:block;margin:0 0 12px">` +
    p(esc(hello)) +
    p(`Te contesto yo, Mascarito IA (un agente de inteligencia artificial), <strong>no una persona</strong>. 🤖`) +
    blocks.map((b) => p(esc(b.text) + (b.link ? ` <a href="${b.link.url}">${esc(b.link.label)}</a>` : ""))).join("") +
    tail.map((t) => p(esc(t))).join("") +
    `</div>`;
  return { text, html };
}
