/**
 * Manda el correo de recuperación de carrito a quien dejó un checkout de plan a medias.
 *
 * Nació para Oswaldo (26-ago-2026, Básico $49, preapproval `pending` en la app vieja de
 * MP): con el modelo gratis del 7-sep el motivo para no terminar desapareció. El dato
 * del intento sale de MP (`/preapproval/search?payer_email=`), no de la base: la app
 * nunca registró ese checkout como orden.
 *
 *   npx tsx scripts/recuperar-carrito.ts --email x@y.com                 # sólo reporta
 *   npx tsx scripts/recuperar-carrito.ts --email x@y.com --nombre Oswaldo --apply
 *
 * Corre en la máquina de Fly (necesita MP_ACCESS_TOKEN y SES de producción). Se niega
 * si la cuenta no existe, si ya tiene dominios, o si MP no tiene un preapproval pending.
 */
import { getUser, listUserDomains, planLabel } from "../db.js";
import { sendTemplate, carritoAbandonado } from "../emails.js";

function flag(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  if (i !== -1 && process.argv[i + 1] && !process.argv[i + 1].startsWith("--")) return process.argv[i + 1];
  const inline = process.argv.find((a) => a.startsWith(`--${name}=`));
  return inline?.split("=").slice(1).join("=");
}

const email = flag("email")?.toLowerCase();
const nombre = flag("nombre") ?? null;
const apply = process.argv.includes("--apply");
if (!email) { console.error("Falta --email"); process.exit(1); }

const user = getUser(email);
if (!user) { console.error(`No existe la cuenta ${email}`); process.exit(1); }
const dominios = listUserDomains(email);
if (dominios.length) { console.error(`${email} ya tiene ${dominios.length} dominio(s); no es un carrito abandonado.`); process.exit(1); }

const token = process.env.MP_ACCESS_TOKEN;
if (!token) { console.error("Falta MP_ACCESS_TOKEN"); process.exit(1); }
const res = await fetch(`https://api.mercadopago.com/preapproval/search?payer_email=${encodeURIComponent(email)}`, {
  headers: { Authorization: `Bearer ${token}` },
});
const data = await res.json() as { results?: Array<{ id: string; status: string; reason: string; date_created: string; auto_recurring: { transaction_amount: number } }> };
const pending = (data.results ?? []).filter((r) => r.status === "pending").sort((a, b) => b.date_created.localeCompare(a.date_created))[0];
if (!pending) { console.error(`MP no tiene un preapproval pending para ${email}`); process.exit(1); }

const planKey = /basic|básic/i.test(pending.reason) ? "basico" : /equipo/i.test(pending.reason) ? "equipo" : null;
const label = planKey ? planLabel(planKey) : pending.reason.replace(/^MailMask\s*[—-]\s*/, "");
const correo = carritoAbandonado({
  nombre,
  fechaIntento: new Date(pending.date_created).toISOString(),
  planLabel: label,
  amountCents: Math.round(pending.auto_recurring.transaction_amount * 100),
});

console.log(`Cuenta: ${email} (verificado: ${user.emailVerified ? "sí" : "no"}, creada ${user.createdAt})`);
console.log(`Intento: ${pending.date_created} · ${pending.reason} · $${pending.auto_recurring.transaction_amount} · preapproval ${pending.id}`);
console.log(`Asunto: ${correo.subject}`);
console.log("---\n" + correo.text);

if (!apply) { console.log("\n(dry-run: agrega --apply para mandarlo)"); process.exit(0); }
const id = await sendTemplate(email, correo);
console.log(`Enviado. Message-ID: ${id}`);
