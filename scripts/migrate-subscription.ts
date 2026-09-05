/**
 * Migra la suscripción de un usuario a la app correcta de MercadoPago sin cobrarle
 * dos veces.
 *
 * Existe por el incidente de sep-2026: las suscripciones nacían bajo una app de MP
 * cuyo webhook apuntaba a otro proyecto (denik.me) y sin los tópicos de pagos, así
 * que ningún cobro recurrente nos llegó jamás. La app nueva (7311798029787174) ya
 * está bien configurada, pero un preapproval viejo sigue notificando a la app que lo
 * creó. La única salida limpia es crear uno nuevo y cancelar el viejo.
 *
 * Para no cobrar doble, el preapproval nuevo nace con `auto_recurring.start_date`
 * en la fecha que el cliente ya tiene pagada. MP lo convierte en "período de prueba" y
 * **cobra $10 MXN de validación de tarjeta** al autorizar (pago `regular_payment`,
 * external_reference `migrate:<email>` o `addon:<id>`): hay que reembolsarlo a mano
 * con `POST /v1/payments/{id}/refunds`. El webhook (rama `migrate:` en main.ts)
 * cambia el id vinculado y cancela el viejo.
 *
 *   npx tsx scripts/migrate-subscription.ts --email x@y.com --plan-start 2026-09-28
 *   npx tsx scripts/migrate-subscription.ts --email x@y.com --plan-start 2026-09-28 \
 *       --sends-start 2026-09-18 --payer-email pagador@gmail.com --apply
 *
 * `--sends-start` crea además un add-on de envíos (sends25) con su propio primer
 * cobro, para quien lo perdió porque el cron lo canceló en MP. Sin `--apply` sólo
 * reporta. Corre en la máquina de Fly para usar el MP_ACCESS_TOKEN de producción.
 */
import { getUser, createAddon, updateAddon, listEffectiveAddons, PLANS, ADDONS, planLabel, addonLabel } from "../db.js";
import { sendTemplate, subscriptionMigration } from "../emails.js";

function flag(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  if (i !== -1 && process.argv[i + 1] && !process.argv[i + 1].startsWith("--")) return process.argv[i + 1];
  return process.argv.find((a) => a.startsWith(`--${name}=`))?.split("=").slice(1).join("=");
}
const has = (name: string) => process.argv.includes(`--${name}`);

function die(msg: string): never {
  console.error(`✗ ${msg}`);
  process.exit(1);
}

function parseDay(value: string | undefined, name: string): Date | null {
  if (!value) return null;
  const d = new Date(`${value}T12:00:00.000Z`);
  if (Number.isNaN(d.getTime())) die(`--${name} no es una fecha válida: ${value}`);
  if (d.getTime() < Date.now()) die(`--${name} ya pasó: ${value}. El primer cobro tiene que ser futuro, si no MP cobra al autorizar.`);
  return d;
}

const email = flag("email")?.toLowerCase().trim();
const planStart = parseDay(flag("plan-start"), "plan-start");
const sendsStart = parseDay(flag("sends-start"), "sends-start");
const APPLY = has("apply");
const NO_EMAIL = has("no-email");
const TOKEN = process.env.MP_ACCESS_TOKEN;
const MAIN = `https://${(process.env.MAIN_DOMAIN ?? "www.mailmask.studio").replace(/^https?:\/\//, "").replace(/\/+$/, "")}`;

if (!email) die("Falta --email");
if (!planStart) die("Falta --plan-start (YYYY-MM-DD): la fecha del próximo cobro que ya tiene pagado");
if (!TOKEN) die("Falta MP_ACCESS_TOKEN");

const user = getUser(email);
if (!user) die(`No existe ${email}`);
const sub = user.subscription;
if (!sub?.mpSubscriptionId) die(`${email} no tiene suscripción vinculada a MercadoPago; no hay nada que migrar`);
if (sub.status !== "active") die(`La suscripción de ${email} está "${sub.status}", no active`);
const plan = PLANS[sub.plan as keyof typeof PLANS];
if (!plan) die(`Plan desconocido: ${sub.plan}`);

const oldRes = await fetch(`https://api.mercadopago.com/preapproval/${sub.mpSubscriptionId}`, {
  headers: { Authorization: `Bearer ${TOKEN}` },
  signal: AbortSignal.timeout(15_000),
});
if (!oldRes.ok) die(`MP no devolvió el preapproval viejo ${sub.mpSubscriptionId}: ${oldRes.status} ${await oldRes.text()}`);
const old = await oldRes.json() as {
  status: string; payer_email?: string; application_id?: number;
  auto_recurring?: { frequency?: number; frequency_type?: string; transaction_amount?: number };
  next_payment_date?: string;
};
if (old.status !== "authorized") die(`El preapproval viejo está "${old.status}" en MP, no authorized. Revisa antes de migrar.`);
if (old.auto_recurring?.frequency !== 1 || old.auto_recurring?.frequency_type !== "months") {
  die(`Sólo se migran suscripciones mensuales; ésta es ${old.auto_recurring?.frequency} ${old.auto_recurring?.frequency_type}`);
}
// Con el token de la app nueva, MP no expone payer_email de un preapproval creado por
// otra app. Se acepta por bandera; sale en /v1/payments/search del cobro anterior.
const payerEmail = old.payer_email || flag("payer-email")?.toLowerCase().trim();
if (!payerEmail) die("El preapproval viejo no trae payer_email (token de otra app). Pásalo con --payer-email; búscalo en /v1/payments/search?external_reference=<email> → payer.email");

const amount = old.auto_recurring?.transaction_amount ?? plan.price / 100;
if (sendsStart && sub.plan !== "basico") die("Sólo el plan Básico compra envíos; los demás ya los incluyen");
if (sendsStart) {
  // Lo que importa es MP, no la base: la fila local puede seguir activa (cubre lo que
  // ya se pagó) aunque el cron haya cancelado el preapproval.
  for (const a of listEffectiveAddons(email)) {
    if (!a.kind.startsWith("sends") || !a.mpPreapprovalId) continue;
    const r = await fetch(`https://api.mercadopago.com/preapproval/${a.mpPreapprovalId}`, {
      headers: { Authorization: `Bearer ${TOKEN}` }, signal: AbortSignal.timeout(15_000),
    });
    const st = r.ok ? ((await r.json() as { status?: string }).status ?? "?") : `HTTP ${r.status}`;
    console.log(`Add-on ${a.kind} existente: fila ${a.id} (${a.status} hasta ${a.currentPeriodEnd}), preapproval ${a.mpPreapprovalId} → ${st} en MP`);
    if (st === "authorized") die(`Ese preapproval sigue authorized en MP; cancélalo primero si de verdad hay que recrearlo`);
  }
}

console.log(`Usuario:         ${email}`);
console.log(`Plan:            ${planLabel(sub.plan)} · $${amount} MXN/mes · cubierto hasta ${sub.currentPeriodEnd}`);
console.log(`Preapproval viejo: ${sub.mpSubscriptionId} (app ${old.application_id}, próximo cobro MP ${old.next_payment_date})`);
console.log(`Pagador en MP:   ${payerEmail}`);
console.log(`Plan nuevo:      primer cobro ${planStart.toISOString()}`);
if (sendsStart) console.log(`Add-on sends25:  primer cobro ${sendsStart.toISOString()} · $${ADDONS.sends25.price / 100} MXN/mes`);
if (!APPLY) {
  console.log("\nSin --apply no se crea nada.");
  process.exit(0);
}

const { MercadoPagoConfig, PreApproval } = await import("mercadopago");
const preApproval = new PreApproval(new MercadoPagoConfig({ accessToken: TOKEN }));
const common = {
  payer_email: payerEmail,
  back_url: `${MAIN}/app?billing=success`,
  notification_url: `${MAIN}/api/webhooks/mercadopago`,
};

// El plan: mismo cuerpo que el checkout autenticado de main.ts, sin free_trial y con
// start_date. El external_reference `migrate:` es lo que hace que el webhook no lo
// trate como compra.
const planRes = await preApproval.create({
  body: {
    reason: `MailMask — Plan ${sub.plan.charAt(0).toUpperCase() + sub.plan.slice(1)} (Mensual)`,
    auto_recurring: {
      frequency: 1,
      frequency_type: "months",
      transaction_amount: amount,
      currency_id: "MXN",
      start_date: planStart.toISOString(),
    },
    external_reference: `migrate:${email}`,
    ...common,
    // deno-lint-ignore no-explicit-any
  } as any,
});
console.log(`\n✓ Plan nuevo creado: ${planRes.id} (${planRes.status})`);
console.log(`  Link: ${planRes.init_point}`);

let sendsLink: string | undefined;
if (sendsStart) {
  const addon = createAddon(email, "sends25");
  const addonRes = await preApproval.create({
    body: {
      reason: `MailMask — Add-on ${ADDONS.sends25.label}`,
      auto_recurring: {
        frequency: 1,
        frequency_type: "months",
        transaction_amount: ADDONS.sends25.price / 100,
        currency_id: "MXN",
        start_date: sendsStart.toISOString(),
      },
      external_reference: `addon:${addon.id}`,
      ...common,
      back_url: `${MAIN}/app?addon=success`,
      // deno-lint-ignore no-explicit-any
    } as any,
  });
  updateAddon(addon.id, { mpPreapprovalId: addonRes.id });
  sendsLink = addonRes.init_point;
  console.log(`✓ Add-on creado: fila ${addon.id}, preapproval ${addonRes.id} (${addonRes.status})`);
  console.log(`  Link: ${sendsLink}`);
}

if (NO_EMAIL) {
  console.log("\n--no-email: no se mandó el correo. Los links de arriba son los que hay que hacerle llegar.");
  process.exit(0);
}

await sendTemplate(email, subscriptionMigration({
  planLabel: planLabel(sub.plan),
  planStart: planStart.toISOString(),
  planLink: planRes.init_point!,
  ...(sendsStart ? { sendsLabel: addonLabel("sends25"), sendsStart: sendsStart.toISOString(), sendsLink } : {}),
}));
console.log(`\n✓ Correo de migración enviado a ${email}`);
