/**
 * Otorga un add-on de cortesía: un regalo del equipo, sin cobro.
 *
 * Existe porque hasta ahora las cortesías se daban editando SQLite a mano. Eso dejaba
 * la fila indistinguible de una compra —el dashboard le decía a la clienta que pagaba
 * $99 al mes por algo regalado, con botón de cancelar incluido— y sin rastro de quién
 * la otorgó ni por qué.
 *
 *   npx tsx scripts/grant-addon.ts --email x@y.com --kind domain --months 12
 *   npx tsx scripts/grant-addon.ts --email x@y.com --kind domain --until 2027-12-31 \
 *       --note "Compensación por la falla de cobro del 29 de julio" --by hugo --apply
 *
 * Sin `--apply` solo reporta lo que haría. Se pide `--months` o `--until` a propósito:
 * un regalo sin fecha de fin debe ser una decisión consciente, no un valor por defecto.
 *
 * `--kind` acepta cualquier cadena. Si no está en el catálogo, hay que pasar `--label`
 * y `--price-cents`, y así un add-on que se invente el año que entra se puede regalar
 * hoy sin tocar código.
 */
import { getUser, listEffectiveAddons, createCourtesyAddon, ADDONS, addonLabel } from "../db.js";
import { sendTemplate, courtesyGranted } from "../emails.js";

function flag(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  if (i !== -1 && process.argv[i + 1] && !process.argv[i + 1].startsWith("--")) return process.argv[i + 1];
  return process.argv.find((a) => a.startsWith(`--${name}=`))?.split("=").slice(1).join("=");
}
const has = (name: string) => process.argv.includes(`--${name}`) || process.argv.some((a) => a.startsWith(`--${name}=`));

const email = flag("email")?.toLowerCase().trim();
const kind = flag("kind");
const months = flag("months");
const until = flag("until");
const note = flag("note");
const by = flag("by") ?? process.env.USER ?? "equipo";
const label = flag("label");
const priceCents = flag("price-cents");
const APPLY = has("apply");
const FORCE = has("force");
const NO_EMAIL = has("no-email");

function die(msg: string): never {
  console.error(`✗ ${msg}`);
  process.exit(1);
}

if (!email) die("Falta --email");
if (!kind) die("Falta --kind (por ejemplo: domain, sends25, sends100, o uno nuevo)");
if (!months && !until) die("Falta --months o --until. Un regalo sin fecha de fin tiene que ser deliberado.");
if (months && until) die("--months y --until son excluyentes");

const enCatalogo = kind in ADDONS;
if (!enCatalogo && (!label || !priceCents)) {
  die(`"${kind}" no está en el catálogo, así que necesita --label y --price-cents para poder mostrarlo y valuarlo.`);
}

let periodEnd: Date;
if (until) {
  periodEnd = new Date(`${until}T00:00:00.000Z`);
  if (Number.isNaN(periodEnd.getTime())) die(`--until no es una fecha válida: ${until}`);
} else {
  const n = Number(months);
  if (!Number.isFinite(n) || n <= 0) die(`--months debe ser un número positivo: ${months}`);
  periodEnd = new Date();
  periodEnd.setMonth(periodEnd.getMonth() + n);
}
if (periodEnd <= new Date()) die(`La vigencia queda en el pasado: ${periodEnd.toISOString()}`);

const user = getUser(email);
if (!user) die(`No existe el usuario ${email}`);

// Un regalo sobre una cuenta sin plan casi siempre es un correo mal escrito.
const sub = user.subscription;
const planVivo = sub && (sub.status === "active" || sub.status === "cancelled")
  && (!sub.currentPeriodEnd || new Date(sub.currentPeriodEnd) >= new Date());
if (!planVivo && !FORCE) {
  die(`${email} no tiene un plan activo. Si es a propósito, repite con --force.`);
}

const yaTiene = listEffectiveAddons(email).filter((a) => a.kind === kind);
if (yaTiene.length && !FORCE) {
  die(`${email} ya tiene ${yaTiene.length} add-on(s) "${kind}" vigente(s). Si quieres otro, repite con --force.`);
}
if (kind.startsWith("sends")) {
  const otrosEnvios = listEffectiveAddons(email).filter((a) => a.kind.startsWith("sends") && a.kind !== kind);
  if (otrosEnvios.length) {
    console.warn(`⚠ Ya tiene otro add-on de envíos (${otrosEnvios.map((a) => a.kind).join(", ")}). Los de envíos no se acumulan: gana el mayor.`);
  }
}

const etiqueta = label ?? addonLabel(kind);
const valor = priceCents ? Number(priceCents) : (ADDONS as Record<string, { price?: number }>)[kind]?.price ?? null;

console.log("");
console.log(`  Usuario     ${email}`);
console.log(`  Plan        ${sub?.plan ?? "ninguno"} (${sub?.status ?? "sin suscripción"})`);
console.log(`  Add-on      ${etiqueta}  [${kind}]${enCatalogo ? "" : "  ← fuera del catálogo"}`);
console.log(`  Costo       $0.00 MXN${valor ? `  (valor normal $${(valor / 100).toLocaleString("es-MX")}/mes)` : ""}`);
console.log(`  Vigencia    hasta ${periodEnd.toISOString().slice(0, 10)}`);
console.log(`  Motivo      ${note ?? "(sin nota)"}`);
console.log(`  Otorga      ${by}`);
console.log(`  Correo      ${NO_EMAIL ? "no se manda" : "se le avisa al cliente"}`);
console.log("");

if (!APPLY) {
  console.log("Esto es un simulacro. Repite con --apply para escribirlo.");
  process.exit(0);
}

const { addon, order } = createCourtesyAddon({
  userEmail: email,
  kind,
  currentPeriodEnd: periodEnd.toISOString(),
  label: etiqueta,
  listPriceCents: valor ?? undefined,
  note,
  grantedBy: by,
});

console.log(`✓ Add-on ${addon.id} otorgado`);
console.log(`✓ Orden ${order?.number ?? "(ya existía)"} en el libro mayor`);

if (!NO_EMAIL) {
  try {
    await sendTemplate(email, courtesyGranted({
      addonLabel: etiqueta,
      until: periodEnd.toISOString(),
      listPriceCents: valor,
      note,
    }));
    console.log("✓ Aviso enviado");
  } catch (err) {
    // El regalo ya está otorgado; que falle el correo no lo deshace.
    console.error(`⚠ No se pudo mandar el aviso: ${String(err)}`);
    console.error("  El add-on quedó otorgado de todos modos.");
  }
}
