/**
 * Activa un dominio por cortesía (add-on `domain` a $0) y, opcionalmente, retira la
 * suscripción legado de su dueño para que la cuenta se vea como el modelo nuevo.
 *
 *   npx tsx scripts/cortesia-dominio.ts --email x@y.com --domain ejemplo.com [--hasta 2027-12-31] [--sin-legado] [--apply]
 *
 * Dry-run por defecto. No toca MercadoPago: si el dueño tiene un preapproval vivo,
 * cancélalo aparte antes de --sin-legado, o le seguirán cobrando.
 */
import { listUserDomains, listEffectiveAddonsForDomain, createCourtesyAddon, getUser, derechosDeDominio } from "../db.js";
import { sqlite } from "../pg.js";

const arg = (k: string) => { const i = process.argv.indexOf(k); return i > -1 ? process.argv[i + 1] : undefined; };
const email = arg("--email"); const domainName = arg("--domain");
const hasta = arg("--hasta") ?? "2027-12-31";
const sinLegado = process.argv.includes("--sin-legado");
const apply = process.argv.includes("--apply");
if (!email || !domainName) { console.error("uso: --email --domain [--hasta] [--sin-legado] [--apply]"); process.exit(1); }

const user = getUser(email);
if (!user) { console.error(`no existe el usuario ${email}`); process.exit(1); }
const dom = listUserDomains(email).find((d) => d.domain === domainName);
if (!dom) { console.error(`${email} no tiene el dominio ${domainName}`); process.exit(1); }
if (user.subscription?.mpSubscriptionId && sinLegado) {
  console.error(`⚠️ ${email} tiene preapproval vivo en MP (${user.subscription.mpSubscriptionId}). Cancélalo antes de --sin-legado.`);
  process.exit(1);
}

const ya = listEffectiveAddonsForDomain(dom.id).some((a) => a.kind === "domain");
console.log(`${domainName}: ${ya ? "ya tiene add-on domain" : `se crea cortesía domain hasta ${hasta}`}${sinLegado ? " · se retira la suscripción legado" : ""}`);
if (!apply) { console.log("(dry-run: nada escrito; corre con --apply)"); process.exit(0); }

if (!ya) createCourtesyAddon({ userEmail: email, kind: "domain", domainId: dom.id, currentPeriodEnd: `${hasta}T00:00:00.000Z`, note: "Cortesía de dominio", grantedBy: "script" });
if (sinLegado) sqlite.prepare("UPDATE users SET sub_plan = NULL, sub_status = NULL, sub_mp_id = NULL, sub_period_end = NULL WHERE email = ?").run(email);
const r = derechosDeDominio(dom, getUser(email));
console.log(`✅ ${domainName}: activado=${r.activado} legado=${r.legado} gratis=${r.esGratis} bloqueado=${r.bloqueado}`);
