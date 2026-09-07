/**
 * Migración al modelo de $99 por dominio (7-sep-2026).
 *
 * Los add-ons de antes eran por CUENTA; los nuevos son por DOMINIO. Este script asigna
 * las cortesías `domain` viejas (sin `domain_id`) a los dominios más antiguos del dueño
 * que no tengan add-on, y comprueba que NINGÚN dominio que hoy reenvía quede `bloqueado`.
 * Si alguno quedara, aborta antes de escribir: la regla es que nadie que pague hoy pague
 * más y nadie pierda una cortesía.
 *
 * Los `sends25`/`mailbox` viejos se dejan como legado del usuario (sin dominio): siguen
 * sumando en todos sus dominios. MercadoPago no se toca.
 *
 *   npx tsx scripts/migrar-modelo-99.ts            # dry-run
 *   npx tsx scripts/migrar-modelo-99.ts --apply
 */
import { listAllUsers, listUserDomains, listEffectiveAddons, updateAddon, derechosDeDominio, getUser } from "../db.js";

const apply = process.argv.includes("--apply");
const cambios: { email: string; addonId: string; domain: string }[] = [];
const bloqueados: string[] = [];

for (const u of listAllUsers()) {
  const dominios = [...listUserDomains(u.email)].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  const cortesiasSinDominio = listEffectiveAddons(u.email).filter((a) => a.kind === "domain" && !a.domainId);
  // Candidatos: los más antiguos primero, saltando el 1.º (ya es gratis) y los que ya
  // tienen add-on propio.
  const sinAddon = dominios.slice(1).filter((d) => !listEffectiveAddons(u.email).some((a) => a.domainId === d.id && a.kind === "domain"));
  cortesiasSinDominio.forEach((a, i) => {
    const d = sinAddon[i];
    if (d) cambios.push({ email: u.email, addonId: a.id, domain: d.domain });
  });
}

console.log(`${cambios.length} cortesía(s) por asignar:`);
for (const c of cambios) console.log(`  ${c.email}: add-on ${c.addonId} → ${c.domain}`);

if (apply) {
  for (const c of cambios) {
    const d = listUserDomains(c.email).find((x) => x.domain === c.domain)!;
    updateAddon(c.addonId, { domainId: d.id });
  }
}

// Verificación (con los cambios aplicados, o simulándolos en memoria en dry-run).
console.log("\nDerechos por dominio después de la migración:");
for (const u of listAllUsers()) {
  const owner = getUser(u.email);
  for (const d of listUserDomains(u.email)) {
    let r = derechosDeDominio(d, owner);
    if (!apply && cambios.some((c) => c.domain === d.domain)) r = { ...r, activado: true, bloqueado: false, esGratis: false };
    const estado = r.activado ? (r.legado ? "activado (legado)" : "activado") : r.esGratis ? "gratis" : "BLOQUEADO";
    console.log(`  ${u.email.padEnd(36)} ${d.domain.padEnd(28)} ${estado}`);
    if (r.bloqueado && d.verified) bloqueados.push(`${u.email} → ${d.domain}`);
  }
}

if (bloqueados.length) {
  console.error(`\n🔴 ${bloqueados.length} dominio(s) verificados quedarían bloqueados:\n  ${bloqueados.join("\n  ")}`);
  console.error("Resuélvelo (cortesía o activación) antes de desplegar. No se escribió nada.");
  process.exit(1);
}
console.log(apply ? "\n✅ Aplicado." : "\n(dry-run: nada escrito; corre con --apply)");
