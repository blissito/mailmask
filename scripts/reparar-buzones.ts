/**
 * Vuelve a crear en Stalwart los buzones que esta base dice que existen y allá ya no.
 *
 * Existe por el 2026-09-12: el reboot del fierro se llevó el disco de la caja de
 * correo y se restauró un estado del 6-sep. Todo buzón dado de alta después seguía
 * en esta base —alias con `mailboxAccountId`— pero en Stalwart no había ni dominio
 * ni cuenta, y Mail pedía la contraseña en bucle.
 *
 *   npx tsx scripts/reparar-buzones.ts            → sólo reporta
 *   npx tsx scripts/reparar-buzones.ts --apply    → crea lo que falte
 *
 * Cada buzón recreado sale con contraseña NUEVA (no guardamos la vieja, por diseño):
 * se imprime una vez y hay que dársela al dueño. El correo que llegó entre el
 * respaldo y la reparación no vuelve por aquí.
 */
import { listarBuzonesActivos, marcarBuzon } from "../db.js";
import { accountIdDe, crearBuzon, olvidarCuenta } from "../stalwart.js";

const apply = process.argv.includes("--apply");
const buzones = listarBuzonesActivos();
let faltan = 0;
for (const b of buzones) {
  const email = `${b.alias}@${b.domain}`.toLowerCase();
  olvidarCuenta(email);
  const id = await accountIdDe(email);
  if (id) { console.log(`ok       ${email} (${id})`); continue; }
  faltan++;
  if (!apply) { console.log(`FALTA    ${email} (base: ${b.accountId})`); continue; }
  const r = await crearBuzon({ localPart: b.alias, domain: b.domain, quotaBytes: b.quotaBytes ?? 1024 * 1024 * 1024 });
  if (!r.ok) { console.log(`ERROR    ${email}: ${r.error}`); continue; }
  marcarBuzon(b.domainId, b.alias, { accountId: r.valor.accountId, quotaBytes: b.quotaBytes ?? 1024 * 1024 * 1024 });
  console.log(`CREADO   ${email} → ${r.valor.accountId}  password: ${r.valor.password}`);
}
console.log(`${buzones.length} buzones, ${faltan} faltaban${apply ? "" : " (sin --apply no se creó nada)"}`);
process.exit(0);
