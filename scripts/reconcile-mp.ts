/**
 * Reconcilia MercadoPago contra la base.
 *
 * Existe porque una clienta pagó el 2026-07-29 y el webhook nunca la registró: su
 * suscripción quedó `authorized` en MP y `sub_mp_id` en NULL. Nadie se enteró hasta que
 * ella lo dijo, semanas después. Esto lo detecta al día siguiente.
 *
 *   npx tsx scripts/reconcile-mp.ts          # solo reporta
 *   npx tsx scripts/reconcile-mp.ts --fix    # vincula los huérfanos que encuentre
 */
import { db } from "../pg.js";
import { users } from "../schema.js";
import { eq } from "drizzle-orm";

const FIX = process.argv.includes("--fix");
const TOKEN = process.env.MP_ACCESS_TOKEN;

if (!TOKEN) {
  console.error("Falta MP_ACCESS_TOKEN");
  process.exit(1);
}

interface Preapproval {
  id: string;
  status: string;
  reason?: string;
  external_reference?: string;
  auto_recurring?: { transaction_amount?: number };
  date_created?: string;
  last_charged_date?: string | null;
}

async function mpGet(path: string): Promise<Record<string, unknown>> {
  const res = await fetch(`https://api.mercadopago.com${path}`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`MP ${path} → ${res.status}: ${await res.text()}`);
  return await res.json();
}

const rows = db.select().from(users).all();
console.log(`Revisando ${rows.length} usuarios…\n`);

const huerfanos: { email: string; preapproval: Preapproval }[] = [];
const cortesias: string[] = [];
const rotos: { email: string; mpId: string; motivo: string }[] = [];

for (const u of rows) {
  let encontrados: Preapproval[] = [];
  try {
    const r = await mpGet(`/preapproval/search?payer_email=${encodeURIComponent(u.email)}`);
    encontrados = ((r.results as Preapproval[]) ?? []).filter((p) => p.status === "authorized");
  } catch (err) {
    console.error(`  ${u.email}: error consultando MP — ${String(err)}`);
    continue;
  }

  // Add-ons aparte: su external_reference empieza con "addon:".
  const dePlan = encontrados.filter((p) => !(p.external_reference ?? "").startsWith("addon:"));

  if (!u.subMpId && dePlan.length > 0) {
    huerfanos.push({ email: u.email, preapproval: dePlan[0] });
  } else if (!u.subMpId && u.subStatus === "active") {
    cortesias.push(u.email);
  } else if (u.subMpId && !encontrados.some((p) => p.id === u.subMpId)) {
    rotos.push({ email: u.email, mpId: u.subMpId, motivo: "no está authorized en MP" });
  }
}

if (huerfanos.length) {
  console.log("PAGOS SIN VINCULAR — alguien pagó y no lo registramos:");
  for (const h of huerfanos) {
    console.log(`  ${h.email}`);
    console.log(`    preapproval ${h.preapproval.id} · $${h.preapproval.auto_recurring?.transaction_amount} · creada ${h.preapproval.date_created}`);
    console.log(`    último cobro: ${h.preapproval.last_charged_date ?? "ninguno todavía"}`);
    if (FIX) {
      db.update(users).set({ subMpId: h.preapproval.id }).where(eq(users.email, h.email)).run();
      console.log(`    → vinculada`);
    }
  }
  console.log();
}

if (rotos.length) {
  console.log("VINCULACIONES ROTAS — la base apunta a algo que MP ya no tiene activo:");
  for (const r of rotos) console.log(`  ${r.email} → ${r.mpId} (${r.motivo})`);
  console.log();
}

if (cortesias.length) {
  console.log("CORTESÍAS — plan activo sin suscripción en MP (no pagan):");
  for (const c of cortesias) console.log(`  ${c}`);
  console.log();
}

if (!huerfanos.length && !rotos.length) {
  console.log("Sin desfases entre MercadoPago y la base.");
}

if (huerfanos.length && !FIX) {
  console.log("Corre con --fix para vincular los huérfanos.");
  process.exit(1);
}
process.exit(0);
