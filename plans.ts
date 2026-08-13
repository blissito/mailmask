/**
 * Catálogo comercial: planes, add-ons y sus nombres para mostrar.
 *
 * Vive aparte de `db.ts` a propósito. Todo esto son constantes puras, pero `db.ts`
 * importa `pg.ts`, que abre SQLite y corre las migraciones al cargarse — así que
 * cualquiera que solo quisiera el precio del plan Básico terminaba arrastrando la base
 * entera. Eso rompía el script de preview de correos y volvía imposible probar las
 * plantillas sin una base migrada.
 *
 * `db.ts` lo re-exporta, así que nada de lo que ya importaba de ahí tuvo que cambiar.
 */

// `sends` y `forwardPerHour` se cuentan **por dominio**, no por cuenta: getSendCount()
// y el rate limit de forwarding se llavean con domainId. Un Freelancer con 15 dominios
// tiene 15 x 100 envíos al día disponibles.
//
// `sends` es solo correo saliente que el usuario origina (panel, API, SMTP relay).
// El reenvío entrante — el caso de uso principal — va por `forwardPerHour` y es un orden
// de magnitud mayor, así que el límite de envíos no lo toca quien solo reenvía.
export const PLANS = {
  basico:     { label: "Básico",     price: 49_00,  yearlyPrice: 490_00,  domains: 1,  aliases: 5,   rules: 0,   logDays: 15, sends: 0,     api: true,  webhooks: false, forwardPerHour: 100,  smtpRelay: false },
  freelancer: { label: "Freelancer", price: 449_00, yearlyPrice: 4490_00, domains: 15, aliases: 50,  rules: 10,  logDays: 30, sends: 200,   api: true,  webhooks: false, forwardPerHour: 500,  smtpRelay: false },
  developer:  { label: "Developer",  price: 999_00, yearlyPrice: 9990_00, domains: 20, aliases: 100, rules: 50,  logDays: 90, sends: 1000,  api: true,  webhooks: true,  forwardPerHour: 2000, smtpRelay: true },
  pro:     { label: "Pro",     price: 299_00, yearlyPrice: 2990_00, domains: 15, aliases: 50,  rules: 10,  logDays: 30, sends: 500,   api: false, webhooks: false, forwardPerHour: 500,  smtpRelay: true },
  agencia: { label: "Agencia", price: 999_00, yearlyPrice: 9990_00, domains: 20, aliases: 100, rules: 50,  logDays: 90, sends: 2000,  api: true,  webhooks: true,  forwardPerHour: 2000, smtpRelay: true },
} as const;

// --- Add-ons ---

// Se compran encima del plan base. El de envíos se compra una vez y desbloquea el envío
// en todos los dominios del usuario; el tope sigue aplicando por dominio y por día,
// que es como ya se llavea sendCounts. El de dominio es cupo acumulable y no incluye envíos.
export const ADDONS = {
  sends25:  { price: 49_00, sends: 25,  label: "Envíos 25/día" },
  sends100: { price: 99_00, sends: 100, label: "Envíos 100/día" },
  domain:   { price: 99_00, domains: 1, label: "Dominio extra" },
} as const;

export type AddonKind = keyof typeof ADDONS;
export type PlanKey = keyof typeof PLANS;

// Nombre para mostrar. Existe porque `plan.charAt(0).toUpperCase() + plan.slice(1)`
// sobre el enum daba "Basico" sin acento, en los correos y en el dashboard. Cubre los
// cinco planes: un cliente con un plan legado (`pro`, `agencia`) veía `undefined`.
export function planLabel(plan?: string | null): string {
  return (PLANS as Record<string, { label?: string }>)[plan ?? ""]?.label ?? "Sin plan";
}

export function planPriceCents(plan?: string | null): number {
  return (PLANS as Record<string, { price?: number }>)[plan ?? ""]?.price ?? 0;
}

// Etiqueta de cualquier cosa cobrable. `kind` no se valida contra ADDONS: un add-on
// que se invente mañana tiene que poder etiquetarse hoy, aunque sea con su propia llave.
export function addonLabel(kind: string): string {
  return (ADDONS as Record<string, { label?: string }>)[kind]?.label ?? kind;
}

export function addonPriceCents(kind: string): number | null {
  return (ADDONS as Record<string, { price?: number }>)[kind]?.price ?? null;
}
