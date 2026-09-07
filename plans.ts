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
// `monthlyForwards` es el tope de reenvíos **por cuenta y por mes**, el único que acota
// el costo: a SES se le paga por correo y al cliente una cuota fija. El de por hora
// (`forwardPerHour`) frena picos; sin este, 1,000/hora sostenidas eran ~13,000 MXN al mes
// de un cliente que paga 299. Al llegar al tope el correo se guarda en la Bandeja pero
// ya no se reenvía al buzón externo; al 80% se avisa al dueño por correo.
//
// Dos planes a la venta desde sep-2026 (ver "Precios" en CLAUDE.md): Básico y Equipo.
// El reenvío puro lo regala la competencia (ImprovMX, ForwardEmail); lo que se cobra es
// la Bandeja compartida por dominio en vez de por persona (Workspace $140/usuario,
// Help Scout $25 USD/asiento). `aliases: 1000` en Equipo se muestra como "ilimitadas".
//
// Freelancer, Developer, Pro y Agencia son legado: sin suscriptores al momento del cambio,
// pero cupones, correos y tests los nombran. LEGACY_PLANS los saca de páginas y checkout.
export const PLANS = {
  basico:     { label: "Básico",     price: 49_00,  yearlyPrice: 490_00,  domains: 1,  aliases: 10,   rules: 0,   logDays: 15, sends: 0,     api: true,  webhooks: false, forwardPerHour: 100,  smtpRelay: false, monthlyForwards: 3000 },
  equipo:     { label: "Equipo",     price: 299_00, yearlyPrice: 2990_00, domains: 5,  aliases: 1000, rules: 25,  logDays: 90, sends: 200,   api: true,  webhooks: true,  forwardPerHour: 1000, smtpRelay: true, monthlyForwards: 30000 },
  freelancer: { label: "Freelancer", price: 449_00, yearlyPrice: 4490_00, domains: 15, aliases: 50,  rules: 10,  logDays: 30, sends: 200,   api: true,  webhooks: false, forwardPerHour: 500,  smtpRelay: false, monthlyForwards: 30000 },
  developer:  { label: "Developer",  price: 999_00, yearlyPrice: 9990_00, domains: 20, aliases: 100, rules: 50,  logDays: 90, sends: 1000,  api: true,  webhooks: true,  forwardPerHour: 2000, smtpRelay: true, monthlyForwards: 100000 },
  pro:     { label: "Pro",     price: 299_00, yearlyPrice: 2990_00, domains: 15, aliases: 50,  rules: 10,  logDays: 30, sends: 500,   api: false, webhooks: false, forwardPerHour: 500,  smtpRelay: true, monthlyForwards: 30000 },
  agencia: { label: "Agencia", price: 999_00, yearlyPrice: 9990_00, domains: 20, aliases: 100, rules: 50,  logDays: 90, sends: 2000,  api: true,  webhooks: true,  forwardPerHour: 2000, smtpRelay: true, monthlyForwards: 100000 },
} as const;

export const LEGACY_PLANS: ReadonlySet<string> = new Set(["freelancer", "developer", "pro", "agencia"]);
export function isLegacyPlan(plan?: string | null): boolean { return LEGACY_PLANS.has(plan ?? ""); }
/** Planes que se pueden comprar hoy. */
export const PLANS_FOR_SALE = [] as const;

// --- Catálogo de venta (7-sep-2026) ---
//
// Ya no hay planes. Toda cuenta es gratis y se compran tres cosas, todas a $99/mes y
// POR DOMINIO (cada add-on lleva `domainId`):
//   domain    → "este dominio está activado": equipo ilimitado, buzones, envío, 10 GB.
//   storage50 → +50 GB al pozo de ese dominio. Acumulable.
//   sends100  → +100 correos nuevos al día en ese dominio. Acumulable.
//
// Por qué por dominio y no por persona: es el diferenciador entero ("Google cobra por
// persona, MailMask por dominio"). Por qué nada va "incluido" sin medidor: el reenvío
// ilimitado ya salió caro una vez (por eso existe `monthlyForwards`), y el disco y los
// envíos tienen la misma forma — crecen solos. Todo lo que escala con el costo se vende
// en bloques del mismo precio.
//
// `PLANS` de arriba queda SOLO para etiquetar suscripciones legado (`planLabel`) y para
// que el webhook de MercadoPago siga renovando los preapprovals viejos. No se venden.
export const ADDONS = {
  domain:    { price: 99_00, label: "Dominio activado" },
  storage50: { price: 99_00, bytes: 50 * 1024 * 1024 * 1024, label: "+50 GB de buzón" },
  sends100:  { price: 99_00, sends: 100, label: "+100 envíos al día" },
} as const;

// Add-ons de antes del 7-sep-2026. Si una cuenta los tiene, se respetan (sin `domainId`,
// aplican a todos sus dominios); no se venden. `domain` viejo (cupo de dominio extra) se
// migró a "dominio activado" asignándole un `domainId` con scripts/migrar-modelo-99.ts.
export const LEGACY_ADDONS = {
  sends25: { price: 49_00, sends: 25, label: "Envíos 25/día" },
  mailbox: { price: 99_00, bytes: 10 * 1024 * 1024 * 1024, label: "Buzón IMAP 10 GB" },
} as const;

export type AddonKind = keyof typeof ADDONS;
export type PlanKey = keyof typeof PLANS;

/** Precio en centavos de cualquier add-on, incluidos los legado. */
export function addonPriceCents(kind: string): number | null {
  return (ADDONS as Record<string, { price?: number }>)[kind]?.price
    ?? (LEGACY_ADDONS as Record<string, { price?: number }>)[kind]?.price
    ?? null;
}

// Etiqueta de cualquier cosa cobrable. `kind` no se valida: una cortesía de un add-on
// que se invente mañana tiene que poder etiquetarse hoy, aunque sea con su propia llave.
export function addonLabel(kind: string): string {
  return (ADDONS as Record<string, { label?: string }>)[kind]?.label
    ?? (LEGACY_ADDONS as Record<string, { label?: string }>)[kind]?.label
    ?? kind;
}

// Nombre para mostrar de una suscripción legado. Cubre los seis planes viejos: un
// cliente con `pro` o `agencia` veía `undefined`.
export function planLabel(plan?: string | null): string {
  return (PLANS as Record<string, { label?: string }>)[plan ?? ""]?.label ?? "Sin plan";
}

export function planPriceCents(plan?: string | null): number {
  return (PLANS as Record<string, { price?: number }>)[plan ?? ""]?.price ?? 0;
}

/** Los tres add-ons a la venta, en el orden de la página de precios. */
export const ADDONS_FOR_SALE = ["domain", "storage50", "sends100"] as const;

/** Lo que trae un dominio activado sin add-ons extra. Es la tabla de precios en código. */
export const DOMINIO_ACTIVADO = {
  aliases: 1000,           // "ilimitadas" en la página
  sends: 50,
  mailboxBytes: 10 * 1024 * 1024 * 1024,
  forwardPerHour: 1000,
  monthlyForwards: 10_000,
  logDays: 90,
} as const;

/** Lo que trae el único dominio gratis de una cuenta. */
export const DOMINIO_GRATIS = {
  aliases: 5,
  sends: 0,
  forwardPerHour: 100,
  monthlyForwards: 1_000,
  logDays: 7,
  retencionDias: 7,        // la Bandeja muestra 7 días
  purgaDias: 30,           // y borra a los 30
} as const;
