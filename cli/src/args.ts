import type { DnsPreset, RuleAction, RuleField, RuleMatch, WebhookEvent } from "@easybits.cloud/mailmask";

/** Compartido entre `domains` (create --preset) y `dns` (preset): un solo lugar para la lista. */
export const PRESETS: DnsPreset[] = [
  "vercel", "netlify", "github-pages", "cloudflare-pages", "render", "fly", "redirect-a-www", "dmarc",
];

export const jsonArg = { json: { type: "boolean" as const, description: "Salida en JSON para scripts/agentes" } };
export const domainArg = { domain: { type: "positional" as const, description: "Dominio (acme.com) o su id" } };
export const yesArg = { yes: { type: "boolean" as const, description: "Confirma sin preguntar (obligatorio fuera de una terminal)" } };

/** Los 5 eventos de `WebhookEvent` del SDK; `webhooks --events` se valida contra esta lista antes de tocar la red. */
export const WEBHOOK_EVENTS: WebhookEvent[] = ["email.received", "email.sent", "email.delivered", "email.bounced", "email.complained"];

/** Los valores de `RuleField`, `RuleMatch` y `RuleAction` del SDK; `rules --field/--match/--action` se validan contra ellas antes de tocar la red. */
export const RULE_FIELDS: RuleField[] = ["to", "from", "subject"];
export const RULE_MATCHES: RuleMatch[] = ["contains", "equals", "regex"];
export const RULE_ACTIONS: RuleAction[] = ["forward", "webhook", "discard"];

/** Roles de `members invite` (los de `DomainMember.role` del SDK); se validan antes de tocar la red. */
export const MEMBER_ROLES = ["admin", "agent"] as const;
/** Lo que se puede comprar con `billing checkout` y su periodo; mismos valores que el SDK. */
export const BILLING_KINDS = ["domain", "storage50", "sends100"] as const;
export const BILLING_PERIODS = ["monthly", "annual"] as const;

/** Dominio registrado (acme.com) o el id de su registro: `registrations` y `transfers` aceptan los dos. */
export const registrationArg = { registration: { type: "positional" as const, description: "Dominio registrado (acme.com) o el id de su registro" } };
