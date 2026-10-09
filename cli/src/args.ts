import type { InboxStatus, DnsPreset, RuleAction, RuleField, RuleMatch, WebhookEvent } from "@easybits.cloud/mailmask";

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

/** `inbox update --status` (InboxStatus del SDK), `inbox list --status` (suma unread y deleted) y `--priority`: se validan antes de tocar la red. */
export const INBOX_STATUSES: InboxStatus[] = ["open", "snoozed", "closed"];
export const INBOX_LIST_STATUSES: string[] = [...INBOX_STATUSES, "unread", "deleted"];
export const INBOX_PRIORITIES = ["normal", "urgent"];
