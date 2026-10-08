import type { DnsPreset, WebhookEvent } from "@easybits.cloud/mailmask";

/** Compartido entre `domains` (create --preset) y `dns` (preset): un solo lugar para la lista. */
export const PRESETS: DnsPreset[] = [
  "vercel", "netlify", "github-pages", "cloudflare-pages", "render", "fly", "redirect-a-www", "dmarc",
];

export const jsonArg = { json: { type: "boolean" as const, description: "Salida en JSON para scripts/agentes" } };
export const domainArg = { domain: { type: "positional" as const, description: "Dominio (acme.com) o su id" } };
export const yesArg = { yes: { type: "boolean" as const, description: "Confirma sin preguntar (obligatorio fuera de una terminal)" } };

/** Los 5 eventos de `WebhookEvent` del SDK; `webhooks --events` se valida contra esta lista antes de tocar la red. */
export const WEBHOOK_EVENTS: WebhookEvent[] = ["email.received", "email.sent", "email.delivered", "email.bounced", "email.complained"];
