import type { DnsPreset } from "@easybits.cloud/mailmask";

/** Compartido entre `domains` (create --preset) y `dns` (preset): un solo lugar para la lista. */
export const PRESETS: DnsPreset[] = [
  "vercel", "netlify", "github-pages", "cloudflare-pages", "render", "fly", "redirect-a-www", "dmarc",
];

export const jsonArg = { json: { type: "boolean" as const, description: "Salida en JSON para scripts/agentes" } };
export const domainArg = { domain: { type: "positional" as const, description: "Dominio (acme.com) o su id" } };
