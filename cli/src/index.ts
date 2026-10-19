import { createRequire } from "node:module";
import { defineCommand, runMain } from "citty";
import login from "./commands/login.js";
import logout from "./commands/logout.js";
import whoami from "./commands/whoami.js";
import domains from "./commands/domains.js";
import dns from "./commands/dns.js";
import aliases from "./commands/aliases.js";
import webhooks from "./commands/webhooks.js";
import smtp from "./commands/smtp.js";
import apiKeys from "./commands/api-keys.js";
import rules from "./commands/rules.js";
import suppressions from "./commands/suppressions.js";
import account from "./commands/account.js";
import members from "./commands/members.js";
import billing from "./commands/billing.js";
import registrations from "./commands/registrations.js";
import transfers from "./commands/transfers.js";
import referrals from "./commands/referrals.js";
import inbox from "./commands/inbox.js";
import canned from "./commands/canned.js";
import signature from "./commands/signature.js";
import send from "./commands/send.js";
import logs from "./commands/logs.js";

// La versión sale de cli/package.json (../ desde src/ y desde dist/ es el mismo
// archivo): así `--version` no puede desfasarse del paquete que npm publica.
const { version } = createRequire(import.meta.url)("../package.json") as { version: string };

const main = defineCommand({
  meta: {
    name: "mailmask",
    version,
    description: "CLI oficial de MailMask — dominios, direcciones, DNS, reglas, envío, logs, equipo, cobros, dominios registrados y más desde la terminal.",
  },
  subCommands: { login, logout, whoami, domains, dns, aliases, webhooks, smtp, "api-keys": apiKeys, rules, suppressions, inbox, canned, signature, account, members, billing, registrations, transfers, referrals, send, logs },
});

runMain(main);
