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

const main = defineCommand({
  meta: {
    name: "mailmask",
    version: "0.1.0",
    description: "CLI oficial de MailMask — dominios, alias, DNS, reglas, equipo, cobros, dominios registrados y más desde la terminal.",
  },
  subCommands: { login, logout, whoami, domains, dns, aliases, webhooks, smtp, "api-keys": apiKeys, rules, suppressions, account, members, billing, registrations, transfers, referrals },
});

runMain(main);
