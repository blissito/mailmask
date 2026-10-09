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
import send from "./commands/send.js";
import logs from "./commands/logs.js";

const main = defineCommand({
  meta: {
    name: "mailmask",
    version: "0.1.0",
    description: "CLI oficial de MailMask — dominios, alias, DNS, reglas, envío, logs y más desde la terminal.",
  },
  subCommands: { login, logout, whoami, domains, dns, aliases, webhooks, smtp, "api-keys": apiKeys, rules, suppressions, send, logs },
});

runMain(main);
