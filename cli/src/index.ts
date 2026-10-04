import { defineCommand, runMain } from "citty";
import login from "./commands/login.js";
import logout from "./commands/logout.js";
import whoami from "./commands/whoami.js";
import domains from "./commands/domains.js";
import dns from "./commands/dns.js";

const main = defineCommand({
  meta: {
    name: "mailmask",
    version: "0.1.0",
    description: "CLI oficial de MailMask — dominios, alias, DNS, reglas, envío y más desde la terminal.",
  },
  subCommands: { login, logout, whoami, domains, dns },
});

runMain(main);
