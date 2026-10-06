import { writeFile } from "node:fs/promises";
import { defineCommand } from "citty";
import type { CreateAliasInput, UpdateAliasInput } from "@easybits.cloud/mailmask";
import { requireClient } from "../client.js";
import { confirmOrExit, failFromError, maskSecret, printJson } from "../output.js";
import { resolveDomainId } from "../resolve.js";
import { domainArg, jsonArg, yesArg } from "../args.js";

/** `<dominio> <alias>`: compartidos entre casi todos los subcomandos de este archivo. */
const aliasArgs = {
  domain: { type: "positional" as const, description: "Dominio (acme.com) o su id" },
  alias: { type: "positional" as const, description: "Parte local de la máscara, p. ej. hola (usa * para catch-all)" },
};

const AFTER_SECRET = "  Corre el mismo comando con --json para obtenerla completa ahora; no se vuelve a mostrar.\n";

const list = defineCommand({
  meta: { name: "list", description: "Lista las máscaras (alias) de un dominio" },
  args: { ...domainArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const aliases = await client.aliases.list(id);
      if (args.json) return printJson(aliases);
      if (aliases.length === 0) {
        process.stdout.write('Sin alias. Crea uno con "mailmask aliases create <dominio> <alias>".\n');
        return;
      }
      for (const a of aliases) {
        const estado = [a.enabled ? "activo" : "desactivado", a.mailboxEnabled ? "con buzón" : "sin buzón"].join(", ");
        process.stdout.write(`${a.alias}  →  ${a.destinations.join(", ") || "(sin destinos)"}  (${estado})\n`);
      }
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const create = defineCommand({
  meta: { name: "create", description: "Crea una máscara (alias) en un dominio" },
  args: {
    ...aliasArgs,
    mailbox: { type: "boolean", description: "Crea también un buzón IMAP (requiere dominio activado)" },
    json: { type: "boolean", description: "Salida en JSON para scripts/agentes" },
  },
  async run({ args }) {
    // domain y alias ya consumieron los 2 primeros positionals; el resto son destinos.
    const destinations = args._.slice(2);
    if (destinations.length === 0 && !args.mailbox) {
      process.stderr.write("✖ Hace falta al menos un destino, o --mailbox.\n");
      process.exit(1);
    }
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    const input: CreateAliasInput = { alias: args.alias, destinations };
    if (args.mailbox) input.mailbox = true;
    try {
      const created = await client.aliases.create(id, input);
      if (args.json) return printJson(created);
      process.stdout.write(`✓ Máscara creada: ${created.alias}  →  ${created.destinations.join(", ") || "(sin destinos)"}\n`);
      if (created.buzon) {
        process.stdout.write(`  Buzón: ${created.buzon.email}\n`);
        process.stdout.write(`  Contraseña: ${maskSecret(created.buzon.password)}\n`);
        process.stdout.write(AFTER_SECRET);
      } else if (created.errorBuzon) {
        process.stdout.write(`  ⚠ No se pudo crear el buzón: ${created.errorBuzon}\n`);
      }
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const update = defineCommand({
  meta: { name: "update", description: "Actualiza una máscara: destinos y/o estado (activa/desactiva)" },
  args: {
    ...aliasArgs,
    enable: { type: "boolean", description: "Activa la máscara" },
    disable: { type: "boolean", description: "Desactiva la máscara" },
    json: { type: "boolean", description: "Salida en JSON para scripts/agentes" },
  },
  async run({ args }) {
    if (args.enable && args.disable) {
      process.stderr.write("✖ --enable y --disable son mutuamente excluyentes.\n");
      process.exit(1);
    }
    const destinations = args._.slice(2);
    const input: UpdateAliasInput = {};
    if (args.enable) input.enabled = true;
    if (args.disable) input.enabled = false;
    if (destinations.length > 0) input.destinations = destinations;
    if (Object.keys(input).length === 0) {
      process.stderr.write("✖ Nada que actualizar: pasa --enable, --disable o destinos nuevos.\n");
      process.exit(1);
    }
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const updated = await client.aliases.update(id, args.alias, input);
      if (args.json) return printJson(updated);
      process.stdout.write(`✓ Máscara actualizada: ${updated.alias}  →  ${updated.destinations.join(", ") || "(sin destinos)"}  (${updated.enabled ? "activa" : "desactivada"})\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const del = defineCommand({
  meta: { name: "delete", description: "Borra una máscara" },
  args: { ...aliasArgs, ...yesArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    await confirmOrExit(`¿Borrar la máscara "${args.alias}"? Es irreversible.`, { yes: args.yes, json: args.json });
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      await client.aliases.delete(id, args.alias);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
    if (args.json) return printJson({ ok: true });
    process.stdout.write(`✓ Máscara borrada: ${args.alias}\n`);
  },
});

const mailboxCreate = defineCommand({
  meta: { name: "create", description: "Crea un buzón IMAP para una máscara existente (requiere dominio activado)" },
  args: { ...aliasArgs, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const mailbox = await client.aliases.createMailbox(id, args.alias);
      if (args.json) return printJson(mailbox);
      process.stdout.write(`✓ Buzón creado: ${mailbox.email}\n`);
      process.stdout.write(`  Contraseña: ${maskSecret(mailbox.password)}\n`);
      process.stdout.write(AFTER_SECRET);
      process.stdout.write(`  IMAP: ${mailbox.imap.host}:${mailbox.imap.port} (${mailbox.imap.security})\n`);
      process.stdout.write(`  SMTP: ${mailbox.smtp.host}:${mailbox.smtp.port} (${mailbox.smtp.security})\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const mailboxDelete = defineCommand({
  meta: { name: "delete", description: "Borra el buzón de una máscara Y su correo (la máscara debe conservar al menos un destino)" },
  args: { ...aliasArgs, ...yesArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    await confirmOrExit(`¿Borrar el buzón de "${args.alias}"? Se borra también su correo. Es irreversible.`, { yes: args.yes, json: args.json });
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      await client.aliases.deleteMailbox(id, args.alias);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
    if (args.json) return printJson({ ok: true });
    process.stdout.write(`✓ Buzón borrado: ${args.alias}\n`);
  },
});

const resetPassword = defineCommand({
  meta: { name: "reset-password", description: "Genera una contraseña nueva para el buzón (sólo se devuelve aquí; la anterior deja de servir)" },
  args: { ...aliasArgs, ...yesArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    await confirmOrExit(`¿Generar una contraseña nueva para el buzón de "${args.alias}"? La anterior deja de servir.`, { yes: args.yes, json: args.json });
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const result = await client.aliases.resetMailboxPassword(id, args.alias);
      if (args.json) return printJson(result);
      process.stdout.write(`✓ Contraseña reiniciada: ${maskSecret(result.password)}\n`);
      process.stdout.write(AFTER_SECRET);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const mailbox = defineCommand({
  meta: { name: "mailbox", description: "Administra el buzón IMAP de una máscara" },
  subCommands: { create: mailboxCreate, delete: mailboxDelete, "reset-password": resetPassword },
});

const appleProfile = defineCommand({
  meta: { name: "apple-profile", description: "Genera el perfil de configuración de Apple Mail (.mobileconfig) para el buzón de una máscara" },
  args: {
    ...aliasArgs,
    output: { type: "string", alias: "o", description: "Ruta del archivo .mobileconfig a escribir" },
  },
  async run({ args }) {
    if (!args.output) {
      process.stderr.write("✖ Hace falta -o/--output con la ruta del archivo.\n");
      process.exit(1);
    }
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain);
    try {
      const profile = await client.aliases.appleProfile(id, args.alias);
      await writeFile(args.output, profile);
      process.stdout.write(`✓ Perfil escrito en ${args.output}\n`);
    } catch (err) {
      failFromError(err);
    }
  },
});

const exportMailbox = defineCommand({
  meta: { name: "export", description: "Exporta el buzón de una máscara en formato mbox, a un archivo o a stdout" },
  args: {
    ...aliasArgs,
    output: { type: "string", alias: "o", description: "Ruta del archivo a escribir; sin esto, sale por stdout" },
  },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain);
    try {
      const res = await client.aliases.exportMbox(id, args.alias);
      const buffer = Buffer.from(await res.arrayBuffer());
      if (args.output) {
        await writeFile(args.output, buffer);
        process.stderr.write(`✓ Exportado a ${args.output}\n`);
      } else {
        process.stdout.write(buffer);
      }
    } catch (err) {
      failFromError(err);
    }
  },
});

export default defineCommand({
  meta: { name: "aliases", description: "Administra las máscaras (alias) y buzones de un dominio" },
  subCommands: {
    list,
    create,
    update,
    delete: del,
    mailbox,
    "apple-profile": appleProfile,
    export: exportMailbox,
  },
});
