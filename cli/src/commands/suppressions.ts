import { defineCommand } from "citty";
import { requireClient } from "../client.js";
import { confirmOrExit, failFromError, printJson } from "../output.js";
import { resolveDomainId } from "../resolve.js";
import { domainArg, jsonArg, yesArg } from "../args.js";

const emailArgs = {
  ...domainArg,
  email: { type: "positional" as const, description: "Correo a suprimir / reactivar" },
};

const list = defineCommand({
  meta: { name: "list", description: "Lista los correos suprimidos de un dominio (bounces, quejas y manuales)" },
  args: { ...domainArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const items = await client.suppressions.list(id);
      if (args.json) return printJson(items);
      if (items.length === 0) {
        process.stdout.write("Sin correos suprimidos.\n");
        return;
      }
      for (const s of items) process.stdout.write(`${s.email}  ${s.reason}  ${s.createdAt}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const add = defineCommand({
  meta: { name: "add", description: "Suprime un correo: no se le volverá a enviar desde este dominio" },
  args: { ...emailArgs, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const created = await client.suppressions.add(id, args.email);
      if (args.json) return printJson(created);
      process.stdout.write(`✓ Suprimido: ${created.email} (${created.reason})\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const remove = defineCommand({
  meta: { name: "remove", description: "Quita un correo de la lista de supresión" },
  args: { ...emailArgs, ...yesArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    await confirmOrExit(`¿Quitar "${args.email}" de la lista de supresión? Volverá a recibir correo.`, { yes: args.yes, json: args.json });
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      await client.suppressions.remove(id, args.email);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
    if (args.json) return printJson({ ok: true });
    process.stdout.write(`✓ Quitado de la lista: ${args.email}\n`);
  },
});

export default defineCommand({
  meta: { name: "suppressions", description: "Administra la lista de supresión de un dominio" },
  subCommands: { list, add, remove },
});
