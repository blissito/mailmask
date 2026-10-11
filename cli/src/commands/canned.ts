import { defineCommand } from "citty";
import { requireClient } from "../client.js";
import { confirmOrExit, failFromError, printJson } from "../output.js";
import { resolveDomainId } from "../resolve.js";
import { domainArg, jsonArg, yesArg } from "../args.js";

const list = defineCommand({
  meta: { name: "list", description: "Lista las respuestas guardadas de un dominio" },
  args: { ...domainArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const items = await client.canned.list(id);
      if (args.json) return printJson(items);
      if (items.length === 0) {
        process.stdout.write("Sin respuestas guardadas.\n");
        return;
      }
      for (const c of items) process.stdout.write(`${c.id}  ${c.title}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const create = defineCommand({
  meta: { name: "create", description: "Guarda una respuesta para reusarla en la Bandeja" },
  args: {
    ...domainArg,
    title: { type: "string", required: true, description: "Título con el que la encuentra el equipo" },
    body: { type: "string", required: true, description: "Texto de la respuesta" },
    ...jsonArg,
  },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const created = await client.canned.create(id, { title: args.title, body: args.body });
      if (args.json) return printJson(created);
      process.stdout.write(`✓ Guardada: ${created.title} (${created.id})\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const del = defineCommand({
  meta: { name: "delete", description: "Borra una respuesta guardada" },
  args: {
    ...domainArg,
    id: { type: "positional", description: "Id de la respuesta guardada" },
    ...yesArg,
    ...jsonArg,
  },
  async run({ args }) {
    const { client } = await requireClient();
    await confirmOrExit(`¿Borrar la respuesta guardada "${args.id}"?`, { yes: args.yes, json: args.json });
    const domainId = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      await client.canned.delete(domainId, args.id);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
    if (args.json) return printJson({ ok: true });
    process.stdout.write(`✓ Borrada: ${args.id}\n`);
  },
});

export default defineCommand({
  meta: { name: "canned", description: "Respuestas guardadas de la Bandeja de un dominio" },
  subCommands: { list, create, delete: del },
});
