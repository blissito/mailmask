import { defineCommand } from "citty";
import { requireClient } from "../client.js";
import { failFromError, printJson } from "../output.js";
import { jsonArg } from "../args.js";

const get = defineCommand({
  meta: { name: "get", description: "Tu liga de referidos y quiénes se han unido" },
  args: jsonArg,
  async run({ args }) {
    const { client } = await requireClient();
    try {
      const stats = await client.referrals.get();
      if (args.json) return printJson(stats);
      process.stdout.write(`Slug: ${stats.slug ?? "(sin definir)"}  referidos: ${stats.referrals.length}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const slug = defineCommand({
  meta: { name: "slug", description: "Cambia tu slug de referidos (3-30 caracteres: minúsculas, números y guiones)" },
  args: { slug: { type: "positional", description: "Nuevo slug" }, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    try {
      const result = await client.referrals.setSlug(args.slug);
      if (args.json) return printJson(result);
      process.stdout.write(`✓ Slug: ${result.slug}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const name = defineCommand({
  meta: { name: "name", description: "Cambia el nombre que ven tus invitados (2-40 caracteres)" },
  args: { name: { type: "positional", description: "Nombre visible" }, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    try {
      const result = await client.referrals.setName(args.name);
      if (args.json) return printJson(result);
      process.stdout.write(`✓ Nombre actualizado: ${args.name}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

export default defineCommand({
  meta: { name: "referrals", description: "Programa de referidos: tu liga, slug y nombre" },
  subCommands: { get, slug, name },
});
