import { defineCommand } from "citty";
import { requireClient } from "../client.js";
import { failFromError, failUsage, printJson } from "../output.js";
import { resolveDomainId } from "../resolve.js";
import { domainArg, jsonArg } from "../args.js";

/** Límite del servidor para la firma (caracteres). */
const MAX_SIGNATURE = 2000;

const get = defineCommand({
  meta: { name: "get", description: "Muestra la firma en markdown de un dominio" },
  args: { ...domainArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const res = await client.signature.get(id);
      if (args.json) return printJson(res);
      process.stdout.write(res.signature ? `${res.signature}\n` : "Sin firma.\n");
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const set = defineCommand({
  meta: { name: "set", description: 'Fija la firma (markdown, máx. 2000 caracteres); "" la borra' },
  args: {
    ...domainArg,
    markdown: { type: "positional", description: 'Firma en markdown; "" la borra' },
    ...jsonArg,
  },
  async run({ args }) {
    const markdown = args.markdown ?? "";
    if (markdown.length > MAX_SIGNATURE) {
      failUsage(`La firma mide ${markdown.length} caracteres; el máximo es ${MAX_SIGNATURE}.`, { json: args.json });
    }
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const res = await client.signature.set(id, markdown);
      if (args.json) return printJson(res);
      process.stdout.write(markdown ? "✓ Firma guardada\n" : "✓ Firma borrada\n");
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

export default defineCommand({
  meta: { name: "signature", description: "Firma de los correos de un dominio" },
  subCommands: { get, set },
});
