import { defineCommand } from "citty";
import { requireClient } from "../client.js";
import { confirmOrExit, failFromError, printJson } from "../output.js";
import { jsonArg, yesArg } from "../args.js";

const list = defineCommand({
  meta: { name: "list", description: "Lista tus API keys (nombre, prefijo, último uso); marca la que usa esta sesión" },
  args: { ...jsonArg },
  async run({ args }) {
    const { client, auth } = await requireClient();
    try {
      const keys = (await client.apiKeys.list()).map((k) => ({ ...k, active: k.keyPrefix !== "" && auth.apiKey.startsWith(k.keyPrefix) }));
      if (args.json) return printJson(keys);
      if (keys.length === 0) {
        process.stdout.write('Sin API keys. Crea una con "mailmask api-keys create <nombre>".\n');
        return;
      }
      for (const k of keys) {
        process.stdout.write(`${k.id}  ${k.name}  ${k.keyPrefix}...  último uso: ${k.lastUsedAt ?? "nunca"}${k.active ? "  ← activa (esta sesión)" : ""}\n`);
      }
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const create = defineCommand({
  meta: { name: "create", description: "Crea una API key (sale completa sólo aquí)" },
  args: { name: { type: "positional", description: "Nombre para reconocerla, p. ej. ci-github" }, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    try {
      const created = await client.apiKeys.create(args.name);
      if (args.json) return printJson(created);
      process.stdout.write(`✓ API key creada: ${created.id}  (${created.name})\n`);
      process.stdout.write(`  Llave: ${created.key}\n`);
      process.stdout.write("  Guárdala ahora: no se vuelve a mostrar.\n");
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const revoke = defineCommand({
  meta: { name: "revoke", description: "Revoca una API key; si es la de esta sesión, te quedas sin llave" },
  args: { id: { type: "positional", description: "Id de la llave (lo muestra `api-keys list`)" }, ...yesArg, ...jsonArg },
  async run({ args }) {
    const { client, auth } = await requireClient();
    // Confirmación genérica primero (contrato de la ficha): sin TTY y sin --yes sale con 1 sin tocar la API.
    await confirmOrExit(`¿Revocar la API key "${args.id}"? Deja de servir de inmediato.`, { yes: args.yes, json: args.json });

    // Excepción documentada a "confirmar antes de listar": para avisar de la llave activa hay que leerla.
    let activeKeyRevoked = false;
    try {
      const target = (await client.apiKeys.list()).find((k) => k.id === args.id);
      activeKeyRevoked = !!target && target.keyPrefix !== "" && auth.apiKey.startsWith(target.keyPrefix);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
    if (activeKeyRevoked) {
      const warning = "Es la llave con la que estás conectado: la sesión quedará sin llave.";
      if (args.yes) process.stderr.write(`⚠ ${warning}\n`);
      else await confirmOrExit(`${warning} ¿Revocarla de todos modos?`, { json: args.json });
    }

    try {
      await client.apiKeys.revoke(args.id);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
    if (args.json) return printJson(activeKeyRevoked ? { ok: true, activeKeyRevoked: true } : { ok: true });
    process.stdout.write(`✓ API key revocada: ${args.id}\n`);
    if (activeKeyRevoked) process.stdout.write('  Corre "mailmask login" para volver a conectarte.\n');
  },
});

export default defineCommand({
  meta: { name: "api-keys", description: "Administra tus API keys" },
  subCommands: { list, create, revoke },
});
