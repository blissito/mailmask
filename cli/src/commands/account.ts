import { readFile, stat } from "node:fs/promises";
import { extname } from "node:path";
import { defineCommand } from "citty";
import { requireClient } from "../client.js";
import { confirmOrExit, failFromError, failUsage, printJson } from "../output.js";
import { jsonArg, yesArg } from "../args.js";

const NAME_MAX = 60; // mismo tope que el servidor; si cambia allá, moverlo aquí
const AVATAR_TYPES: Record<string, string> = { ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp" };
const AVATAR_MAX_BYTES = 2 * 1024 * 1024; // mismo tope que el servidor; si cambia allá, moverlo aquí

function printProfile(p: { email: string; displayName: string | null; avatarUrl: string | null }): void {
  process.stdout.write(`${p.email}  nombre: ${p.displayName ?? "(sin nombre)"}  foto: ${p.avatarUrl ?? "(sin foto)"}\n`);
}

const profile = defineCommand({
  meta: { name: "profile", description: "Muestra tu perfil, o cambia tu nombre visible con --name (vacío lo borra)" },
  args: {
    name: { type: "string", description: `Nombre visible (máx. ${NAME_MAX} caracteres); "" lo borra` },
    ...jsonArg,
  },
  async run({ args }) {
    if (args.name !== undefined && [...args.name].length > NAME_MAX) {
      failUsage(`El nombre mide ${[...args.name].length} caracteres; el máximo es ${NAME_MAX}.`, { json: args.json });
    }
    const { client } = await requireClient();
    try {
      const result = args.name === undefined ? await client.account.getProfile() : await client.account.updateProfile({ displayName: args.name });
      if (args.json) return printJson(result);
      if (args.name !== undefined) process.stdout.write("✓ Perfil actualizado\n");
      printProfile(result);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const avatarSet = defineCommand({
  meta: { name: "set", description: "Cambia tu foto (archivo local PNG, JPG o WebP, máx. 2 MB)" },
  args: {
    file: { type: "positional", description: "Ruta del archivo de imagen" },
    ...jsonArg,
  },
  async run({ args }) {
    const mime = AVATAR_TYPES[extname(args.file).toLowerCase()];
    if (!mime) failUsage(`Formato no válido: "${args.file}". Usa .png, .jpg, .jpeg o .webp.`, { json: args.json });
    let size: number;
    try {
      size = (await stat(args.file)).size;
    } catch (err) {
      failUsage(`No se pudo leer "${args.file}": ${err instanceof Error ? err.message : String(err)}`, { json: args.json });
    }
    if (size > AVATAR_MAX_BYTES) failUsage(`La foto pesa ${(size / 1024 / 1024).toFixed(1)} MB; el máximo es 2 MB.`, { json: args.json });
    const bytes = await readFile(args.file);
    const { client } = await requireClient();
    try {
      const result = await client.account.setAvatar(new Blob([bytes], { type: mime }), args.file.split(/[\\/]/).pop());
      if (args.json) return printJson(result);
      process.stdout.write(`✓ Foto actualizada: ${result.avatarUrl ?? "(sin foto)"}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const avatarRemove = defineCommand({
  meta: { name: "remove", description: "Quita tu foto" },
  args: { ...yesArg, ...jsonArg },
  async run({ args }) {
    await confirmOrExit("¿Quitar tu foto de perfil?", { yes: args.yes, json: args.json });
    const { client } = await requireClient();
    try {
      const result = await client.account.removeAvatar();
      if (args.json) return printJson(result);
      process.stdout.write("✓ Foto quitada\n");
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const avatar = defineCommand({
  meta: { name: "avatar", description: "Foto de tu perfil" },
  subCommands: { set: avatarSet, remove: avatarRemove },
});

export default defineCommand({
  meta: { name: "account", description: "Tu perfil: nombre visible y foto" },
  subCommands: { profile, avatar },
});
