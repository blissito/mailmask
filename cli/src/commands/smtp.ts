import { defineCommand } from "citty";
import { requireClient } from "../client.js";
import { confirmOrExit, failFromError, printJson } from "../output.js";
import { resolveDomainId } from "../resolve.js";
import { domainArg, jsonArg, yesArg } from "../args.js";

const list = defineCommand({
  meta: { name: "list", description: "Lista las credenciales SMTP de un dominio (sin contraseñas)" },
  args: { ...domainArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const creds = (await client.smtp.list(id)).map(({ id, label, iamUsername, createdAt }) => ({ id, label, iamUsername, createdAt }));
      if (args.json) return printJson(creds);
      if (creds.length === 0) {
        process.stdout.write('Sin credenciales SMTP. Crea una con "mailmask smtp create <dominio> <etiqueta>".\n');
        return;
      }
      for (const c of creds) process.stdout.write(`${c.id}  ${c.label}  usuario: ${c.iamUsername}  ${c.createdAt}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const create = defineCommand({
  meta: { name: "create", description: "Crea una credencial SMTP (la contraseña sale completa sólo aquí; requiere dominio activado)" },
  args: {
    ...domainArg,
    label: { type: "positional", description: "Etiqueta para reconocerla, p. ej. app-produccion" },
    ...jsonArg,
  },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const cred = await client.smtp.create(id, args.label);
      if (args.json) return printJson(cred);
      process.stdout.write(`✓ Credencial SMTP creada: ${cred.id}  (${cred.label})\n`);
      process.stdout.write(`  Servidor:   ${cred.server}\n`);
      process.stdout.write(`  Puerto:     ${cred.port}\n`);
      process.stdout.write(`  Cifrado:    ${cred.encryption}\n`);
      process.stdout.write(`  Usuario:    ${cred.username}\n`);
      process.stdout.write(`  Contraseña: ${cred.password}\n`);
      process.stdout.write(`  Guárdala ahora: no se vuelve a mostrar. Para otra, revoca esta ("mailmask smtp revoke ${args.domain} ${cred.id}") y crea una nueva.\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const revoke = defineCommand({
  meta: { name: "revoke", description: "Revoca una credencial SMTP: deja de servir de inmediato" },
  args: {
    ...domainArg,
    id: { type: "positional", description: "Id de la credencial (lo muestra `smtp list`)" },
    ...yesArg,
    ...jsonArg,
  },
  async run({ args }) {
    const { client } = await requireClient();
    await confirmOrExit(`¿Revocar la credencial SMTP "${args.id}"? Lo que la use dejará de poder enviar.`, { yes: args.yes, json: args.json });
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      await client.smtp.revoke(id, args.id);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
    if (args.json) return printJson({ ok: true });
    process.stdout.write(`✓ Credencial SMTP revocada: ${args.id}\n`);
  },
});

export default defineCommand({
  meta: { name: "smtp", description: "Administra las credenciales SMTP de un dominio" },
  subCommands: { list, create, revoke },
});
