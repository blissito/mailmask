import { defineCommand } from "citty";
import { requireClient } from "../client.js";
import { confirmOrExit, failFromError, failUsage, printJson } from "../output.js";
import { resolveDomainId } from "../resolve.js";
import { MEMBER_ROLES, domainArg, jsonArg, yesArg } from "../args.js";

const list = defineCommand({
  meta: { name: "list", description: "Lista el equipo de un dominio y sus invitaciones pendientes" },
  args: { ...domainArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const { members, invites } = await client.members.list(id);
      if (args.json) return printJson({ members, invites });
      if (members.length === 0 && invites.length === 0) {
        process.stdout.write("Sin equipo. Invita con \"mailmask members invite <dominio> --email ... --name ...\".\n");
        return;
      }
      for (const m of members) process.stdout.write(`${m.email}  ${m.role}  ${m.name}  (${m.id})\n`);
      for (const i of invites) process.stdout.write(`${i.email}  ${i.role}  invitación pendiente hasta ${i.expiresAt}  (${i.token})\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const invite = defineCommand({
  meta: { name: "invite", description: "Invita a alguien al equipo del dominio e imprime su liga de invitación" },
  args: {
    ...domainArg,
    email: { type: "string", required: true, description: "Correo de la persona invitada" },
    name: { type: "string", required: true, description: "Nombre de la persona invitada" },
    role: { type: "string", description: `Rol: ${MEMBER_ROLES.join(" | ")} (por omisión agent)` },
    ...jsonArg,
  },
  async run({ args }) {
    if (args.role !== undefined && !(MEMBER_ROLES as readonly string[]).includes(args.role)) {
      failUsage(`Rol no válido: "${args.role}". Usa ${MEMBER_ROLES.join(" o ")}.`, { json: args.json });
    }
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const result = await client.members.invite(id, { email: args.email, name: args.name, role: args.role as (typeof MEMBER_ROLES)[number] | undefined });
      if (args.json) return printJson(result);
      process.stdout.write(`✓ Invitación creada para ${args.email}. Compártele esta liga:\n${result.inviteUrl}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const remove = defineCommand({
  meta: { name: "remove", description: "Quita a una persona del equipo del dominio" },
  args: { ...domainArg, member: { type: "positional", description: "Id del miembro (lo muestra members list)" }, ...yesArg, ...jsonArg },
  async run({ args }) {
    await confirmOrExit(`¿Quitar a ${args.member} del equipo de "${args.domain}"? Pierde el acceso.`, { yes: args.yes, json: args.json });
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      await client.members.remove(id, args.member);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
    if (args.json) return printJson({ ok: true });
    process.stdout.write(`✓ Miembro quitado: ${args.member}\n`);
  },
});

const cancelInvite = defineCommand({
  meta: { name: "cancel-invite", description: "Cancela una invitación pendiente" },
  args: { ...domainArg, token: { type: "positional", description: "Token de la invitación (lo muestra members list)" }, ...yesArg, ...jsonArg },
  async run({ args }) {
    await confirmOrExit(`¿Cancelar la invitación ${args.token} de "${args.domain}"? La liga dejará de servir.`, { yes: args.yes, json: args.json });
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      await client.members.cancelInvite(id, args.token);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
    if (args.json) return printJson({ ok: true });
    process.stdout.write(`✓ Invitación cancelada: ${args.token}\n`);
  },
});

export default defineCommand({
  meta: { name: "members", description: "Equipo de un dominio: miembros e invitaciones" },
  subCommands: { list, invite, remove, "cancel-invite": cancelInvite },
});
