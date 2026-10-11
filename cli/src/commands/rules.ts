import { defineCommand } from "citty";
import type { CreateRuleInput, Rule, RuleAction, RuleField, RuleMatch, UpdateRuleInput } from "@easybits.cloud/mailmask";
import { requireClient } from "../client.js";
import { confirmOrExit, failFromError, failUsage, printJson } from "../output.js";
import { resolveDomainId } from "../resolve.js";
import { RULE_ACTIONS, RULE_FIELDS, RULE_MATCHES, domainArg, jsonArg, yesArg } from "../args.js";

const idArgs = {
  ...domainArg,
  ruleId: { type: "positional" as const, description: "Id de la regla (lo muestra `rules list`)" },
};

const ruleFlags = {
  field: { type: "string" as const, description: `Campo del correo: ${RULE_FIELDS.join(", ")}` },
  match: { type: "string" as const, description: `Tipo de coincidencia: ${RULE_MATCHES.join(", ")} (regex lo valida el servidor)` },
  value: { type: "string" as const, description: "Texto o patrón a buscar" },
  action: { type: "string" as const, description: `Qué hacer: ${RULE_ACTIONS.join(", ")}` },
  target: { type: "string" as const, description: "Destino del forward o URL del webhook (obligatorio con forward/webhook)" },
  priority: { type: "string" as const, description: "Prioridad (entero; la regla de menor número corre primero)" },
};

function oneOf<T extends string>(flag: string, raw: string, allowed: readonly T[], json?: boolean): T {
  if (!allowed.includes(raw as T)) failUsage(`--${flag} no válido: "${raw}". Los válidos son: ${allowed.join(", ")}.`, { json });
  return raw as T;
}

function parsePriority(raw: string, json?: boolean): number {
  if (!/^-?\d+$/.test(raw.trim())) failUsage(`--priority debe ser un entero, no "${raw}".`, { json });
  return Number(raw);
}

/** Valida los flags que vinieron (todos opcionales) ANTES de tocar la red; la regex NO se valida aquí: el 400 del servidor sale tal cual. */
function parseFlags(args: Record<string, any>): UpdateRuleInput {
  const json = args.json as boolean | undefined;
  const input: UpdateRuleInput = {};
  if (args.field !== undefined) input.field = oneOf<RuleField>("field", args.field, RULE_FIELDS, json);
  if (args.match !== undefined) input.match = oneOf<RuleMatch>("match", args.match, RULE_MATCHES, json);
  if (args.action !== undefined) input.action = oneOf<RuleAction>("action", args.action, RULE_ACTIONS, json);
  if (args.value !== undefined) input.value = args.value;
  if (args.target !== undefined) input.target = args.target;
  if (args.priority !== undefined) input.priority = parsePriority(args.priority, json);
  return input;
}

function needsTarget(action: RuleAction | undefined): boolean {
  return action === "forward" || action === "webhook";
}

function line(r: Rule): string {
  const destino = r.target ? ` → ${r.target}` : "";
  return `${r.id}  [${r.priority}] ${r.field} ${r.match} "${r.value}"  ${r.action}${destino}  (${r.enabled ? "activa" : "desactivada"})\n`;
}

const list = defineCommand({
  meta: { name: "list", description: "Lista las reglas de un dominio" },
  args: { ...domainArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const rules = await client.rules.list(id);
      if (args.json) return printJson(rules);
      if (rules.length === 0) {
        process.stdout.write('Sin reglas. Crea una con "mailmask rules create <dominio> --field subject --match contains --value factura --action forward --target yo@acme.com".\n');
        return;
      }
      for (const r of rules) process.stdout.write(line(r));
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const create = defineCommand({
  meta: { name: "create", description: "Crea una regla (una regex peligrosa la rechaza el servidor)" },
  args: {
    ...domainArg,
    ...ruleFlags,
    disabled: { type: "boolean", description: "Crea la regla desactivada" },
    ...jsonArg,
  },
  async run({ args }) {
    const missing = (["field", "match", "value", "action"] as const).filter((f) => args[f] === undefined);
    if (missing.length > 0) failUsage(`Faltan flags obligatorios: ${missing.map((f) => `--${f}`).join(", ")}.`, { json: args.json });
    const parsed = parseFlags(args);
    if (needsTarget(parsed.action) && !parsed.target) {
      failUsage(`--target es obligatorio con --action ${parsed.action}.`, { json: args.json });
    }
    const input: CreateRuleInput = {
      field: parsed.field!,
      match: parsed.match!,
      value: parsed.value!,
      action: parsed.action!,
      ...(parsed.target !== undefined && { target: parsed.target }),
      ...(parsed.priority !== undefined && { priority: parsed.priority }),
      ...(args.disabled && { enabled: false }),
    };
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const created = await client.rules.create(id, input);
      if (args.json) return printJson(created);
      process.stdout.write(`✓ Regla creada: ${line(created)}`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const update = defineCommand({
  meta: { name: "update", description: "Cambia una regla; sólo se envía lo que pases" },
  args: {
    ...idArgs,
    ...ruleFlags,
    enable: { type: "boolean", description: "Activa la regla" },
    disable: { type: "boolean", description: "Desactiva la regla" },
    ...jsonArg,
  },
  async run({ args }) {
    if (args.enable && args.disable) failUsage("--enable y --disable son mutuamente excluyentes.", { json: args.json });
    const input = parseFlags(args);
    if (args.enable) input.enabled = true;
    if (args.disable) input.enabled = false;
    if (Object.keys(input).length === 0) {
      failUsage("Nada que actualizar: pasa --field, --match, --value, --action, --target, --priority, --enable o --disable.", { json: args.json });
    }
    if (needsTarget(input.action) && !input.target) {
      failUsage(`--target es obligatorio con --action ${input.action}.`, { json: args.json });
    }
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const updated = await client.rules.update(id, args.ruleId, input);
      if (args.json) return printJson(updated);
      process.stdout.write(`✓ Regla actualizada: ${line(updated)}`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const del = defineCommand({
  meta: { name: "delete", description: "Borra una regla" },
  args: { ...idArgs, ...yesArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    await confirmOrExit(`¿Borrar la regla "${args.ruleId}"? Es irreversible.`, { yes: args.yes, json: args.json });
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      await client.rules.delete(id, args.ruleId);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
    if (args.json) return printJson({ ok: true });
    process.stdout.write(`✓ Regla borrada: ${args.ruleId}\n`);
  },
});

export default defineCommand({
  meta: { name: "rules", description: "Administra las reglas de un dominio" },
  subCommands: { list, create, update, delete: del },
});
