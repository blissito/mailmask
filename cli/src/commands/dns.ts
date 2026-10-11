import { defineCommand } from "citty";
import type { DnsPreset, DnsRecordType, MailMask } from "@easybits.cloud/mailmask";
import { requireClient } from "../client.js";
import { confirmOrExit, failFromError, printJson } from "../output.js";
import { resolveDomainId } from "../resolve.js";
import { PRESETS, jsonArg, domainArg, yesArg } from "../args.js";

const RECORD_TYPES: DnsRecordType[] = ["A", "AAAA", "CNAME", "TXT", "MX", "NS", "CAA", "SRV"];

function checkRecordType(type: string): asserts type is DnsRecordType {
  if (!RECORD_TYPES.includes(type as DnsRecordType)) {
    process.stderr.write(`✖ Tipo de registro desconocido: "${type}". Usa uno de: ${RECORD_TYPES.join(", ")}\n`);
    process.exit(1);
  }
}

// Convención dura (docs/agents/mailmask-cli.md): ningún registro managed se
// toca desde el CLI, ni con --force. El servidor también lo rechaza (409),
// pero rehusarse aquí da un mensaje claro sin gastar la llamada de red.
//
// Falla CERRADO: si no se pudo listar (red, 5xx, lo que sea), NO se deja pasar
// la mutación — se aborta. Antes dejaba seguir cuando `dns.list` lanzaba, que
// es exactamente el escenario en el que menos se sabe si el registro es
// managed, y es el peor momento para arriesgarse.
export async function refuseIfManaged(
  client: MailMask,
  domainId: string,
  name: string,
  type: DnsRecordType,
  opts: { json?: boolean } = {},
): Promise<void> {
  let current: Awaited<ReturnType<typeof client.dns.list>>;
  try {
    current = await client.dns.list(domainId);
  } catch (err) {
    const reason = `No se pudo confirmar si ${type} ${name} está protegido por MailMask; no se arriesga la mutación. (${err instanceof Error ? err.message : String(err)})`;
    if (opts.json) {
      process.stderr.write(`${JSON.stringify({ error: reason })}\n`);
      process.exit(1);
    }
    process.stderr.write(`✖ ${reason}\n`);
    process.exit(1);
  }
  const match = current.records?.find((r) => r.name === name && r.type === type);
  if (match?.managed) {
    const reason = `${type} ${name} lo administra MailMask${match.managedReason ? ` (${match.managedReason})` : ""} — no se puede tocar desde el CLI.`;
    if (opts.json) {
      process.stderr.write(`${JSON.stringify({ error: reason })}\n`);
      process.exit(1);
    }
    process.stderr.write(`✖ ${reason}\n`);
    process.exit(1);
  }
}

const list = defineCommand({
  meta: { name: "list", description: "Lista los registros DNS de un dominio (managed: true son los que protege MailMask)" },
  args: { ...domainArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const result = await client.dns.list(id);
      if (args.json) return printJson(result);
      if (result.hint) {
        process.stdout.write(`${result.hint}\n`);
        return;
      }
      process.stdout.write(`Zona: ${result.zone.status}${result.zone.delegated === false ? " (nameservers aún no delegados)" : ""}\n`);
      for (const r of result.records) {
        const flags = r.managed ? ` [managed${r.managedReason ? `: ${r.managedReason}` : ""}]` : r.editable ? "" : " [no editable]";
        process.stdout.write(`${r.type.padEnd(5)} ${r.name}  →  ${r.values.join(", ")}  (ttl ${r.ttl})${flags}\n`);
      }
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const upsert = defineCommand({
  meta: { name: "upsert", description: "Reemplaza el conjunto de valores de un (nombre, tipo) — no es un append" },
  args: {
    domain: { type: "positional", description: "Dominio (acme.com) o su id" },
    name: { type: "positional", description: "Nombre del registro, p. ej. @ o app" },
    type: { type: "positional", description: `Tipo: ${RECORD_TYPES.join(", ")}` },
    ttl: { type: "string", description: "TTL en segundos (60–172800, por omisión 300)" },
    json: { type: "boolean", description: "Salida en JSON para scripts/agentes" },
  },
  async run({ args }) {
    checkRecordType(args.type);
    // domain/name/type ya consumieron los 3 primeros positionals; citty no
    // tiene un tipo "rest", así que el resto de valores sueltos se toma
    // directo de `args._` (la lista completa de positionals sin tocar).
    const values = args._.slice(3);
    if (values.length === 0) {
      process.stderr.write("✖ Hace falta al menos un valor.\n");
      process.exit(1);
    }
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    await refuseIfManaged(client, id, args.name, args.type, { json: args.json });
    try {
      const result = await client.dns.upsert(id, {
        name: args.name,
        type: args.type,
        values,
        ttl: args.ttl ? Number(args.ttl) : undefined,
      });
      if (args.json) return printJson(result);
      process.stdout.write(`✓ ${args.type} ${args.name} → ${values.join(", ")} (propagación: ${result.propagacion})\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const del = defineCommand({
  meta: { name: "delete", description: "Borra un conjunto de registros (nombre, tipo) completo" },
  args: {
    domain: { type: "positional", description: "Dominio (acme.com) o su id" },
    name: { type: "positional", description: "Nombre del registro" },
    type: { type: "positional", description: `Tipo: ${RECORD_TYPES.join(", ")}` },
    ...yesArg,
    json: { type: "boolean", description: "Salida en JSON para scripts/agentes" },
  },
  async run({ args }) {
    checkRecordType(args.type);
    const { client } = await requireClient();
    await confirmOrExit(`¿Borrar el registro ${args.type} ${args.name}? Es irreversible.`, { yes: args.yes, json: args.json });
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    await refuseIfManaged(client, id, args.name, args.type, { json: args.json });
    try {
      const result = await client.dns.delete(id, args.name, args.type);
      if (args.json) return printJson(result);
      process.stdout.write(`✓ Borrado: ${args.type} ${args.name}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const preset = defineCommand({
  meta: { name: "preset", description: "Apunta el dominio a un hosting (Vercel, Netlify, ...) sin escribir los registros a mano" },
  args: {
    domain: { type: "positional", description: "Dominio (acme.com) o su id" },
    preset: { type: "positional", description: `Uno de: ${PRESETS.join(", ")}` },
    target: { type: "string", description: "Valor del registro (p. ej. el *.vercel.app del proyecto)" },
    subdomain: { type: "string", description: "Subdominio donde aplicarlo; sin esto, fija la raíz Y www" },
    json: { type: "boolean", description: "Salida en JSON para scripts/agentes" },
  },
  async run({ args }) {
    if (!PRESETS.includes(args.preset as DnsPreset)) {
      process.stderr.write(`✖ Preset desconocido: "${args.preset}". Usa uno de: ${PRESETS.join(", ")}\n`);
      process.exit(1);
    }
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const result = await client.dns.preset(id, args.preset as DnsPreset, args.target, args.subdomain);
      if (args.json) return printJson(result);
      process.stdout.write(`✓ Preset "${args.preset}" aplicado (propagación: ${result.propagacion}).\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const createZone = defineCommand({
  meta: { name: "create-zone", description: "Mueve el DNS del dominio a MailMask: importa lo que haya y devuelve los nameservers a fijar en el registrador" },
  args: { ...domainArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const result = await client.dns.createZone(id);
      if (args.json) return printJson(result);
      process.stdout.write(`✓ Zona creada (${result.hostedZoneId}).\n`);
      process.stdout.write(`  Nameservers a fijar en el registrador:\n`);
      for (const ns of result.nameservers) process.stdout.write(`    ${ns}\n`);
      process.stdout.write(`  Importados: ${result.imported.length} registro(s). ${result.importWarning}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const delegation = defineCommand({
  meta: { name: "delegation", description: "Revisa si los nameservers del dominio ya apuntan a MailMask" },
  args: { ...domainArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const result = await client.dns.delegation(id);
      if (args.json) return printJson(result);
      process.stdout.write(`Delegado: ${result.delegated ? "sí" : "no"}\n`);
      process.stdout.write(`  Observados: ${result.observed.join(", ") || "(ninguno)"}\n`);
      process.stdout.write(`  Esperados:  ${result.expected.join(", ")}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const importCmd = defineCommand({
  meta: { name: "import", description: "Muestra los registros DNS que MailMask encontró en el dominio y los nameservers (sólo lectura: no cambia nada)" },
  args: { ...domainArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const result = await client.dns.import(id);
      if (args.json) return printJson(result);
      process.stdout.write(`Encontrados: ${result.found.length} registro(s).\n`);
      for (const r of result.found) process.stdout.write(`  ${r.type}  ${r.name}  ${r.values.join(" | ")}\n`);
      process.stdout.write("  Nameservers:\n");
      for (const ns of result.nameservers) process.stdout.write(`    ${ns}\n`);
      if (result.warning) process.stdout.write(`  ${result.warning}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

export default defineCommand({
  meta: { name: "dns", description: "Administra los registros DNS de un dominio" },
  subCommands: { list, upsert, delete: del, preset, "create-zone": createZone, delegation, import: importCmd },
});
