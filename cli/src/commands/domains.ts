import { defineCommand } from "citty";
import type { DnsPreset } from "@easybits.cloud/mailmask";
import { requireClient } from "../client.js";
import { confirmOrExit, failFromError, printJson } from "../output.js";
import { resolveDomainId } from "../resolve.js";
import { PRESETS, jsonArg, domainArg, yesArg } from "../args.js";

const list = defineCommand({
  meta: { name: "list", description: "Lista los dominios de la cuenta" },
  args: jsonArg,
  async run({ args }) {
    const { client } = await requireClient();
    let domains: Awaited<ReturnType<typeof client.domains.list>> = [];
    try {
      domains = await client.domains.list();
    } catch (err) {
      failFromError(err, { json: args.json });
    }
    if (args.json) return printJson(domains);
    if (domains.length === 0) {
      process.stdout.write("Sin dominios. Crea uno con \"mailmask domains create <dominio>\".\n");
      return;
    }
    for (const d of domains) {
      const estado = [d.verified ? "verificado" : "sin verificar", d.mxConfigured ? "MX ok" : "MX pendiente"].join(", ");
      process.stdout.write(`${d.domain}  (${d.id})  ${estado}\n`);
    }
  },
});

const get = defineCommand({
  meta: { name: "get", description: "Muestra el detalle de un dominio" },
  args: { ...domainArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const domain = await client.domains.get(id);
      if (args.json) return printJson(domain);
      process.stdout.write(`${domain.domain}  (${domain.id})\n`);
      process.stdout.write(`  Verificado: ${domain.verified ? "sí" : "no"}\n`);
      process.stdout.write(`  MX configurado: ${domain.mxConfigured ? "sí" : "no"}\n`);
      process.stdout.write(`  Registrado vía MailMask: ${domain.registeredViaMailmask ? "sí" : "no"}\n`);
      process.stdout.write(`  Creado: ${domain.createdAt}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const create = defineCommand({
  meta: { name: "create", description: "Registra un dominio y, si se pide, aplica un preset de DNS" },
  args: {
    domain: { type: "positional", description: "Dominio a registrar, p. ej. acme.com" },
    preset: { type: "string", description: `Aplica este preset tras crear: ${PRESETS.join(", ")}` },
    target: { type: "string", description: "Valor del registro para el preset (p. ej. el CNAME de Vercel)" },
    subdomain: { type: "string", description: "Subdominio donde aplicar el preset (por omisión, la raíz)" },
    json: { type: "boolean", description: "Salida en JSON para scripts/agentes" },
  },
  async run({ args }) {
    if (args.preset && !PRESETS.includes(args.preset as DnsPreset)) {
      process.stderr.write(`✖ Preset desconocido: "${args.preset}". Usa uno de: ${PRESETS.join(", ")}\n`);
      process.exit(1);
    }
    const { client } = await requireClient();
    let created: Awaited<ReturnType<typeof client.domains.create>>;
    try {
      created = await client.domains.create(args.domain);
    } catch (err) {
      failFromError(err, { json: args.json });
    }

    let presetResult: Awaited<ReturnType<typeof client.dns.preset>> | null = null;
    if (args.preset) {
      try {
        presetResult = await client.dns.preset(created.domain.id, args.preset as DnsPreset, args.target, args.subdomain);
      } catch (err) {
        failFromError(err, { json: args.json });
      }
    }

    if (args.json) return printJson({ ...created, presetResult });

    process.stdout.write(`✓ Dominio creado: ${created.domain.domain} (${created.domain.id})\n`);
    if (created.requiereActivacion) {
      process.stdout.write("  Es tu 2.º dominio sin activar: se guardó pero no reenvía hasta activarlo ($99/mes).\n");
    }
    process.stdout.write(`  MX:           ${created.dnsRecords.mx.name} → ${created.dnsRecords.mx.value}\n`);
    process.stdout.write(`  Verificación:  ${created.dnsRecords.verification.name} → ${created.dnsRecords.verification.value}\n`);
    process.stdout.write(`  SPF:           ${created.dnsRecords.spf.name} → ${created.dnsRecords.spf.value}\n`);
    for (const dkim of created.dnsRecords.dkim) {
      process.stdout.write(`  DKIM:          ${dkim.name} → ${dkim.value}\n`);
    }
    if (presetResult) {
      process.stdout.write(`✓ Preset "${args.preset}" aplicado (propagación: ${presetResult.propagacion}).\n`);
    }
  },
});

const del = defineCommand({
  meta: { name: "delete", description: "Borra un dominio de la cuenta" },
  args: { ...domainArg, ...jsonArg, ...yesArg },
  async run({ args }) {
    const { client } = await requireClient();
    await confirmOrExit(`¿Borrar el dominio "${args.domain}"? Es irreversible.`, { yes: args.yes, json: args.json });
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      await client.domains.delete(id);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
    if (args.json) return printJson({ ok: true });
    process.stdout.write(`✓ Dominio borrado: ${args.domain}\n`);
  },
});

const verify = defineCommand({
  meta: { name: "verify", description: "Revisa el estado de verificación DNS/DKIM de un dominio" },
  args: { ...domainArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const result = await client.domains.verify(id);
      if (args.json) return printJson(result);
      process.stdout.write(`${result.domain}\n`);
      process.stdout.write(`  Verificado: ${result.verified ? "sí" : "no"}\n`);
      process.stdout.write(`  DKIM verificado: ${result.dkimVerified ? "sí" : "no"}\n`);
      if (result.stale) process.stdout.write("  (no se pudo consultar a SES; esto es el último estado conocido)\n");
      if (result.error) process.stdout.write(`  Error: ${result.error}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const health = defineCommand({
  meta: { name: "health", description: "Estado de salud (entregabilidad, colas, etc.) de un dominio — siempre en JSON, no tiene forma fija" },
  args: domainArg,
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: true });
    try {
      const result = await client.domains.health(id);
      printJson(result);
    } catch (err) {
      failFromError(err, { json: true });
    }
  },
});

export default defineCommand({
  meta: { name: "domains", description: "Administra los dominios de la cuenta" },
  subCommands: { list, get, create, delete: del, verify, health },
});
