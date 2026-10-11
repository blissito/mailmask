import { readFile } from "node:fs/promises";
import { defineCommand } from "citty";
import { requireClient } from "../client.js";
import { confirmOrExit, failFromError, failUsage, formatMxn, printJson } from "../output.js";
import { resolveRegistrationId } from "../resolve.js";
import { jsonArg, registrationArg, yesArg } from "../args.js";

type DnsRecordInput = { name: string; type: string; ttl?: number; values: string[] };

/** Lee y valida el arreglo de registros ANTES de tocar la red: `set-dns` reemplaza el inventario completo. */
async function readRecords(file: string, json?: boolean): Promise<DnsRecordInput[]> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(file, "utf8"));
  } catch (err) {
    failUsage(`No se pudo leer "${file}" como JSON: ${err instanceof Error ? err.message : String(err)}`, { json });
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    failUsage(`"${file}" debe ser un arreglo JSON no vacío de registros { name, type, ttl?, values[] }.`, { json });
  }
  parsed.forEach((r: unknown, i: number) => {
    const rec = r as Partial<DnsRecordInput> | null;
    const ok =
      rec !== null && typeof rec === "object" &&
      typeof rec.name === "string" && rec.name !== "" &&
      typeof rec.type === "string" && rec.type !== "" &&
      (rec.ttl === undefined || (typeof rec.ttl === "number" && Number.isInteger(rec.ttl) && rec.ttl > 0)) &&
      Array.isArray(rec.values) && rec.values.length > 0 && rec.values.every((v) => typeof v === "string" && v !== "");
    if (!ok) failUsage(`Registro #${i + 1} de "${file}" inválido: necesita name, type, values (cadenas, al menos una) y ttl entero opcional.`, { json });
  });
  return parsed as DnsRecordInput[];
}

const check = defineCommand({
  meta: { name: "check", description: "Requisitos, precio e inventario DNS para traer un dominio (no cobra ni crea nada)" },
  args: { domain: { type: "positional", description: "Nombre del dominio a trasladar (acme.com)" }, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    try {
      const result = await client.transfers.check(args.domain);
      if (args.json) return printJson(result);
      process.stdout.write(`${result.domain}  traslado ${formatMxn(result.price)} (incluye un año de renovación)\n`);
      for (const r of result.requisitos) {
        process.stdout.write(`${r.ok === true ? "✓" : r.ok === false ? "✖" : "?"} ${r.texto}${r.ayuda ? ` — ${r.ayuda}` : ""}\n`);
      }
      if (result.dns.warning) process.stdout.write(`Aviso DNS: ${result.dns.warning}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const dns = defineCommand({
  meta: { name: "dns", description: "Inventario DNS de un traslado y su estado de aprobación" },
  args: { ...registrationArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveRegistrationId(client, args.registration, { json: args.json });
    try {
      const inv = await client.transfers.dns(id);
      if (args.json) return printJson(inv);
      process.stdout.write(`Estado: ${inv.status}${inv.takenAt ? `  tomado: ${inv.takenAt}` : ""}  registros: ${inv.records.length}\n`);
      for (const r of inv.records as Array<{ name?: string; type?: string; values?: string[] }>) {
        process.stdout.write(`${r.name ?? "?"}  ${r.type ?? "?"}  ${(r.values ?? []).join(", ")}\n`);
      }
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const setDns = defineCommand({
  meta: { name: "set-dns", description: "REEMPLAZA el inventario DNS completo del traslado con un archivo JSON; queda pendiente de aprobar" },
  args: {
    ...registrationArg,
    file: { type: "string", required: true, description: "Archivo JSON: arreglo de { name, type, ttl?, values[] }" },
    ...yesArg,
    ...jsonArg,
  },
  async run({ args }) {
    const records = await readRecords(args.file, args.json);
    await confirmOrExit(`¿Reemplazar TODO el inventario DNS de "${args.registration}" con ${records.length} registro(s) de "${args.file}"? Vuelve a quedar pendiente de aprobar.`, { yes: args.yes, json: args.json });
    const { client } = await requireClient();
    const id = await resolveRegistrationId(client, args.registration, { json: args.json });
    try {
      const result = await client.transfers.setDns(id, records);
      if (args.json) return printJson(result);
      process.stdout.write(`✓ Inventario reemplazado (${result.records.length} registros). Falta aprobarlo: mailmask transfers approve-dns ${args.registration}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const approveDns = defineCommand({
  meta: { name: "approve-dns", description: "Aprueba el inventario DNS del traslado para que se publique" },
  args: { ...registrationArg, ...yesArg, ...jsonArg },
  async run({ args }) {
    await confirmOrExit(`¿Aprobar el inventario DNS de "${args.registration}"? Se publicará en el traslado.`, { yes: args.yes, json: args.json });
    const { client } = await requireClient();
    const id = await resolveRegistrationId(client, args.registration, { json: args.json });
    try {
      const result = await client.transfers.approveDns(id);
      if (args.json) return printJson(result);
      process.stdout.write("✓ Inventario DNS aprobado\n");
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const resendEmail = defineCommand({
  meta: { name: "resend-email", description: "Reenvía al dueño el correo del traslado" },
  args: { ...registrationArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveRegistrationId(client, args.registration, { json: args.json });
    try {
      const result = await client.transfers.resendEmail(id);
      if (args.json) return printJson(result);
      process.stdout.write("✓ Correo reenviado al dueño\n");
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

export default defineCommand({
  meta: { name: "transfers", description: "Traer un dominio de otro registrador: requisitos, DNS y aprobación" },
  subCommands: { check, dns, "set-dns": setDns, "approve-dns": approveDns, "resend-email": resendEmail },
});
