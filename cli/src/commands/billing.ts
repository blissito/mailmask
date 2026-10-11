import { defineCommand } from "citty";
import { requireClient } from "../client.js";
import { confirmOrExit, failFromError, failUsage, formatMxn, printJson } from "../output.js";
import { resolveDomainId } from "../resolve.js";
import { BILLING_KINDS, BILLING_PERIODS, domainArg, jsonArg, yesArg } from "../args.js";

const status = defineCommand({
  meta: { name: "status", description: "Tu suscripción y su estado" },
  args: jsonArg,
  async run({ args }) {
    const { client } = await requireClient();
    try {
      const result = await client.billing.status();
      if (args.json) return printJson(result);
      const s = result.subscription;
      process.stdout.write(`Plan: ${s.plan}  estado: ${s.status}${s.currentPeriodEnd ? `  vigente hasta: ${s.currentPeriodEnd}` : ""}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const addons = defineCommand({
  meta: { name: "addons", description: "Add-ons disponibles y los que tienes" },
  args: jsonArg,
  async run({ args }) {
    const { client } = await requireClient();
    try {
      const result = await client.billing.addons();
      if (args.json) return printJson(result);
      if (result.mine.length === 0) {
        process.stdout.write("Sin add-ons.\n");
        return;
      }
      for (const a of result.mine) {
        process.stdout.write(`${a.id}  ${a.kind}  ${a.status}  ${formatMxn(a.priceCents)}${a.domainId ? `  dominio: ${a.domainId}` : ""}${a.currentPeriodEnd ? `  hasta: ${a.currentPeriodEnd}` : ""}\n`);
      }
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const orders = defineCommand({
  meta: { name: "orders", description: "Historial de cobros, cortesías y cancelaciones (más reciente primero)" },
  args: {
    limit: { type: "string", description: "Cuántos traer (entero positivo)" },
    before: { type: "string", description: "Cursor de la página anterior (nextCursor)" },
    ...jsonArg,
  },
  async run({ args }) {
    let limit: number | undefined;
    if (args.limit !== undefined) {
      limit = Number(args.limit);
      if (!Number.isInteger(limit) || limit < 1) failUsage(`--limit debe ser un entero positivo, recibí "${args.limit}".`, { json: args.json });
    }
    const { client } = await requireClient();
    try {
      const page = await client.billing.orders({ limit, before: args.before });
      if (args.json) return printJson(page);
      if (page.orders.length === 0) {
        process.stdout.write("Sin cobros.\n");
        return;
      }
      for (const o of page.orders) process.stdout.write(`${o.number}  ${o.date}  ${formatMxn(o.amountCents)}  ${o.concept}\n`);
      if (page.nextCursor) process.stdout.write(`Siguiente página: --before ${page.nextCursor}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const checkout = defineCommand({
  meta: { name: "checkout", description: "Imprime la liga de pago de un add-on del dominio (no cobra: tú la abres y pagas)" },
  args: {
    ...domainArg,
    kind: { type: "string", description: `Qué comprar: ${BILLING_KINDS.join(" | ")} (por omisión domain = activar el dominio)` },
    period: { type: "string", description: `Periodo: ${BILLING_PERIODS.join(" | ")}` },
    "payer-email": { type: "string", description: "Correo de quien paga, si no es el de la cuenta" },
    ...jsonArg,
  },
  async run({ args }) {
    if (args.kind !== undefined && !(BILLING_KINDS as readonly string[]).includes(args.kind)) {
      failUsage(`--kind no válido: "${args.kind}". Usa ${BILLING_KINDS.join(", ")}.`, { json: args.json });
    }
    if (args.period !== undefined && !(BILLING_PERIODS as readonly string[]).includes(args.period)) {
      failUsage(`--period no válido: "${args.period}". Usa ${BILLING_PERIODS.join(" o ")}.`, { json: args.json });
    }
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const link = await client.billing.checkout(id, args.kind as (typeof BILLING_KINDS)[number] | undefined, {
        payerEmail: args["payer-email"],
        period: args.period as (typeof BILLING_PERIODS)[number] | undefined,
      });
      if (args.json) return printJson(link);
      process.stdout.write(`Abre esta liga para pagar (el CLI no cobra ni espera el pago):\n${link.init_point}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const cancelAddon = defineCommand({
  meta: { name: "cancel-addon", description: "Cancela la suscripción de un add-on; el cupo sigue hasta el fin del periodo pagado" },
  args: { addon: { type: "positional", description: "Id del add-on (lo muestra billing addons)" }, ...yesArg, ...jsonArg },
  async run({ args }) {
    await confirmOrExit(`¿Cancelar el add-on ${args.addon}? Dejará de renovarse.`, { yes: args.yes, json: args.json });
    const { client } = await requireClient();
    try {
      const result = await client.billing.cancelAddon(args.addon);
      if (args.json) return printJson(result);
      process.stdout.write(`✓ Add-on cancelado${result.activeUntil ? `; sigue activo hasta ${result.activeUntil}` : ""}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

export default defineCommand({
  meta: { name: "billing", description: "Suscripción, add-ons y cobros de tu cuenta" },
  subCommands: { status, addons, orders, checkout, "cancel-addon": cancelAddon },
});
