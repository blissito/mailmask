import { defineCommand } from "citty";
import { requireClient } from "../client.js";
import { confirmOrExit, failFromError, formatMxn, printJson } from "../output.js";
import { resolveRegistrationId } from "../resolve.js";
import { jsonArg, registrationArg, yesArg } from "../args.js";

const payerArg = { "payer-email": { type: "string" as const, description: "Correo de quien paga, si no es el de la cuenta" } };

/** La API devuelve una pista del código EPP en `transferAuthCodeHint`; el CLI nunca la muestra: el código llega por correo al dueño. */
function withoutAuthHint<T extends { transferAuthCodeHint?: unknown }>(registration: T): Omit<T, "transferAuthCodeHint"> {
  const { transferAuthCodeHint: _hint, ...rest } = registration;
  return rest;
}

const search = defineCommand({
  meta: { name: "search", description: "Revisa si un dominio está disponible y cuánto cuesta al año" },
  args: { domain: { type: "positional", description: "Dominio a buscar (acme.com)" }, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    try {
      const result = await client.registrations.search(args.domain);
      if (args.json) return printJson(result);
      process.stdout.write(`${result.domain}  ${result.available ? `disponible  ${formatMxn(result.price)}/año` : "no disponible"}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const tlds = defineCommand({
  meta: { name: "tlds", description: "Precios por extensión (.com, .mx, ...)" },
  args: jsonArg,
  async run({ args }) {
    const { client } = await requireClient();
    try {
      const prices = await client.registrations.tlds();
      if (args.json) return printJson(prices);
      for (const t of prices) {
        process.stdout.write(`${t.tld}  registro ${formatMxn(t.price)}  renovación ${formatMxn(t.renewPrice)}  traslado ${formatMxn(t.transferPrice)}\n`);
      }
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const register = defineCommand({
  meta: { name: "register", description: "Crea el registro pendiente e imprime la liga de pago (no cobra: se registra al pagar)" },
  args: { domain: { type: "positional", description: "Dominio a registrar (acme.com)" }, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    try {
      const created = await client.registrations.register(args.domain);
      if (args.json) return printJson(created);
      process.stdout.write(`Abre esta liga para pagar; el dominio se registra al pagar (el CLI no cobra ni espera el pago):\n${created.initPoint}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const list = defineCommand({
  meta: { name: "list", description: "Tus dominios registrados o trasladados" },
  args: jsonArg,
  async run({ args }) {
    const { client } = await requireClient();
    try {
      const items = (await client.registrations.list()).map(withoutAuthHint);
      if (args.json) return printJson(items);
      if (items.length === 0) {
        process.stdout.write("Sin dominios registrados. Busca uno con \"mailmask registrations search <dominio>\".\n");
        return;
      }
      for (const r of items) {
        process.stdout.write(`${r.domainName}  (${r.id})  ${r.kind}  ${r.status}  vence: ${r.expiresAt ?? "—"}  renovación: ${r.renewalStatus}\n`);
      }
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const renewal = defineCommand({
  meta: { name: "renewal", description: "Imprime la liga de pago de la renovación anual (no cobra)" },
  args: { ...registrationArg, ...payerArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveRegistrationId(client, args.registration, { json: args.json });
    try {
      const link = await client.registrations.renewal(id, { payerEmail: args["payer-email"] });
      if (args.json) return printJson(link);
      process.stdout.write(`Abre esta liga para pagar la renovación (el CLI no cobra ni espera el pago):\n${link.init_point}\nPróximo cobro: ${link.nextChargeAt}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const cancelRenewal = defineCommand({
  meta: { name: "cancel-renewal", description: "Deja de cobrar la renovación anual; el dominio sigue vigente hasta su vencimiento" },
  args: { ...registrationArg, ...yesArg, ...jsonArg },
  async run({ args }) {
    await confirmOrExit(`¿Cancelar la renovación de "${args.registration}"? El dominio vencerá si no la reactivas.`, { yes: args.yes, json: args.json });
    const { client } = await requireClient();
    const id = await resolveRegistrationId(client, args.registration, { json: args.json });
    try {
      const result = await client.registrations.cancelRenewal(id);
      if (args.json) return printJson(result);
      process.stdout.write(`✓ ${result.aviso}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const transferOut = defineCommand({
  meta: { name: "transfer-out", description: "Pide el traslado a otro registrador; el código llega por correo al dueño, nunca aquí" },
  args: { ...registrationArg, ...yesArg, ...jsonArg },
  async run({ args }) {
    await confirmOrExit(`¿Pedir el traslado de "${args.registration}" a otro registrador? El código de autorización llegará por correo al dueño.`, { yes: args.yes, json: args.json });
    const { client } = await requireClient();
    const id = await resolveRegistrationId(client, args.registration, { json: args.json });
    try {
      const result = await client.registrations.transferOut(id);
      if (args.json) return printJson({ ok: result.ok, aviso: result.aviso });
      process.stdout.write(`✓ ${result.aviso}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

export default defineCommand({
  meta: { name: "registrations", description: "Registro, renovación y traslado de dominios comprados en MailMask" },
  subCommands: { search, tlds, register, list, renewal, "cancel-renewal": cancelRenewal, "transfer-out": transferOut },
});
