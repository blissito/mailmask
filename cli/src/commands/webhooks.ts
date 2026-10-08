import { defineCommand } from "citty";
import type { UpdateWebhookInput, Webhook, WebhookEvent } from "@easybits.cloud/mailmask";
import { requireClient } from "../client.js";
import { confirmOrExit, failFromError, failUsage, printJson } from "../output.js";
import { resolveDomainId } from "../resolve.js";
import { domainArg, jsonArg, WEBHOOK_EVENTS, yesArg } from "../args.js";

const idArgs = {
  ...domainArg,
  id: { type: "positional" as const, description: "Id del webhook (lo muestra `webhooks list`)" },
};
const eventsArg = { type: "string" as const, description: `Eventos separados por coma: ${WEBHOOK_EVENTS.join(", ")}` };

/** Valida `--events` ANTES de tocar la red: un evento mal escrito no debe costar ni una llamada. */
function parseEvents(raw: string, json?: boolean): WebhookEvent[] {
  const events = raw.split(",").map((e) => e.trim()).filter(Boolean);
  const invalid = events.filter((e) => !WEBHOOK_EVENTS.includes(e as WebhookEvent));
  if (events.length === 0 || invalid.length > 0) {
    failUsage(
      invalid.length > 0
        ? `Evento no válido: ${invalid.join(", ")}. Los válidos son: ${WEBHOOK_EVENTS.join(", ")}.`
        : `Pasa al menos un evento en --events: ${WEBHOOK_EVENTS.join(", ")}.`,
      { json },
    );
  }
  return events as WebhookEvent[];
}

/** El secreto sólo sale de `create`; si la API lo devolviera en otra ruta, aquí se tira. */
function withoutSecret<T extends object>(value: T): Omit<T, "secret"> {
  const { secret: _secret, ...rest } = value as T & { secret?: unknown };
  return rest;
}

function line(w: Webhook): string {
  return `${w.id}  ${w.url}  [${w.events.join(", ")}]  (${w.enabled ? "activo" : "desactivado"})\n`;
}

const list = defineCommand({
  meta: { name: "list", description: "Lista los webhooks de un dominio" },
  args: { ...domainArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const hooks = (await client.webhooks.list(id)).map(withoutSecret) as Webhook[];
      if (args.json) return printJson(hooks);
      if (hooks.length === 0) {
        process.stdout.write('Sin webhooks. Crea uno con "mailmask webhooks create <dominio> <url> --events email.received".\n');
        return;
      }
      for (const w of hooks) process.stdout.write(line(w));
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const create = defineCommand({
  meta: { name: "create", description: "Crea un webhook (el secreto de firma sale completo sólo aquí)" },
  args: {
    ...domainArg,
    url: { type: "positional", description: "URL https pública que recibirá los eventos" },
    events: { ...eventsArg, description: `Obligatorio. ${eventsArg.description}` },
    ...jsonArg,
  },
  async run({ args }) {
    const events = parseEvents(args.events ?? "", args.json);
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const created = await client.webhooks.create(id, { url: args.url, events });
      if (args.json) return printJson(created);
      process.stdout.write(`✓ Webhook creado: ${created.id}  ${created.url}  [${created.events.join(", ")}]\n`);
      process.stdout.write(`  Secreto de firma: ${created.secret}\n`);
      process.stdout.write("  Guárdalo ahora: no se vuelve a mostrar y el SDK no permite rotarlo (borra el webhook y crea otro).\n");
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const update = defineCommand({
  meta: { name: "update", description: "Cambia la URL, los eventos o el estado (activo/desactivado) de un webhook" },
  args: {
    ...idArgs,
    url: { type: "string", description: "URL https pública nueva" },
    events: eventsArg,
    enable: { type: "boolean", description: "Activa el webhook" },
    disable: { type: "boolean", description: "Desactiva el webhook" },
    ...jsonArg,
  },
  async run({ args }) {
    if (args.enable && args.disable) failUsage("--enable y --disable son mutuamente excluyentes.", { json: args.json });
    const input: UpdateWebhookInput = {};
    if (args.url) input.url = args.url;
    if (args.events !== undefined) input.events = parseEvents(args.events, args.json);
    if (args.enable) input.enabled = true;
    if (args.disable) input.enabled = false;
    if (Object.keys(input).length === 0) {
      failUsage("Nada que actualizar: pasa --url, --events, --enable o --disable.", { json: args.json });
    }
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const updated = withoutSecret(await client.webhooks.update(id, args.id, input)) as Webhook;
      if (args.json) return printJson(updated);
      process.stdout.write(`✓ Webhook actualizado: ${line(updated)}`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const del = defineCommand({
  meta: { name: "delete", description: "Borra un webhook" },
  args: { ...idArgs, ...yesArg, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    await confirmOrExit(`¿Borrar el webhook "${args.id}"? Es irreversible.`, { yes: args.yes, json: args.json });
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      await client.webhooks.delete(id, args.id);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
    if (args.json) return printJson({ ok: true });
    process.stdout.write(`✓ Webhook borrado: ${args.id}\n`);
  },
});

const test = defineCommand({
  meta: { name: "test", description: "Manda un evento de prueba (ping) al webhook" },
  args: { ...idArgs, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const result = await client.webhooks.test(id, args.id);
      if (args.json) return printJson(withoutSecret(result));
      process.stdout.write(`✓ Ping enviado (entrega ${result.deliveryId}). Revísalo con "mailmask webhooks deliveries ${args.domain} ${args.id}".\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const deliveries = defineCommand({
  meta: { name: "deliveries", description: "Lista las entregas recientes de un webhook y su resultado" },
  args: { ...idArgs, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const items = (await client.webhooks.deliveries(id, args.id)).map(withoutSecret);
      if (args.json) return printJson(items);
      if (items.length === 0) {
        process.stdout.write("Sin entregas todavía.\n");
        return;
      }
      for (const d of items) {
        const detalle = d.lastError ? `  ${d.lastError}` : d.lastStatusCode ? `  HTTP ${d.lastStatusCode}` : "";
        process.stdout.write(`${d.id}  ${d.event}  ${d.status}  intentos: ${d.attempts}  ${d.createdAt}${detalle}\n`);
      }
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

export default defineCommand({
  meta: { name: "webhooks", description: "Administra los webhooks de un dominio" },
  subCommands: { list, create, update, delete: del, test, deliveries },
});
