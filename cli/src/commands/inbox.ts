import { writeFile } from "node:fs/promises";
import { defineCommand } from "citty";
import { MailMaskError } from "@easybits.cloud/mailmask";
import type { InboxConversationDetail, InboxListOptions, InboxMessage, InboxUpdateInput } from "@easybits.cloud/mailmask";
import { requireClient } from "../client.js";
import { confirmOrExit, failFromError, failUsage, printJson } from "../output.js";
import { resolveDomainId } from "../resolve.js";
import { INBOX_LIST_STATUSES, INBOX_STATUSES, INBOX_PRIORITIES, domainArg, jsonArg, yesArg } from "../args.js";

const MAX_DELETE_IDS = 200;

const conversationArgs = {
  ...domainArg,
  conversation: { type: "positional" as const, description: "Id de la conversación" },
};

/** `a, b ,c` → ["a","b","c"]; vacío o ausente → undefined. */
function csv(value: unknown): string[] | undefined {
  if (typeof value !== "string") return undefined;
  const items = value.split(",").map((s) => s.trim()).filter(Boolean);
  return items.length ? items : undefined;
}

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };

/** HTML → texto: quita etiquetas (y el contenido de style/script) y decodifica las entidades básicas. */
function htmlATexto(html: string): string {
  return html
    .replace(/<(style|script)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, "")
    .replace(/<br\s*\/?>|<\/(p|div|li|tr|h[1-6])\s*>/gi, "\n")
    .replace(/<[^>]*>/g, "")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&([a-z]+);/gi, (m, name) => ENTITIES[name.toLowerCase()] ?? m)
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

/** Texto de un mensaje: `body`, si no `bodyDegraded` (el original ya no está) y, si sólo hay HTML, ese HTML sin etiquetas. */
export function textoDeMensaje(m: Pick<InboxMessage, "body" | "bodyDegraded" | "html">): string {
  if (m.body?.trim()) return m.body;
  if (m.bodyDegraded?.trim()) return m.bodyDegraded;
  return m.html ? htmlATexto(m.html) : "";
}

const list = defineCommand({
  meta: { name: "list", description: "Lista las conversaciones de la Bandeja (una fila cada una)" },
  args: {
    ...domainArg,
    status: { type: "string", description: `Estado: ${INBOX_LIST_STATUSES.join(", ")}` },
    alias: { type: "string", description: "Sólo una máscara (dirección completa, ventas@acme.com)" },
    assigned: { type: "string", description: "Sólo las asignadas a esta persona" },
    q: { type: "string", description: "Busca en asunto, remitente y cuerpo (sin paginación, tope 50)" },
    limit: { type: "string", description: "Máximo de filas (hasta 100)" },
    cursor: { type: "string", description: "nextCursor de la página anterior" },
    ...jsonArg,
  },
  async run({ args }) {
    if (args.status && !(INBOX_LIST_STATUSES as string[]).includes(args.status)) {
      failUsage(`--status debe ser uno de: ${INBOX_LIST_STATUSES.join(", ")}.`, { json: args.json });
    }
    if (args.limit !== undefined && !/^\d+$/.test(args.limit)) failUsage("--limit debe ser un entero.", { json: args.json });
    const opts: InboxListOptions = {};
    if (args.status) opts.status = args.status as InboxListOptions["status"];
    if (args.alias) opts.to = args.alias;
    if (args.assigned) opts.assignedTo = args.assigned;
    if (args.q) opts.q = args.q;
    if (args.limit) opts.limit = Number(args.limit);
    if (args.cursor) opts.cursor = args.cursor;
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const page = await client.inbox.list(id, opts);
      if (args.json) return printJson(page);
      if (page.items.length === 0) {
        process.stdout.write("Sin conversaciones.\n");
        return;
      }
      for (const c of page.items) {
        const marca = c.unread ? "*" : " ";
        process.stdout.write(`${marca} ${c.id}  ${c.status}  ${c.to}  ${c.from}  ${c.subject}  ${c.lastMessageAt}\n`);
      }
      if (page.nextCursor) process.stdout.write(`Más: --cursor ${page.nextCursor}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

function imprimirConversacion(c: InboxConversationDetail): void {
  const out = process.stdout;
  out.write(`${c.subject}\n${c.from} ⇄ ${c.to}  [${c.status}${c.assignedTo ? `, asignada a ${c.assignedTo}` : ""}]\n`);
  if (c.hasMore) out.write(`(${c.messages.length} de ${c.totalMessages} mensajes; los anteriores con --before <id del primero>)\n`);
  for (const m of c.messages) {
    out.write(`\n── ${m.id}  ${m.direction === "inbound" ? "←" : "→"} ${m.from}  ${m.createdAt}\n${textoDeMensaje(m)}\n`);
    for (const a of m.attachments ?? []) out.write(`   adjunto ${a.index}: ${a.filename} (${a.contentType}, ${a.size} bytes)\n`);
  }
  for (const n of c.notes) out.write(`\n── nota de ${n.author}  ${n.createdAt}\n${n.body}\n`);
}

const get = defineCommand({
  meta: { name: "get", description: "Muestra una conversación en texto (abrirla la marca leída en el servidor)" },
  args: {
    ...conversationArgs,
    before: { type: "string", description: "Id de mensaje: trae los anteriores a ése" },
    ...jsonArg,
  },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const c = await client.inbox.get(id, args.conversation, args.before ? { before: args.before } : undefined);
      if (args.json) return printJson({ ...c, messages: c.messages.map((m) => ({ ...m, text: textoDeMensaje(m) })) });
      imprimirConversacion(c);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const reply = defineCommand({
  meta: { name: "reply", description: "Responde en el hilo desde la máscara del hilo (sale al contacto)" },
  args: {
    ...conversationArgs,
    markdown: { type: "string", required: true, description: "Cuerpo de la respuesta en markdown" },
    cc: { type: "string", description: "Copia, separados por coma" },
    bcc: { type: "string", description: "Copia oculta, separados por coma" },
    // citty entiende `--no-quote` como `quote=false`; por eso el arg se llama `quote`.
    quote: { type: "boolean", default: true, description: "Cita el último mensaje recibido (--no-quote para no citar)" },
    ...yesArg,
    ...jsonArg,
  },
  async run({ args }) {
    const { client } = await requireClient();
    await confirmOrExit(`¿Enviar esta respuesta al contacto de la conversación ${args.conversation}?`, { yes: args.yes, json: args.json });
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    const input: Parameters<typeof client.inbox.reply>[2] = { markdown: args.markdown };
    const cc = csv(args.cc);
    const bcc = csv(args.bcc);
    if (cc) input.cc = cc;
    if (bcc) input.bcc = bcc;
    if (args.quote === false) input.quote = false;
    try {
      const res = await client.inbox.reply(id, args.conversation, input);
      if (args.json) return printJson(res);
      process.stdout.write(`✓ Respuesta enviada (mensaje ${res.messageId})\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const compose = defineCommand({
  meta: { name: "compose", description: "Abre un hilo nuevo con un correo desde una máscara (gasta cuota de envío)" },
  args: {
    ...domainArg,
    from: { type: "string", required: true, description: "Máscara del dominio desde la que sale (ventas o ventas@acme.com)" },
    to: { type: "string", required: true, description: "Destinatario" },
    subject: { type: "string", required: true, description: "Asunto" },
    markdown: { type: "string", required: true, description: "Cuerpo en markdown" },
    cc: { type: "string", description: "Copia, separados por coma" },
    bcc: { type: "string", description: "Copia oculta, separados por coma" },
    ...yesArg,
    ...jsonArg,
  },
  async run({ args }) {
    const { client } = await requireClient();
    await confirmOrExit(`¿Enviar "${args.subject}" a ${args.to} desde ${args.from}?`, { yes: args.yes, json: args.json });
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    const input: Parameters<typeof client.inbox.compose>[1] = { fromAlias: args.from, to: args.to, subject: args.subject, markdown: args.markdown };
    const cc = csv(args.cc);
    const bcc = csv(args.bcc);
    if (cc) input.cc = cc;
    if (bcc) input.bcc = bcc;
    try {
      const res = await client.inbox.compose(id, input);
      if (args.json) return printJson(res);
      process.stdout.write(`✓ Enviado. Conversación ${res.conversationId} (mensaje ${res.messageId})\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const update = defineCommand({
  meta: { name: "update", description: "Cambia estado, posposición, etiquetas o prioridad de una conversación" },
  args: {
    ...conversationArgs,
    status: { type: "string", description: `Estado: ${INBOX_STATUSES.join(", ")}` },
    "snooze-until": { type: "string", description: "Fecha ISO futura (a menos de 90 días); obligatoria con --status snoozed" },
    tags: { type: "string", description: "Etiquetas separadas por coma (reemplazan a las actuales; vacío las quita)" },
    priority: { type: "string", description: `Prioridad: ${INBOX_PRIORITIES.join(", ")}` },
    ...jsonArg,
  },
  async run({ args }) {
    const json = args.json;
    if (args.status && !(INBOX_STATUSES as string[]).includes(args.status)) failUsage(`--status debe ser uno de: ${INBOX_STATUSES.join(", ")}.`, { json });
    if (args.priority && !(INBOX_PRIORITIES as string[]).includes(args.priority)) failUsage(`--priority debe ser uno de: ${INBOX_PRIORITIES.join(", ")}.`, { json });
    if (args.status === "snoozed" && !args["snooze-until"]) failUsage('--status snoozed necesita --snooze-until <fecha ISO>.', { json });
    const input: InboxUpdateInput = {};
    if (args.status) input.status = args.status as InboxUpdateInput["status"];
    if (args["snooze-until"]) input.snoozedUntil = args["snooze-until"];
    if (args.tags !== undefined) input.tags = csv(args.tags) ?? [];
    if (args.priority) input.priority = args.priority as InboxUpdateInput["priority"];
    if (Object.keys(input).length === 0) failUsage("Nada que cambiar: pasa --status, --snooze-until, --tags o --priority.", { json });
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json });
    try {
      const c = await client.inbox.update(id, args.conversation, input);
      if (json) return printJson(c);
      process.stdout.write(`✓ Actualizada: ${c.id} (${c.status}, prioridad ${c.priority})\n`);
    } catch (err) {
      failFromError(err, { json });
    }
  },
});

const read = defineCommand({
  meta: { name: "read", description: "Marca una conversación como leída" },
  args: { ...conversationArgs, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const res = await client.inbox.markRead(id, args.conversation);
      if (args.json) return printJson(res);
      process.stdout.write(`✓ Leída. Sin leer: ${res.unreadCount}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const assign = defineCommand({
  meta: { name: "assign", description: "Asigna una conversación a una persona del equipo; sin usuario la deja sin asignar" },
  args: {
    ...conversationArgs,
    user: { type: "positional", required: false, description: "Correo o id de la persona; vacío = desasignar" },
    ...jsonArg,
  },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const c = await client.inbox.assign(id, args.conversation, args.user || undefined);
      if (args.json) return printJson(c);
      process.stdout.write(c.assignedTo ? `✓ Asignada a ${c.assignedTo}\n` : "✓ Sin asignar\n");
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const note = defineCommand({
  meta: { name: "note", description: "Agrega una nota interna (la ve el equipo, nunca el contacto)" },
  args: {
    ...conversationArgs,
    text: { type: "positional", description: "Texto de la nota" },
    ...jsonArg,
  },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const n = await client.inbox.addNote(id, args.conversation, args.text);
      if (args.json) return printJson(n);
      process.stdout.write(`✓ Nota agregada (${n.id})\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const del = defineCommand({
  meta: { name: "delete", description: "Manda de 1 a 200 conversaciones a la papelera (se pueden restaurar)" },
  args: {
    ...domainArg,
    id: { type: "positional", description: "Id(s) de conversación; acepta varios" },
    ...yesArg,
    ...jsonArg,
  },
  async run({ args }) {
    // citty no tiene positional "rest": igual que `dns upsert`, los ids salen de `args._` (sin tocar `rawArgs`).
    const ids = args._.slice(1);
    if (ids.length < 1 || ids.length > MAX_DELETE_IDS) {
      failUsage(`Pasa de 1 a ${MAX_DELETE_IDS} ids de conversación (recibí ${ids.length}).`, { json: args.json });
    }
    const { client } = await requireClient();
    await confirmOrExit(`¿Mandar ${ids.length} conversación(es) a la papelera?`, { yes: args.yes, json: args.json });
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const res = await client.inbox.delete(id, ids);
      if (args.json) return printJson(res);
      process.stdout.write(`✓ ${res.deleted} en la papelera (se restauran con "mailmask inbox restore")\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const restore = defineCommand({
  meta: { name: "restore", description: "Saca una conversación de la papelera" },
  args: { ...conversationArgs, ...jsonArg },
  async run({ args }) {
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const res = await client.inbox.restore(id, args.conversation);
      if (args.json) return printJson(res);
      process.stdout.write(`✓ Restaurada: ${args.conversation}\n`);
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const metrics = defineCommand({
  meta: { name: "metrics", description: "Métricas de la Bandeja (JSON)" },
  args: {
    ...domainArg,
    days: { type: "string", description: "Ventana en días" },
    ...jsonArg,
  },
  async run({ args }) {
    if (args.days !== undefined && !/^[1-9]\d*$/.test(args.days)) failUsage("--days debe ser un entero positivo.", { json: args.json });
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      printJson(await client.inbox.metrics(id, args.days ? { days: Number(args.days) } : undefined));
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

const attachment = defineCommand({
  meta: { name: "attachment", description: "Descarga un adjunto de un mensaje, a un archivo o a stdout" },
  args: {
    ...conversationArgs,
    message: { type: "positional", description: "Id del mensaje" },
    index: { type: "positional", description: "Posición del adjunto en el mensaje (0, 1, …)" },
    output: { type: "string", alias: "o", description: "Ruta del archivo a escribir; sin esto, sale por stdout" },
    ...jsonArg,
  },
  async run({ args }) {
    if (!/^\d+$/.test(String(args.index))) failUsage("<index> debe ser un entero ≥ 0.", { json: args.json });
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const res = await client.inbox.attachment(id, args.conversation, args.message, Number(args.index));
      // El archivo se abre DESPUÉS de saber que la respuesta es buena: un 404 no deja un archivo vacío.
      if (!res.ok) throw new MailMaskError(res.status, res.statusText || "No se pudo descargar el adjunto");
      const buffer = Buffer.from(await res.arrayBuffer());
      if (args.output) {
        await writeFile(args.output, buffer);
        process.stderr.write(`✓ Guardado en ${args.output}\n`);
      } else {
        process.stdout.write(buffer);
      }
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});

export default defineCommand({
  meta: { name: "inbox", description: "Atiende la Bandeja compartida de un dominio: conversaciones, respuestas y notas" },
  subCommands: { list, get, reply, compose, update, read, assign, note, delete: del, restore, metrics, attachment },
});
