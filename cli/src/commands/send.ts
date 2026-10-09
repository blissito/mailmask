import { readFileSync, statSync } from "node:fs";
import { basename, extname } from "node:path";
import { defineCommand } from "citty";
import type { AttachmentRef, BulkSendInput, SendEmailInput } from "@easybits.cloud/mailmask";
import { requireClient } from "../client.js";
import { confirmOrExit, failFromError, failUsage, printJson } from "../output.js";
import { resolveDomainId } from "../resolve.js";
import { domainArg, jsonArg, yesArg } from "../args.js";

/** Límites del servidor replicados aquí para fallar antes de la red; si cambian allá, moverlos aquí. */
const HTML_MAX_BYTES = 100 * 1024;
const ATTACH_MAX_BYTES = 5 * 1024 * 1024;
const COPIES_MAX = 20;
const IDEMPOTENCY_MAX = 128;
const BULK_KEYS = ["recipients", "subject", "html", "from"];

const CONTENT_TYPES: Record<string, string> = {
  ".pdf": "application/pdf", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
  ".webp": "image/webp", ".txt": "text/plain", ".csv": "text/csv", ".json": "application/json", ".html": "text/html",
  ".zip": "application/zip", ".doc": "application/msword", ".xls": "application/vnd.ms-excel",
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
};

type Opts = { json?: boolean };

const looksLikeEmail = (s: string) => /^[^\s@]+@[^\s@]+$/.test(s);
const toArray = (v: unknown): string[] => (v === undefined || v === "" ? [] : Array.isArray(v) ? v.map(String) : [String(v)]);
/** Un nombre de dominio lleva punto; un id (`dom_…`) no. Sólo con el nombre se puede comparar un `--from` completo. */
const isDomainName = (d: string) => d.includes(".");

function readFileOrFail(path: string, what: string, opts: Opts): Buffer {
  try {
    return readFileSync(path);
  } catch (err) {
    failUsage(`No se pudo leer ${what} "${path}": ${err instanceof Error ? err.message : String(err)}`, opts);
  }
}

/** `@ruta` lee el contenido de un archivo (estilo curl); cualquier otro valor es el contenido mismo. */
function contentOrFile(value: string | undefined, flag: string, opts: Opts): string | undefined {
  if (value === undefined) return undefined;
  if (!value.startsWith("@")) return value;
  return readFileOrFail(value.slice(1), `el archivo de ${flag}`, opts).toString("utf8");
}

/**
 * `--from` es la parte local de un alias (`hola`) o la dirección completa. El SDK sólo entiende la
 * parte local (`from`, nunca `fromLocal`), así que con `@` se recorta SOLO si lo que sigue es el
 * dominio dado por nombre; en cualquier otro caso se rechaza antes de tocar la red.
 */
export function parseFrom(raw: string, domain: string, opts: Opts, flag = "--from"): string {
  const from = raw.trim();
  if (!from) failUsage(`${flag} no puede ir vacío.`, opts);
  const at = from.lastIndexOf("@");
  if (at === -1) return from;
  const local = from.slice(0, at);
  const host = from.slice(at + 1);
  if (!isDomainName(domain)) {
    failUsage(`${flag} "${from}": con el dominio dado como id usa sólo la parte local (p. ej. "${local || "hola"}").`, opts);
  }
  if (host.toLowerCase() !== domain.toLowerCase()) {
    failUsage(`${flag} "${from}" no es de ${domain}: sólo se puede enviar desde un alias de ese dominio.`, opts);
  }
  if (!local) failUsage(`${flag} "${from}" no tiene parte local.`, opts);
  return local;
}

function copies(value: unknown, flag: string, opts: Opts): string[] | undefined {
  const list = toArray(value);
  if (list.length === 0) return undefined;
  if (list.length > COPIES_MAX) failUsage(`${flag} admite máximo ${COPIES_MAX} correos (llegaron ${list.length}).`, opts);
  for (const a of list) if (!looksLikeEmail(a)) failUsage(`${flag}: "${a}" no parece un correo.`, opts);
  return list;
}

interface LocalAttachment {
  filename: string;
  contentType: string;
  data: Uint8Array;
}

function readAttachments(paths: string[], opts: Opts): LocalAttachment[] {
  return paths.map((path) => {
    let size: number;
    try {
      size = statSync(path).size;
    } catch (err) {
      failUsage(`No se pudo leer el adjunto "${path}": ${err instanceof Error ? err.message : String(err)}`, opts);
    }
    if (size > ATTACH_MAX_BYTES) failUsage(`El adjunto "${path}" pesa ${Math.ceil(size / 1024)} KB; el máximo es 5 MB.`, opts);
    const data = readFileOrFail(path, "el adjunto", opts);
    return {
      filename: basename(path),
      contentType: CONTENT_TYPES[extname(path).toLowerCase()] ?? "application/octet-stream",
      data: new Uint8Array(data),
    };
  });
}

const email = defineCommand({
  meta: { name: "email", description: "Envía un correo desde un alias activo del dominio (sale a terceros: pide confirmación)" },
  args: {
    ...domainArg,
    to: { type: "string" as const, description: "Destinatario" },
    subject: { type: "string" as const, description: "Asunto" },
    from: { type: "string" as const, description: "Alias remitente: parte local (hola) o dirección completa del dominio. Sin él sale desde noreply@" },
    "from-name": { type: "string" as const, description: "Nombre visible del remitente" },
    "reply-to": { type: "string" as const, description: "Dirección de respuesta" },
    cc: { type: "string" as const, description: "Copia visible (repetible, máx. 20)" },
    bcc: { type: "string" as const, description: "Copia oculta (repetible, máx. 20)" },
    text: { type: "string" as const, description: "Cuerpo en texto plano, o @archivo para leerlo de un archivo" },
    html: { type: "string" as const, description: "Cuerpo HTML (máx. 100 KB), o @archivo" },
    markdown: { type: "string" as const, description: "Cuerpo en Markdown, o @archivo" },
    attach: { type: "string" as const, description: "Archivo adjunto (repetible, máx. 5 MB cada uno)" },
    "idempotency-key": { type: "string" as const, description: "Clave para que un reintento no vuelva a enviar (máx. 128 caracteres, vale 24 h)" },
    ...yesArg,
    ...jsonArg,
  },
  async run({ args }) {
    const opts = { json: args.json };
    // 1) Validar todo y leer archivos locales: nada de esto toca la red.
    if (!args.to) failUsage("Falta --to.", opts);
    if (!looksLikeEmail(args.to)) failUsage(`--to: "${args.to}" no parece un correo.`, opts);
    if (!args.subject) failUsage("Falta --subject.", opts);
    const body = contentOrFile(args.text, "--text", opts);
    const html = contentOrFile(args.html, "--html", opts);
    const markdown = contentOrFile(args.markdown, "--markdown", opts);
    if (!body && !html && !markdown) failUsage("Falta el cuerpo: usa --text, --html o --markdown (o @archivo).", opts);
    if (html && Buffer.byteLength(html) > HTML_MAX_BYTES) failUsage("El HTML pesa más de 100 KB.", opts);
    const key = args["idempotency-key"];
    if (key !== undefined && (key === "" || key.length > IDEMPOTENCY_MAX)) {
      failUsage(`--idempotency-key debe tener entre 1 y ${IDEMPOTENCY_MAX} caracteres.`, opts);
    }
    const cc = copies(args.cc, "--cc", opts);
    const bcc = copies(args.bcc, "--bcc", opts);
    const replyTo = args["reply-to"];
    if (replyTo && !looksLikeEmail(replyTo)) failUsage(`--reply-to: "${replyTo}" no parece un correo.`, opts);
    const from = args.from === undefined ? undefined : parseFrom(args.from, args.domain, opts);
    const files = readAttachments(toArray(args.attach), opts);

    if (from === undefined) {
      const sender = isDomainName(args.domain) ? `noreply@${args.domain}` : "noreply@ de ese dominio";
      process.stderr.write(`⚠ Sin --from: el correo saldrá desde ${sender}.\n`);
    }

    // 2) Confirmar ANTES de resolver el dominio o subir nada: sin TTY ni --yes no se toca el SDK.
    const lines = [`¿Enviar "${args.subject}" a ${args.to}`];
    if (cc) lines.push(`cc: ${cc.join(", ")}`);
    if (bcc) lines.push(`bcc: ${bcc.join(", ")}`);
    if (files.length) lines.push(`${files.length} adjunto(s): ${files.map((f) => f.filename).join(", ")}`);
    await confirmOrExit(`${lines.join("; ")}? Un correo enviado no se puede deshacer.`, { yes: args.yes, json: args.json });

    // 3) Resolver, subir adjuntos y enviar.
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, opts);
    try {
      const attachments: AttachmentRef[] = [];
      for (const f of files) {
        const up = await client.attachments.upload(id, f);
        attachments.push({ key: up.key, filename: up.filename ?? f.filename, contentType: f.contentType });
      }
      const input: SendEmailInput = { to: args.to, subject: args.subject };
      if (body) input.body = body;
      if (html) input.html = html;
      if (markdown) input.markdown = markdown;
      if (from) input.from = from;
      if (args["from-name"]) input.fromName = args["from-name"];
      if (replyTo) input.replyTo = replyTo;
      if (cc) input.cc = cc;
      if (bcc) input.bcc = bcc;
      if (attachments.length) input.attachments = attachments;
      const res = await client.send.send(id, input, key ? { idempotencyKey: key } : undefined);
      if (args.json) return printJson(res);
      process.stdout.write(`✓ Enviado a ${args.to} (id ${res.messageId})\n`);
    } catch (err) {
      failFromError(err, opts);
    }
  },
});

/** Valida `send bulk` contra EXACTAMENTE lo que admite `BulkSendInput`; cualquier otra llave es error. */
function parseBulk(path: string, domain: string, opts: Opts): BulkSendInput {
  const text = readFileOrFail(path, "el archivo", opts).toString("utf8");
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch (err) {
    failUsage(`"${path}" no es JSON válido: ${err instanceof Error ? err.message : String(err)}`, opts);
  }
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    failUsage('El JSON debe ser un objeto { "recipients": [...], "subject": "...", "html": "...", "from"?: "..." }.', opts);
  }
  const obj = data as Record<string, unknown>;
  const extra = Object.keys(obj).filter((k) => !BULK_KEYS.includes(k));
  if (extra.length) {
    failUsage(`Llaves no soportadas en el envío masivo: ${extra.join(", ")}. Sólo se admiten ${BULK_KEYS.join(", ")}.`, opts);
  }
  const { recipients, subject, html, from } = obj;
  if (!Array.isArray(recipients) || recipients.length === 0) failUsage('"recipients" debe ser una lista no vacía de correos.', opts);
  const bad = recipients.find((r) => typeof r !== "string" || !looksLikeEmail(r));
  if (bad !== undefined) failUsage(`"recipients" tiene un valor que no es un correo: ${JSON.stringify(bad)}.`, opts);
  if (typeof subject !== "string" || !subject.trim()) failUsage('"subject" debe ser un texto no vacío.', opts);
  if (typeof html !== "string" || !html.trim()) failUsage('"html" debe ser un texto no vacío.', opts);
  if (Buffer.byteLength(html) > HTML_MAX_BYTES) failUsage('"html" pesa más de 100 KB.', opts);
  const input: BulkSendInput = { recipients: recipients as string[], subject, html };
  if (from !== undefined) {
    if (typeof from !== "string") failUsage('"from" debe ser un texto.', opts);
    input.from = parseFrom(from, domain, opts, '"from"');
  }
  return input;
}

const bulk = defineCommand({
  meta: { name: "bulk", description: "Lanza un envío masivo desde un JSON { recipients, subject, html, from? } (pide confirmación)" },
  args: {
    ...domainArg,
    file: { type: "positional" as const, description: "Archivo .json con recipients, subject, html y from opcional" },
    ...yesArg,
    ...jsonArg,
  },
  async run({ args }) {
    const opts = { json: args.json };
    const input = parseBulk(args.file, args.domain, opts);
    if (input.from === undefined) {
      const sender = isDomainName(args.domain) ? `noreply@${args.domain}` : "noreply@ de ese dominio";
      process.stderr.write(`⚠ Sin "from": el envío saldrá desde ${sender}.\n`);
    }
    await confirmOrExit(
      `¿Enviar "${input.subject}" a ${input.recipients.length} destinatario(s)? Un correo enviado no se puede deshacer.`,
      { yes: args.yes, json: args.json },
    );
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, opts);
    try {
      const res = await client.send.bulkSend(id, input);
      if (args.json) return printJson(res);
      process.stdout.write(`✓ Envío masivo en cola: ${res.jobId}\nVer avance: mailmask send status ${args.domain} ${res.jobId}\n`);
    } catch (err) {
      failFromError(err, opts);
    }
  },
});

const status = defineCommand({
  meta: { name: "status", description: "Muestra el avance de un envío masivo" },
  args: {
    ...domainArg,
    jobId: { type: "positional" as const, description: "Id del envío masivo (lo imprime send bulk)" },
    ...jsonArg,
  },
  async run({ args }) {
    const opts = { json: args.json };
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, opts);
    try {
      const job = await client.send.bulkStatus(id, args.jobId);
      if (args.json) return printJson(job);
      process.stdout.write(
        `Envío ${job.id}: ${job.status}\n` +
          `  enviados ${job.sent} · fallidos ${job.failed} · suprimidos ${job.skippedSuppressed} · de ${job.totalRecipients}\n`,
      );
      if (job.lastError) process.stdout.write(`  último error: ${job.lastError}\n`);
    } catch (err) {
      failFromError(err, opts);
    }
  },
});

export default defineCommand({
  meta: { name: "send", description: "Envía correo desde un dominio: uno solo, masivo, o consulta el avance" },
  subCommands: { email, bulk, status },
});
