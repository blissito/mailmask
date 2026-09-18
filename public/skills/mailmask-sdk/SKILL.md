---
name: mailmask-sdk
description: Use the official MailMask JavaScript/TypeScript SDK (@easybits.cloud/mailmask on npm) to create masks (aliases), send email from a domain, manage rules, webhooks, suppressions, SMTP credentials and DNS, and to verify webhook signatures in a receiver. Use when writing code that talks to mailmask.studio, when a project imports @easybits.cloud/mailmask, or when the user needs to send or receive email through their own domain from an app.
license: MIT
compatibility: Node 18+, Deno, Bun or Workers (uses fetch and WebCrypto only). Network access to https://www.mailmask.studio.
metadata:
  author: mailmask
  version: "1.0"
---

# MailMask SDK

```bash
npm i @easybits.cloud/mailmask
```

```ts
import { MailMask, MailMaskError } from "@easybits.cloud/mailmask";
const mm = new MailMask({ apiKey: process.env.MAILMASK_API_KEY! });
```

The key (`mk_…`) comes from `/app → API Keys`; keep it in an env var. Everything is typed;
every resource method returns the parsed JSON and throws `MailMaskError` (`status`, `message`
in Spanish, written for the end user) on any non-2xx. 60 requests per minute per key.

## Resources

All take a `domainId` (from `mm.domains.list()`) except `domains` and `apiKeys`.

| Resource | Methods |
|---|---|
| `mm.domains` | `list()`, `get(id)`, `create(domain)` → DNS records to set, `verify(id)`, `health(id)`, `delete(id)` |
| `mm.aliases` | `list(d)`, `create(d, { alias, destinations?, mailbox? })`, `update(d, alias, { enabled?, destinations? })`, `delete(d, alias)`, `createMailbox(d, alias)`, `deleteMailbox(d, alias)`, `resetMailboxPassword(d, alias)` |
| `mm.send` | `send(d, input, { idempotencyKey? })`, `bulkSend(d, { from, recipients, subject, html })`, `bulkStatus(d, jobId)` |
| `mm.attachments` | `upload(d, { filename, contentType, data })` → key to pass in `send({ attachments: [key] })` |
| `mm.rules` | `list`, `create(d, { field, match, value, action, target?, priority? })`, `update`, `delete` |
| `mm.webhooks` | `list`, `create(d, { url, events })` → `secret` once, `update`, `delete`, `test`, `deliveries` |
| `mm.suppressions` | `list`, `add(d, email)`, `remove(d, email)` |
| `mm.logs` | `list(d, { limit? })` (max 100) |
| `mm.smtp` | `list`, `create(d, label)` → password once, `revoke(d, id)` |
| `mm.dns` | `list`, `createZone`, `delegation`, `import`, `upsert(d, { name, type, values, ttl? })`, `delete(d, name, type)`, `preset(d, provider, target?, subdomain?)` |
| `mm.apiKeys` | `list()`, `create(name)` → key once, `revoke(id)` |

## Sending

```ts
await mm.send.send(domainId, {
  from: "hola",                 // local part of an EXISTING mask; omitted → noreply@
  fromName: "Mi Tienda",
  to: "cliente@example.com",
  subject: "Tu pedido",
  markdown: "Gracias por tu compra…",   // markdown gets the domain signature; html/body do not
  replyTo: "ventas@sudominio.com",
  cc: [], bcc: [],              // up to 20 each, both pass the suppression list
  inReplyTo: msgId, references: [msgId], // to land in the customer's thread
}, { idempotencyKey: orderId }); // replayed for 24 h, no quota consumed
```

`html` is capped at 100 KB (`413`). A free domain answers `403` (no outbound mail); the daily
cap per activated domain answers `429`; a suppressed recipient `422`. Returned `messageId` is
the `Message-ID` header (use it for threading).

## Receiving webhooks

```ts
import { verifyWebhookSignature } from "@easybits.cloud/mailmask";

const ok = await verifyWebhookSignature(process.env.MAILMASK_WEBHOOK_SECRET!, {
  signature: req.headers["x-mailmask-signature"],   // "sha256=<hex>"
  timestamp: req.headers["x-mailmask-timestamp"],   // unix ms
}, rawBody);                                        // the body as received, NOT re-serialized
```

Events: `email.received`, `email.sent`, `email.delivered`, `email.bounced`, `email.complained`.
Deliveries retry 1m/5m/30m/2h/12h; answer `2xx` fast and do the work afterwards. Webhooks need
an activated domain and a public https URL (max 10 per domain).

## Rules

- Read the domain list once and cache the id; do not create domains from code paths that run
  more than once (a `409` means it exists).
- Treat `MailMaskError.message` as user-facing copy; do not swallow it.
- `from` must be a mask that exists and is enabled; create it first with `mm.aliases.create`.
- Never hardcode the key; never commit `.env`.
- Full reference with every field: https://www.mailmask.studio/docs (see the `mailmask-docs`
  skill). For an agent that should manage the account interactively use `mailmask-mcp`.
