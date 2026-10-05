---
name: mailmask-sdk
description: Use the official MailMask JavaScript/TypeScript SDK (@easybits.cloud/mailmask on npm) to create addresses (masks, formerly aliases), send email from a domain, manage rules, webhooks, suppressions, SMTP credentials, DNS, team members, signatures, payment links, domain purchases and transfers, and to verify webhook signatures in a receiver. Use when writing code that talks to mailmask.studio, when a project imports @easybits.cloud/mailmask, or when the user needs to send or receive email through their own domain from an app.
license: MIT
compatibility: Node 18+, Deno, Bun or Workers (uses fetch and WebCrypto only). Network access to https://www.mailmask.studio.
metadata:
  author: mailmask
  version: "1.3"
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
| `mm.domains` | `list()`, `get(id)`, `create(domain)` → DNS records to set, `dnsSetup(id, { live? })` → records to paste + `registrarHint`, `verify(id)`, `health(id)`, `delete(id)` |
| `mm.addresses` (0.4.5+; `mm.aliases` is the same object and keeps working) | `list(d)`, `create(d, { alias, destinations?, mailbox? })`, `update(d, alias, { enabled?, destinations? })`, `delete(d, alias)`, `createMailbox(d, alias)`, `deleteMailbox(d, alias)`, `resetMailboxPassword(d, alias)`, `appleProfile(d, alias)` → plist text, `exportMbox(d, alias)` → streaming `Response` |
| `mm.send` | `send(d, input, { idempotencyKey? })`, `bulkSend(d, { from, recipients, subject, html })`, `bulkStatus(d, jobId)` |
| `mm.attachments` | `upload(d, { filename, contentType, data })` → key to pass in `send({ attachments: [key] })` |
| `mm.rules` | `list`, `create(d, { field, match, value, action, target?, priority? })`, `update`, `delete` |
| `mm.webhooks` | `list`, `create(d, { url, events })` → `secret` once, `update`, `delete`, `test`, `deliveries` |
| `mm.suppressions` | `list`, `add(d, email)`, `remove(d, email)` |
| `mm.logs` | `list(d, { limit? })` (max 100) |
| `mm.smtp` | `list`, `create(d, label)` → password once, `revoke(d, id)` |
| `mm.dns` | `list`, `createZone`, `delegation`, `import`, `upsert(d, { name, type, values, ttl? })`, `delete(d, name, type)`, `preset(d, provider, target?, subdomain?)` |
| `mm.apiKeys` | `list()`, `create(name)` → key once, `revoke(id)` |
| `mm.billing` | `status()`, `addons()` → `{ catalog, forSale, mine }`, `checkout(d, kind = "domain", { payerEmail? })` → `{ init_point, addonId }` (`kind`: `domain`, `storage50`, `sends100`) |
| `mm.registrations` | `search(domain)`, `tlds()`, `register(domain)` → `{ initPoint, registrationId }`, `list()`, `renewal(regId, { payerEmail? })`, `transferOut(regId)` |
| `mm.transfers` | `check(domain)` (charges nothing), `dns(regId)`, `setDns(regId, records)` (replaces all), `approveDns(regId)`, `resendEmail(regId)` |
| `mm.members` | `list(d)` → `{ members, invites }`, `invite(d, { email, name, role? })`, `remove(d, memberId)`, `cancelInvite(d, token)` |
| `mm.signature` | `get(d)`, `set(d, markdown)` (max 2000, empty string clears) |
| `mm.canned` | `list(d)`, `create(d, { title, body })`, `delete(d, cannedId)` |
| `mm.account` | `getProfile()` → `{ email, displayName, avatarUrl }`, `updateProfile({ displayName })` (max 60, empty clears), `setAvatar(blob)` (PNG/JPG/WebP, max 2 MB), `setAvatarFromUrl(url)` (only a signed assistant upload), `removeAvatar()` |

Payments are MercadoPago links a person opens and pays (`init_point` / `initPoint`); nothing
changes until MercadoPago confirms, so check `billing.addons()` or `registrations.list()` after.
Annual activation ($999 MXN every 12 months) is `period: "annual"` on `POST /api/addons/checkout`
(only `kind: "domain"`); `billing.checkout()` does not expose `period` yet.

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
- `from` must be a mask that exists and is enabled; create it first with `mm.addresses.create` (`mm.aliases.create` on SDK < 0.4.5).
- Never hardcode the key; never commit `.env`.
- Full reference with every field: https://www.mailmask.studio/docs (see the `mailmask-docs`
  skill). For an agent that should manage the account interactively use `mailmask-mcp`.
