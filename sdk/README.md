# @easybits.cloud/mailmask

Official TypeScript/JavaScript SDK for the [MailMask](https://mailmask.studio) email address, mailbox and forwarding API.

## Install

```bash
npm i @easybits.cloud/mailmask
```

## Quick start

```ts
import { MailMask } from "@easybits.cloud/mailmask";

const mm = new MailMask({ apiKey: "mk_..." });

// Get your domains
const domains = await mm.domains.list();
const domainId = domains[0].id;

// Create an address — emails to hello@yourdomain.com forward to your inbox
const address = await mm.addresses.create(domainId, {
  alias: "hello",
  destinations: ["you@example.com"],
});

// Send an email (routed through MailMask for high deliverability)
await mm.send.send(domainId, {
  from: "hello",              // must be an active address; defaults to `noreply`
  fromName: "Acme",           // optional display name: Acme <hello@yourdomain.com>
  to: "client@example.com",
  subject: "Welcome!",
  html: "<p>Thanks for signing up.</p>", // or `body` (plain text) / `markdown`
});

// List addresses for a domain
const addresses = await mm.addresses.list(domainId);

// Add a domain — returns the DNS records to configure (MX, TXT, DKIM, SPF)
const { domain, dnsRecords } = await mm.domains.create("yourdomain.com");

// An address with an IMAP mailbox (activated domain): password is returned once
const inbox = await mm.addresses.create(domainId, { alias: "sales", mailbox: true });
// `mm.aliases` still works: it is the same resource under its old name.
console.log(inbox.buzon?.password, inbox.buzon?.imap);
```

## MCP

The same actions are available to AI agents at `https://www.mailmask.studio/mcp`
(Streamable HTTP, `Authorization: Bearer mk_...`). See https://www.mailmask.studio/docs#mcp.

## More

```ts
// Attachments, copies, threading, idempotency
const pdf = await mm.attachments.upload(domainId, { filename: "invoice.pdf", contentType: "application/pdf", data: bytes });
await mm.send.send(domainId, {
  from: "billing", to: "client@example.com", cc: ["cfo@example.com"],
  subject: "Re: Invoice 42", markdown: "Attached.", attachments: [pdf],
  inReplyTo: "<abc@mail.example.com>", references: "<abc@mail.example.com>",
}, { idempotencyKey: `invoice-42` });

// Account: identity + usage, and a full JSON export
const me = await mm.account.me();
const backup = await mm.account.export();

// Upload an image to embed in an outgoing email (returns a public url)
const { url } = await mm.domains.uploadImage(domainId, imageBlob);

// Suppression list (hard bounces / complaints)
await mm.suppressions.list(domainId);
await mm.suppressions.remove(domainId, "fixed@example.com");

// Webhooks (activated domain) — secret is shown once
const wh = await mm.webhooks.create(domainId, { url: "https://app.example.com/hooks/mailmask", events: ["email.received", "email.delivered", "email.bounced"] });

// On your server: verify the signature with the raw body
import { verifyWebhookSignature } from "@easybits.cloud/mailmask";
const ok = await verifyWebhookSignature(secret, { signature: req.headers["x-mailmask-signature"], timestamp: req.headers["x-mailmask-timestamp"] }, rawBody);
```

## Docs

Full API reference and examples: https://mailmask.studio/docs

## Links

- [MailMask](https://mailmask.studio) — Email addresses, mailboxes & forwarding on your domain
- [EasyBits](https://easybits.cloud) — Cloud platform
- [Fixter](https://fixter.org) — Development team

## License

MIT
