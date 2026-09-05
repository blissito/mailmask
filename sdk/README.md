# @easybits.cloud/mailmask

Official TypeScript/JavaScript SDK for the [MailMask](https://mailmask.studio) email alias and forwarding API.

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

// Create an alias — emails to hello@yourdomain.com forward to your inbox
const alias = await mm.aliases.create(domainId, {
  alias: "hello",
  destinations: ["you@example.com"],
});

// Send an email (routed through MailMask for high deliverability)
await mm.send.send(domainId, {
  from: "hello",              // must be an active alias; defaults to `noreply`
  fromName: "Acme",           // optional display name: Acme <hello@yourdomain.com>
  to: "client@example.com",
  subject: "Welcome!",
  html: "<p>Thanks for signing up.</p>", // or `body` (plain text) / `markdown`
});

// List aliases for a domain
const aliases = await mm.aliases.list(domainId);
```

## More

```ts
// Attachments, copies, threading, idempotency
const pdf = await mm.attachments.upload(domainId, { filename: "invoice.pdf", contentType: "application/pdf", data: bytes });
await mm.send.send(domainId, {
  from: "billing", to: "client@example.com", cc: ["cfo@example.com"],
  subject: "Re: Invoice 42", markdown: "Attached.", attachments: [pdf],
  inReplyTo: "<abc@mail.example.com>", references: "<abc@mail.example.com>",
}, { idempotencyKey: `invoice-42` });

// Suppression list (hard bounces / complaints)
await mm.suppressions.list(domainId);
await mm.suppressions.remove(domainId, "fixed@example.com");

// Webhooks (Developer plan) — secret is shown once
const wh = await mm.webhooks.create(domainId, { url: "https://app.example.com/hooks/mailmask", events: ["email.received", "email.delivered", "email.bounced"] });

// On your server: verify the signature with the raw body
import { verifyWebhookSignature } from "@easybits.cloud/mailmask";
const ok = await verifyWebhookSignature(secret, { signature: req.headers["x-mailmask-signature"], timestamp: req.headers["x-mailmask-timestamp"] }, rawBody);
```

## Docs

Full API reference and examples: https://mailmask.studio/docs

## Links

- [MailMask](https://mailmask.studio) — Email alias & forwarding service
- [EasyBits](https://easybits.cloud) — Cloud platform
- [Fixter](https://fixter.org) — Development team

## License

MIT
