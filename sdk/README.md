# @easybits.cloud/mailmask

Official TypeScript/JavaScript SDK for the [MailMask](https://mailmask.studio) email alias and forwarding API.

## Install

```bash
npm i @easybits.cloud/mailmask
```

## Quick start

```ts
import { MailMask } from "@easybits.cloud/mailmask";

const mm = new MailMask({ apiKey: "mm_live_..." });

// Get your domains
const domains = await mm.domains.list();
const domainId = domains[0].id;

// Create an alias — emails to hello@yourdomain.com forward to your inbox
const alias = await mm.aliases.create(domainId, {
  local: "hello",
  destinations: ["you@example.com"],
});

// Send an email (routed through MailMask for high deliverability)
await mm.send.send(domainId, {
  from: "hello",
  to: "client@example.com",
  subject: "Welcome!",
  html: "<p>Thanks for signing up.</p>",
});

// List aliases for a domain
const aliases = await mm.aliases.list(domainId);
```

## Docs

Full API reference and examples: https://mailmask.studio/docs

## Links

- [MailMask](https://mailmask.studio) — Email alias & forwarding service
- [EasyBits](https://easybits.cloud) — Cloud platform
- [Fixter](https://fixter.org) — Development team

## License

MIT
