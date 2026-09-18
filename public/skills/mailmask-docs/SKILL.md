---
name: mailmask-docs
description: Read the MailMask documentation from an agent without scraping — llms.txt for the product, pricing and limits, the OpenAPI spec of the REST API, and the docs page for SDK, SMTP, webhooks and MCP. Use when the user asks how something works in MailMask or mailmask.studio, what a plan allows, or before calling its API.
license: MIT
compatibility: Network access to https://www.mailmask.studio
metadata:
  author: mailmask
  version: "1.0"
---

# Read the MailMask docs

## Pick the cheapest source

| Need | Fetch |
|---|---|
| What MailMask is, what it is not, prices and limits | `https://www.mailmask.studio/llms.txt` (plain text, ~120 lines; start here) |
| The REST API contract | `https://www.mailmask.studio/openapi/json` (OpenAPI 3, generated from the server; `/openapi` is the interactive version) |
| SDK, sending, webhooks, SMTP, IMAP, MCP with code samples | `https://www.mailmask.studio/docs` (one HTML page; sections `#instalacion`, `#autenticacion`, `#dominios`, `#aliases`, `#dns`, `#reglas`, `#envio`, `#logs`, `#supresion`, `#webhooks`, `#smtp`, `#api-keys`, `#errores`, `#mcp`, `#referencia`) |
| The SDK's exact types | `https://unpkg.com/@easybits.cloud/mailmask/dist/types.d.ts` |
| Long-form articles (comparisons, guides, ReDoS, SES anatomy) | `https://www.mailmask.studio/blog/` |
| Live tool list with descriptions | the MCP server (`tools/list` on `https://www.mailmask.studio/mcp` with an API key, see `mailmask-mcp`) |

Spanish is the source language of everything, including error messages; JSON field names
are English and are the contract (`destinations`, `enabled`, `events`…) — do not translate.

## Facts that answer most questions

- Every account is free; the first domain is free (5 masks, forwarding only, 1,000 forwards a
  month). Activating a domain costs $99 MXN/month: unlimited masks and people, 50 outbound a
  day, IMAP mailboxes with 10 GB, rules, webhooks, SMTP relay. Extras: +100 sends/day $99,
  +50 GB $99. Prices are MXN.
- Inbound mail arrives through AWS SES; the original body and attachments are kept 90 days, the
  thread and its searchable text stay.
- Auth is one API key (`mk_…`) as `Authorization: Bearer`, 60 req/min.
- IMAP `imap.mailmask.studio:993`, SMTP submission `:465` for mailboxes; SMTP relay for apps
  is `email-smtp.<region>.amazonaws.com:587` with credentials from the API.
- MCP: `https://www.mailmask.studio/mcp`, Streamable HTTP, no sessions, same key.

## Rules

- Read `llms.txt` before answering anything about pricing or limits; do not guess numbers.
- Quote the URL you used. Do not read the whole docs page for a single field: fetch it and
  search for the section anchor.
- This skill is read-only. To change the account use `mailmask-mcp` or `mailmask-account`.
