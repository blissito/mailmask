---
name: mailmask-account
description: Operate a MailMask account end to end on behalf of its owner — add and verify domains, create masks (aliases) with forwarding or IMAP mailboxes, routing rules, webhooks, suppression list, SMTP credentials and outbound email — through the REST API with an API key. Use when the user wants their agent to manage their email on mailmask.studio for them, or mentions MailMask, máscaras, hola@sudominio or a domain's mail setup.
license: MIT
compatibility: Needs curl or any HTTP client and network access to https://www.mailmask.studio. If the agent has MCP, prefer the mailmask-mcp skill (same capabilities, typed tools).
metadata:
  author: mailmask
  version: "1.0"
---

# Run a MailMask account for its owner

MailMask puts email on a domain the user already owns: masks like `hola@sudominio.com` that
forward to any inbox, optional IMAP mailboxes, outbound sending signed with DKIM, rules,
webhooks and a shared inbox (Bandeja). One API key controls everything except billing and the
Bandeja UI, which stay in the browser on purpose.

## Setup (once)

1. Ask the user for an API key: MailMask → **/app → API Keys → Nueva**. It looks like `mk_…`
   and is shown once. Keep it in an env var, never in command arguments or committed files:

```bash
export MAILMASK_API_KEY="mk_…"
```

2. Every call: `https://www.mailmask.studio/api/…` with
   `-H "Authorization: Bearer $MAILMASK_API_KEY" -H "Content-Type: application/json"`.
   60 requests per minute per key. Errors are always JSON `{ "error": "…" }` in Spanish;
   show that text to the user, it is written for them.

3. Start with `GET /api/domains`. Every other call needs a `domainId` from that list.

## What the account can do

| User asks | Call |
|---|---|
| "add my domain" | `POST /api/domains {"domain":"sudominio.com"}` → returns the DNS records to set (MX, TXT, 3 DKIM CNAME, SPF). Show them; then `POST /api/domains/:id/verify` once they are in place |
| "is my mail working?" | `GET /api/domains/:id/health` (MX, DKIM, SPF, receipt rule) |
| "create hola@ that forwards to my Gmail" | `POST /api/domains/:id/alias {"alias":"hola","destinations":["me@gmail.com"]}`; `"*"` is catch-all |
| "give hola@ a real mailbox for Apple Mail" | same call with `"mailbox": true` (or `POST …/alias/hola/mailbox` on an existing mask) → email, password **shown once**, IMAP `imap.mailmask.studio:993`, SMTP `:465` |
| "I lost the mailbox password" | `POST …/alias/hola/mailbox/password` → new password, shown once |
| "turn off / change destinations" | `PUT …/alias/hola {"enabled":false}` or `{"destinations":[…]}` |
| "route invoices to accounting" | `POST …/rules {"field":"subject","match":"contains","value":"factura","action":"forward","target":"conta@…"}`; actions `forward`, `webhook`, `discard`; `match: regex` is rejected with 400 when dangerous |
| "notify my app when mail arrives" | `POST …/webhooks {"url":"https://…","events":["email.received"]}` → `secret` shown once; verify with `X-MailMask-Signature: sha256=HMAC(secret, timestamp + "." + body)` |
| "send an email from hola@" | `POST …/send {"from":"hola","fromName":"…","to":"…","subject":"…","markdown":"…"}` (`html` or `body` also accepted; only `markdown` gets the domain signature). `Idempotency-Key` header is honored 24 h |
| "send this to 300 people" | `POST …/send-bulk {"from","recipients":[…],"subject","html"}` → `jobId`; poll `GET …/bulk/:jobId` |
| "who bounced?" | `GET …/logs?limit=100` (statuses `forwarded`, `discarded`, `sent`, `delivered`, `bounced`, `complained`) and `GET …/suppressions` |
| "stop emailing this person" | `POST …/suppressions {"email":"…"}` |
| "SMTP for my app" | `POST …/smtp-credentials {"label":"…"}` → password shown once, `email-smtp.<region>.amazonaws.com:587` STARTTLS |
| "point my domain to Vercel" | see the `mailmask-dns` skill (`POST …/dns/preset`) |
| "rotate the key" | `POST /api/api-keys {"name":"…"}`, then `DELETE /api/api-keys/:id` for the old one |

## What the plan allows

Every account is free. The **first domain** is free: 5 masks, forwarding only, 1,000 forwards a
month, no outbound email, no rules, no webhooks, no mailboxes. A second domain is created
**blocked** (mail is kept in the Bandeja, not forwarded). Activating a domain costs
**$99 MXN/month** (unlimited masks and people, 50 outbound a day, IMAP with 10 GB, rules,
webhooks, SMTP). A `403` with a price in the message means exactly that: tell the user what it
unlocks and where (`/app → Dominios → Activar`). Activation is a browser checkout; the API
cannot buy anything.

## Rules

- **Read before write.** List domains and masks first; a `409` means the name already exists.
- **Secrets are shown once** (mailbox password, webhook secret, SMTP password, API key). Hand
  them to the user immediately and do not log them.
- **Never delete a domain to "start over".** `DELETE /api/domains/:id` removes every mask, rule,
  mailbox and its mail, and the DNS records for mail stop working. Ask for explicit confirmation
  and repeat the domain name back before calling it; the same for `DELETE …/mailbox`.
- Do not send outbound email the user did not ask for, and never to addresses in the suppression
  list (the API refuses with `422`; do not work around it).
- A mask sends as `noreply@` unless `from` is set: always set `from` to an existing mask.
- Regex rules: prefer `contains`; a `400` on a regex is a safety rejection (ReDoS), not a typo.
- Quote the domain and mask in your answer (`hola@sudominio.com`), never the internal ids.
