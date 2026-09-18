---
name: mailmask-dns
description: Point a domain or subdomain hosted on MailMask DNS to Vercel, Netlify, GitHub Pages, Cloudflare Pages, Render or Fly, add DMARC, redirect apex to www, or edit any DNS record set — without breaking the domain's email. Use when the user's domain has its DNS on mailmask.studio (or wants to move it there) and asks to connect a site, add a TXT verification, or change records.
license: MIT
compatibility: The MailMask MCP server (preferred) or curl with the account's API key. Network access to https://www.mailmask.studio.
metadata:
  author: mailmask
  version: "1.0"
---

# DNS on MailMask

MailMask hosts the zone of a domain (bought there, or delegated by nameservers) and exposes a
**record-set** editor: the unit is `(name, type)` with its full list of values, written with an
idempotent upsert. The records that make mail work (MX, `_amazonses` TXT, DKIM CNAMEs, the
`include:amazonses.com` in the apex SPF) are guarded by the server, so an agent can edit the
rest freely.

Tools (MCP) ↔ REST under `/api/domains/:id/dns`:

| Tool | REST | Does |
|---|---|---|
| `list_dns_records` | `GET /dns` | every record set, `managed: true` on the ones MailMask owns. **Call first.** |
| `point_domain_to` | `POST /dns/preset` | writes the right records for a provider |
| `set_dns_record` | `PUT /dns/records` | upsert `{ name, type, values[], ttl? }` |
| `delete_dns_record` | `DELETE /dns/records` body `{ name, type }` | removes the whole set |
| `create_dns_zone` | `POST /dns/zone` | imports the current public records, then returns the nameservers to set at the registrar |
| `dns_delegation_status` | `GET /dns/delegation` | are the nameservers already ours? (1–48 h after the change) |
| `import_dns_records` | `POST /dns/import` | dry look at the public DNS, writes nothing |

## The common request, in one call

"Point sudominio.com to Vercel" → `point_domain_to { provider: "vercel", target: "mi-app.vercel.app" }`.
Without `subdomain` it sets the apex **and** `www`; with `subdomain: "app"` only that name.

| provider | `target` |
|---|---|
| `vercel` | the `*.vercel.app` domain the project shows |
| `netlify` | the `*.netlify.app` site name |
| `github-pages` | `usuario.github.io` |
| `cloudflare-pages` | the `*.pages.dev` name |
| `render` | the `*.onrender.com` name |
| `fly` | the `*.fly.dev` name |
| `redirect-a-www` | none |
| `dmarc` | the mailbox that receives reports (`rua`) |

Providers know which record they expect at the apex (A vs ALIAS/CNAME flattening) and the tool
encodes that: prefer it over hand-written `set_dns_record`, which is where agents confuse apex
with `www` or invent the target.

## Editing by hand

- `set_dns_record` **replaces** the whole set: to add a TXT verification at `@`, read the
  current values and send them all plus the new one. MX priority goes inside the value
  (`"10 mail.ejemplo.com"`). TTL 60–172800, default 300.
- A `409` means the write would break mail. The response carries `suggestedValues`: the same
  set merged with what must stay. Retry with exactly those values. There is no `force`; the only
  legitimate way to move mail elsewhere is deleting the domain from MailMask.
- A CNAME cannot coexist with other types at the same name; the server says so with `400`.
- Changes are live on Route 53 within seconds; the world sees them after the old TTL.

## Moving a domain's DNS here

1. `create_dns_zone` (requires an activated domain, $99 MXN/month). It **imports before it
   returns**: everything it found from the current nameservers is in `imported`, and the zone
   is discarded if the import fails.
2. Show `imported` to the user and ask what is missing. Without zone transfer nobody can
   enumerate another provider's zone; the import probes common names, so a record with an
   unusual name may be absent and would stop working after the switch.
3. The user sets the returned nameservers at their registrar. Poll `dns_delegation_status`.

## Rules

- List first, write second, then list again and quote the resulting records to the user.
- Do not touch `managed: true` records and do not retry a `409` with the same values.
- One change at a time; do not batch a site move with a mail change in the same message.
