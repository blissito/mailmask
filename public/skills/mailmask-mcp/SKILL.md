---
name: mailmask-mcp
description: Connect an MCP client (Claude Code, Claude Desktop, Cursor, any Streamable HTTP client) to the MailMask MCP server at https://www.mailmask.studio/mcp and use its 41 tools to manage domains, masks, IMAP mailboxes, DNS, rules and webhooks with one API key. Use when the user wants their agent wired to MailMask, asks to "add the MailMask MCP", or when a tool named list_domains, create_alias or point_domain_to is available.
license: MIT
compatibility: An MCP client with Streamable HTTP transport and custom headers, or curl for the raw JSON-RPC.
metadata:
  author: mailmask
  version: "1.0"
---

# MailMask over MCP

`https://www.mailmask.studio/mcp` is a Streamable HTTP MCP server **without sessions**:
`POST` only, JSON responses, no `Mcp-Session-Id`, no stream to keep open. It authenticates with
the account's API key (`mk_…`, from `/app → API Keys`). Without the header it answers `401`;
`GET` and `DELETE` answer `405` (there is no session to open or close).

## Connect

```bash
# Claude Code
claude mcp add --transport http mailmask https://www.mailmask.studio/mcp \
  --header "Authorization: Bearer mk_…"
```

```json
// Claude Desktop, Cursor and other clients (mcp.json)
{ "mcpServers": { "mailmask": {
  "type": "http", "url": "https://www.mailmask.studio/mcp",
  "headers": { "Authorization": "Bearer mk_…" } } } }
```

Raw, without a client:

```bash
curl -s https://www.mailmask.studio/mcp -H "Authorization: Bearer $MAILMASK_API_KEY" \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_domains","arguments":{}}}'
```

## The tools

Every tool is a method of the official SDK running inside the server, so it has the same
limits and error texts as the REST API. Names, grouped:

- **Domains**: `list_domains`, `get_domain`, `create_domain` (returns the DNS records to set),
  `verify_domain`, `domain_health`, `delete_domain` (irreversible).
- **Masks and mailboxes**: `list_aliases`, `create_alias` (`mailbox: true` also creates the IMAP
  mailbox), `update_alias`, `delete_alias`, `create_mailbox`, `delete_mailbox` (deletes its
  mail), `reset_mailbox_password`.
- **DNS**: `list_dns_records`, `create_dns_zone`, `dns_delegation_status`, `set_dns_record`,
  `delete_dns_record`, `import_dns_records`, `point_domain_to` (Vercel, Netlify, GitHub Pages,
  Cloudflare Pages, Render, Fly, redirect to www, DMARC).
- **Rules**: `list_rules`, `create_rule`, `update_rule`, `delete_rule`.
- **Webhooks**: `list_webhooks`, `create_webhook` (secret shown once), `update_webhook`,
  `delete_webhook`, `test_webhook`, `webhook_deliveries`.
- **Sending**: `send_email` (from an existing mask; `markdown` gets the domain signature),
  `bulk_send`, `bulk_status`.
- **Deliverability**: `list_logs`, `list_suppressions`, `add_suppression`, `remove_suppression`.
- **SMTP**: `list_smtp_credentials`, `create_smtp_credential` (password shown once),
  `revoke_smtp_credential`.
- `search_tools` finds a tool by what you want to do when the list above is not loaded.

Not exposed on purpose: API keys (an agent holding one key must not mint more), the Bandeja
(shared inbox) and billing. Activating a domain ($99 MXN/month) happens in the browser.

## How to read the results

- A tool error with `HTTP 403` and a price in the text is information, not a failure: the
  free domain does not allow that (outbound mail, rules, webhooks, mailboxes, a 6th mask).
  Tell the user what it unlocks and stop.
- `HTTP 409` on a DNS write comes with `suggestedValues`: the merged record that keeps
  MailMask's mail records alive. Retry with exactly those values; there is no force flag.
- Passwords and webhook secrets appear **once** in the tool result. Hand them to the user in
  the same message.
- Always call `list_domains` first; every other tool takes its `domainId`.

## Rules

- Read before write: `list_aliases` / `list_dns_records` before creating or replacing.
- Confirm with the user, repeating the name, before `delete_domain` or `delete_mailbox`.
- `set_dns_record` **replaces** the whole record set for a name and type: include the values
  that were already there. Prefer `point_domain_to` for hosting providers.
- Never send email the user did not ask for.
