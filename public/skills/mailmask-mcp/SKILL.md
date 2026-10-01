---
name: mailmask-mcp
description: Connect an MCP client (Claude Code, Claude Desktop, Cursor, any Streamable HTTP client) to the MailMask MCP server at https://www.mailmask.studio/mcp and use its 70 tools to manage domains, masks, IMAP mailboxes, DNS, rules, webhooks, team, payment links, domain purchases and transfers with one API key. Use when the user wants their agent wired to MailMask, asks to "add the MailMask MCP", or when a tool named list_domains, create_alias or point_domain_to is available.
license: MIT
compatibility: An MCP client with Streamable HTTP transport and custom headers, or curl for the raw JSON-RPC.
metadata:
  author: mailmask
  version: "1.1"
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
limits and error texts as the REST API. On `initialize` the server also sends `instructions`
(Spanish): the order to connect a domain, what free / activated / blocked mean, and the payment
rules. Names, grouped:

- **Domains**: `list_domains`, `get_domain`, `create_domain` (returns the DNS records to set),
  `domain_dns_setup` (exact records to paste at the registrar, which ones are already live, and
  `registrarHint` with the panel and menu), `verify_domain`, `domain_health`, `delete_domain`
  (irreversible).
- **Masks and mailboxes**: `list_aliases`, `create_alias` (`mailbox: true` also creates the IMAP
  mailbox), `update_alias`, `delete_alias`, `create_mailbox`, `delete_mailbox` (deletes its
  mail), `reset_mailbox_password`, `apple_profile_link` (Apple Mail profile URL for iPhone/Mac),
  `mailbox_export_link` (`.mbox` download URL). Both links open in the user's logged-in browser.
- **Activation and billing**: `activation_link` (MercadoPago link to activate a domain, $99
  MXN/month, or add `storage50` / `sends100`), `list_addons`, `billing_status`.
- **Buy and renew domains**: `search_domains`, `domain_prices`, `register_domain` (payment link),
  `list_registrations` (with `statusText`), `renewal_status`, `renewal_link`.
- **Transfers**: `transfer_check` (requirements and price, charges nothing), `transfer_start`
  (returns `formUrl`, the in-app form where the user pastes the EPP code and pays),
  `transfer_status`, `transfer_dns`, `update_transfer_dns`, `approve_transfer_dns` (only with
  the user's explicit OK), `resend_transfer_email`, `transfer_out` (EPP goes by email to the owner).
- **Team**: `list_members`, `invite_member` (`agent` or `admin`), `remove_member`, `cancel_invite`.
- **Inbox settings**: `get_signature`, `set_signature` (markdown, max 2000), `list_canned_replies`,
  `create_canned_reply`, `delete_canned_reply`.
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
- `search_tools` finds a tool by what you want to do when the list above is not loaded
  (accent-insensitive, Spanish keywords work).

Not exposed on purpose: API keys (an agent holding one key must not mint more) and reading or
answering Bandeja conversations. Payments are links: `activation_link`, `register_domain` and
`renewal_link` return `paid: false`; the **user** opens and pays in MercadoPago. Never say it is
paid; confirm afterwards with `list_addons`, `list_registrations` or `domain_health`.

## How to read the results

- A tool error with `HTTP 403` and a price in the text is information, not a failure: the
  free domain does not allow that (outbound mail, rules, webhooks, mailboxes, a 6th mask).
  Tell the user what it unlocks and stop.
- `HTTP 409` on a DNS write comes with `suggestedValues`: the merged record that keeps
  MailMask's mail records alive. Retry with exactly those values; there is no force flag.
- Passwords and webhook secrets appear **once** in the tool result. Hand them to the user in
  the same message.
- Always call `list_domains` first; every other tool takes its `domainId`.
- A result with `needsConfirmation: true` is not an error. It only happens with the in-app
  assistant's short-lived turn token (`mt_…`, 5 min) on irreversible actions (`delete_domain`,
  `delete_alias`, `delete_mailbox`, `delete_dns_record`, `remove_member`, `transfer_out`): the
  server answered `409 needs_confirmation` and the user got an approval card in the app. Do not
  retry or look for another way; wait. With an `mk_` key those actions run directly.

## Rules

- Read before write: `list_aliases` / `list_dns_records` before creating or replacing.
- Confirm with the user, repeating the name, before `delete_domain`, `delete_mailbox`,
  `remove_member` or `transfer_out`.
- Never ask for or accept an EPP (auth) code in chat; send the user to `transfer_start`'s
  `formUrl`. Asking the old registrar for a new code invalidates the one already sent.
- `set_dns_record` **replaces** the whole record set for a name and type: include the values
  that were already there. Prefer `point_domain_to` for hosting providers.
- Never send email the user did not ask for.
