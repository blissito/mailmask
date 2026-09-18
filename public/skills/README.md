# MailMask agent skills

Skills in the [Agent Skills](https://agentskills.io) format for coding agents (Claude Code, Cursor,
Codex, Copilot…). Install one or all:

```bash
npx skills add blissito/mailmask-skills
# or straight from the site (same skills, discovered via /.well-known/agent-skills):
npx skills add https://www.mailmask.studio
```

| Skill | What for |
|---|---|
| `mailmask-account` | run a whole MailMask account for its owner: domains, masks, mailboxes, rules, webhooks, sending — with the guardrails |
| `mailmask-mcp` | connect any MCP client (Claude Code, Claude Desktop, Cursor) to `https://www.mailmask.studio/mcp` |
| `mailmask-sdk` | use `@easybits.cloud/mailmask` from JS/TS: masks, sending, webhooks and signature verification |
| `mailmask-dns` | point a domain or subdomain to Vercel, Netlify, GitHub Pages… through the MailMask DNS editor without breaking mail |
| `mailmask-docs` | read the MailMask docs from an agent: `llms.txt`, the docs page and OpenAPI |

This directory is mirrored from `public/skills/` in
[blissito/mailmask](https://github.com/blissito/mailmask). Docs: https://www.mailmask.studio/docs
