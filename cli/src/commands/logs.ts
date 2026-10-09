import { defineCommand } from "citty";
import { requireClient } from "../client.js";
import { failFromError, failUsage, printJson } from "../output.js";
import { resolveDomainId } from "../resolve.js";
import { domainArg, jsonArg } from "../args.js";

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;
const OUTBOUND = ["sent", "delivered", "bounced", "complained"];

function parseLimit(raw: string | undefined, json?: boolean): number {
  if (raw === undefined) return DEFAULT_LIMIT;
  const n = Number(raw);
  if (!/^\d+$/.test(String(raw).trim()) || n < 1 || n > MAX_LIMIT) {
    failUsage(`--limit debe ser un entero entre 1 y ${MAX_LIMIT} (llegó "${raw}").`, { json });
  }
  return n;
}

const cut = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export default defineCommand({
  meta: { name: "logs", description: "Últimos correos del dominio (entrantes y salientes) con su estado" },
  args: {
    ...domainArg,
    limit: { type: "string" as const, description: `Cuántos mostrar, 1–${MAX_LIMIT} (por omisión ${DEFAULT_LIMIT})` },
    ...jsonArg,
  },
  async run({ args }) {
    const limit = parseLimit(args.limit, args.json);
    const { client } = await requireClient();
    const id = await resolveDomainId(client, args.domain, { json: args.json });
    try {
      const entries = await client.logs.list(id, { limit });
      if (args.json) return printJson(entries);
      if (entries.length === 0) {
        process.stdout.write("Sin correos registrados.\n");
        return;
      }
      for (const e of entries) {
        const dir = OUTBOUND.includes(e.status) ? "→ salió " : "← entró ";
        process.stdout.write(`${e.timestamp}  ${dir} ${cut(`${e.from} → ${e.to}`, 60).padEnd(60)}  ${cut(e.subject, 40).padEnd(40)}  ${e.status}\n`);
      }
    } catch (err) {
      failFromError(err, { json: args.json });
    }
  },
});
