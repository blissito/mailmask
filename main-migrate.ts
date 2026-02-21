import { sql } from "./pg.ts";

const schema = await Deno.readTextFile(new URL("./schema.sql", import.meta.url));

// Split by semicolons and execute each statement
const statements = schema
  .split(";")
  .map((s) => s.trim())
  .filter((s) => s.length > 0 && !s.startsWith("--"));

for (const stmt of statements) {
  await sql.unsafe(stmt);
}

console.log(`Migration complete: ${statements.length} statements executed`);
await sql.end();
