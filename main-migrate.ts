import { sql } from "./pg.ts";

const schema = await Deno.readTextFile(new URL("./schema.sql", import.meta.url));

try {
  await sql.unsafe(schema);
  console.log("Migration complete");
} catch (err) {
  console.error("Migration failed:", err);
  Deno.exit(1);
}

await sql.end();
