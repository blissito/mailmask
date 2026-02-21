import postgres from "postgres";

export const sql = postgres(Deno.env.get("DATABASE_URL")!, {
  max: 10,
  idle_timeout: 20,
  connect_timeout: 10,
});
