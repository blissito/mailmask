import { defineConfig } from "drizzle-kit";

export default defineConfig({
  schema: "./schema.ts",
  out: "./drizzle",
  dialect: "sqlite",
  dbCredentials: {
    url: process.env.DATABASE_PATH ?? "./data/mailmask.db",
  },
});
