// Structured JSON logger for production observability

type Level = "info" | "warn" | "error";
type Component = "forwarding" | "webhook" | "auth" | "billing" | "ses" | "cron" | "server" | "backup" | "mesa" | "admin" | "startup";

export function log(level: Level, component: Component, msg: string, data?: Record<string, unknown>): void {
  const entry = {
    ts: new Date().toISOString(),
    level,
    component,
    msg,
    ...data,
  };
  const json = JSON.stringify(entry);
  if (level === "error") {
    console.error(json);
  } else if (level === "warn") {
    console.warn(json);
  } else {
    console.log(json);
  }
}
