// Confirmación de lo destructivo cuando actúa el asistente (turn token `mt_`).
//
// Con un `mt_`, las rutas que borran o entregan algo NO ejecutan: guardan la acción en
// `pending_agent_actions` y contestan 409 `needs_confirmation`. El usuario la aprueba
// desde el dock con SU sesión (`POST /api/agent-actions`), y entonces el servidor
// re-ejecuta la petición archivada contra la misma ruta con la cookie del usuario.
//
// Tres reglas que hacen que esto sirva de algo:
// - El resumen de la tarjeta se arma desde la base, nunca con texto del modelo: si el
//   modelo dice "la máscara de ventas" pero el id apunta a soporte, la tarjeta dice soporte.
// - Aprobar exige cookie de sesión + CSRF y rechaza cualquier Bearer: si el `mt_`
//   alcanzara este endpoint, el agente se aprobaría a sí mismo.
// - `UPDATE … WHERE status='pending'` reclama la fila: dos clics (o dos pestañas) no
//   ejecutan dos veces.
import { sqlite } from "./pg.js";
import type { AuthUser } from "./auth.js";

export const PENDING_TTL_MS = 15 * 60_000;

export type AgentIntent =
  | "delete_domain"
  | "delete_alias"
  | "delete_mailbox"
  | "delete_dns_record"
  | "transfer_out"
  | "remove_member"
  | "cancel_addon"
  | "cancel_renewal";

export type ActionSummary = { title: string; lines: string[]; effects: string[]; destructive: boolean };
type StoredPayload = { method: string; path: string; body?: unknown };

type Row = {
  id: string;
  user_email: string;
  domain_id: string | null;
  intent: string;
  payload: string;
  summary: string;
  status: string;
  result: string | null;
  created_at: string;
  decided_at: string | null;
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function staleCutoff(): string {
  return new Date(Date.now() - PENDING_TTL_MS).toISOString();
}

export function expireStaleActions(email: string): void {
  sqlite
    .prepare("UPDATE pending_agent_actions SET status = 'expired', decided_at = ? WHERE user_email = ? AND status = 'pending' AND created_at <= ?")
    .run(new Date().toISOString(), email, staleCutoff());
}

/**
 * Guardián de una ruta destructiva. Devuelve `null` si la petición puede seguir (no la
 * originó el asistente) o el 409 listo para responder. Va DESPUÉS de las validaciones
 * de la ruta, para no archivar acciones sobre cosas que no existen.
 */
export function requireConfirmation(
  user: AuthUser,
  request: Request,
  o: { intent: AgentIntent; domainId: string | null; body?: unknown; summary: ActionSummary },
): Response | null {
  if (user.via !== "turn") return null;
  const url = new URL(request.url);
  const payload: StoredPayload = { method: request.method, path: url.pathname + url.search };
  if (o.body !== undefined) payload.body = o.body;
  const payloadJson = JSON.stringify(payload);

  expireStaleActions(user.email);
  // Si el modelo reintenta lo mismo, se reusa la tarjeta en vez de apilar dos.
  const existing = sqlite
    .prepare("SELECT id FROM pending_agent_actions WHERE user_email = ? AND intent = ? AND payload = ? AND status = 'pending'")
    .get(user.email, o.intent, payloadJson) as { id: string } | undefined;
  const id = existing?.id ?? crypto.randomUUID();
  if (!existing) {
    sqlite
      .prepare("INSERT INTO pending_agent_actions (id, user_email, domain_id, intent, payload, summary, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)")
      .run(id, user.email, o.domainId, o.intent, payloadJson, JSON.stringify(o.summary), new Date().toISOString());
  }
  return json({ error: "needs_confirmation", actionId: id, summary: o.summary }, 409);
}

export function listPendingActions(email: string) {
  expireStaleActions(email);
  const rows = sqlite
    .prepare("SELECT * FROM pending_agent_actions WHERE user_email = ? AND status = 'pending' ORDER BY created_at ASC")
    .all(email) as Row[];
  return rows.map((r) => ({
    id: r.id,
    tool: r.intent,
    summary: JSON.parse(r.summary) as ActionSummary,
    createdAt: r.created_at,
    expiresAt: new Date(Date.parse(r.created_at) + PENDING_TTL_MS).toISOString(),
  }));
}

export function getPendingAction(id: string): Row | undefined {
  return sqlite.prepare("SELECT * FROM pending_agent_actions WHERE id = ?").get(id) as Row | undefined;
}

/** Por qué no se pudo resolver: la fila ya no está pendiente (o no es de este usuario). */
function notPending(email: string, actionId: string): Response {
  expireStaleActions(email);
  const row = sqlite
    .prepare("SELECT status FROM pending_agent_actions WHERE id = ? AND user_email = ?")
    .get(actionId, email) as { status: string } | undefined;
  const status = row?.status ?? "not_found";
  const outcome = status === "executed" || status === "rejected" || status === "expired" || status === "failed" ? status : undefined;
  return json({
    error: "not_pending",
    status,
    ...(outcome ? { outcome } : {}),
    message: row ? "Esta acción ya se había resuelto." : "No se encontró la acción.",
  }, row ? 409 : 404);
}

export function rejectAction(email: string, actionId: string): Response {
  const r = sqlite
    .prepare("UPDATE pending_agent_actions SET status = 'rejected', decided_at = ? WHERE id = ? AND user_email = ? AND status = 'pending' AND created_at > ?")
    .run(new Date().toISOString(), actionId, email, staleCutoff());
  if (r.changes !== 1) return notPending(email, actionId);
  return json({ ok: true, outcome: "rejected", status: "rejected" });
}

/**
 * Aprueba y ejecuta. `execute` recibe la petición archivada y la corre contra la ruta
 * original con la sesión del usuario (en `main.ts`, vía `app.fetch`).
 */
export async function confirmAction(
  email: string,
  actionId: string,
  execute: (p: StoredPayload) => Promise<Response>,
): Promise<Response> {
  // Se reclama ANTES de ejecutar: el segundo clic encuentra la fila ya fuera de `pending`.
  const claimed = sqlite
    .prepare("UPDATE pending_agent_actions SET status = 'executing', decided_at = ? WHERE id = ? AND user_email = ? AND status = 'pending' AND created_at > ?")
    .run(new Date().toISOString(), actionId, email, staleCutoff());
  if (claimed.changes !== 1) return notPending(email, actionId);

  const row = getPendingAction(actionId)!;
  const payload = JSON.parse(row.payload) as StoredPayload;
  let status = 0;
  let result: unknown = null;
  try {
    const res = await execute(payload);
    status = res.status;
    result = await res.json().catch(() => null);
  } catch (err) {
    result = { error: String((err as Error)?.message ?? err) };
  }
  const ok = status >= 200 && status < 300;
  sqlite
    .prepare("UPDATE pending_agent_actions SET status = ?, result = ? WHERE id = ?")
    .run(ok ? "executed" : "failed", JSON.stringify({ status, body: result }), actionId);

  if (!ok) {
    const error = (result && typeof result === "object" && "error" in result) ? String((result as { error: unknown }).error) : "No se pudo completar la acción";
    return json({ error, outcome: "failed", status: "failed", httpStatus: status, result }, 422);
  }
  return json({ ok: true, outcome: "executed", status: "executed", result });
}
