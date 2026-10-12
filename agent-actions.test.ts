// Confirmación de lo destructivo cuando actúa el asistente (agent-actions.ts).
//
// agent-actions.ts es el freno que impide que el asistente borre o entregue algo sin que el
// usuario lo apruebe: archiva la acción en `pending_agent_actions` y contesta 409
// `needs_confirmation`. Aquí se fija ese contrato a nivel de módulo —la ruta HTTP, con su
// cookie y su CSRF, se cubre en `assistant.test.ts`—: que una petición que no viene del
// asistente pase directo, que el `mt_` no apile dos tarjetas de lo mismo, que una acción
// ajena ni se vea ni se toque, que a los 15 minutos venza, y sobre todo que aprobar dos
// veces ejecute UNA.
//
// La base es compartida (`docs/agents/pruebas-mocks.md`): cada prueba se aísla con su email
// único y sólo afirma sobre las filas de ese email. `pending_agent_actions.user_email` es FK
// a `users` con `ON DELETE CASCADE` y las FK están encendidas, así que el usuario se crea
// antes de archivar nada.

import { describe, it, before, mock } from "node:test";
import assert from "node:assert/strict";
import type { AuthUser } from "./auth.ts";

const SUMMARY = {
  title: "Borrar dominio",
  lines: ["x.com — 3 buzones"],
  effects: ["se pierde el correo que llegue"],
  destructive: true,
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

describe("agent-actions: confirmación de acciones del asistente", () => {
  // deno-lint-ignore no-explicit-any
  let aa: any, dbmod: any, sqlite: any;

  /** Un usuario nuevo por prueba: la base es de toda la suite y no se vacía entre archivos. */
  const usuario = (via: "turn" | "session"): AuthUser => {
    const email = `aa-${crypto.randomUUID()}@test.local`;
    dbmod.createUser(email, "x");
    return { email, via };
  };

  const peticion = () => new Request("https://x/api/domains/d1", { method: "DELETE" });

  /** Archiva una acción del asistente y devuelve el 409 con su actionId. */
  const archivar = async (user: AuthUser) => {
    const res = aa.requireConfirmation(user, peticion(), {
      intent: "delete_domain",
      domainId: "d1",
      summary: SUMMARY,
    });
    assert.ok(res, "el asistente debía recibir el 409 de confirmación");
    const body = await res.json();
    return { res, body, id: body.actionId as string };
  };

  const pendientes = (email: string) => aa.listPendingActions(email).map((r: { id: string }) => r.id);

  // Envejecer con un UPDATE directo: `mock.method(Date, "now")` no congela `new Date()`, que
  // es lo que arma `created_at` y el corte (`docs/agents/pruebas-mocks.md`).
  const envejecer = (id: string) =>
    sqlite
      .prepare("UPDATE pending_agent_actions SET created_at = ? WHERE id = ?")
      .run(new Date(Date.now() - aa.PENDING_TTL_MS - 1000).toISOString(), id);

  before(async () => {
    aa = await import("./agent-actions.ts");
    dbmod = await import("./db.ts");
    sqlite = (await import("./pg.ts")).sqlite;
  });

  it("la ventana de confirmación es de 15 minutos", () => {
    assert.equal(aa.PENDING_TTL_MS, 15 * 60_000);
  });

  it("una petición que no viene del asistente pasa directo y no archiva nada", () => {
    const user = usuario("session");
    const res = aa.requireConfirmation(user, peticion(), {
      intent: "delete_domain",
      domainId: "d1",
      summary: SUMMARY,
    });
    assert.equal(res, null, "una sesión normal no se detiene");
    assert.deepEqual(aa.listPendingActions(user.email), []);
  });

  it("el asistente recibe 409 needs_confirmation con un actionId que sale en pendientes", async () => {
    const user = usuario("turn");
    const { res, body, id } = await archivar(user);

    assert.equal(res.status, 409);
    assert.equal(body.error, "needs_confirmation");
    assert.equal(typeof id, "string");
    assert.deepEqual(body.summary, SUMMARY);

    const lista = aa.listPendingActions(user.email);
    assert.equal(lista.length, 1);
    assert.equal(lista[0].id, id);
    assert.equal(lista[0].tool, "delete_domain");
    assert.deepEqual(lista[0].summary, SUMMARY);
  });

  it("repetir la misma petición reusa el actionId en vez de apilar dos tarjetas", async () => {
    const user = usuario("turn");
    const uno = await archivar(user);
    const dos = await archivar(user);

    assert.equal(dos.id, uno.id);
    assert.deepEqual(pendientes(user.email), [uno.id]);
  });

  it("rechazar la quita de pendientes y deja la fila en rejected", async () => {
    const user = usuario("turn");
    const { id } = await archivar(user);

    const res = aa.rejectAction(user.email, id);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.outcome, "rejected");

    assert.deepEqual(pendientes(user.email), []);
    const fila = aa.getPendingAction(id);
    assert.equal(fila.status, "rejected");
    assert.ok(fila.decided_at, "queda registrado cuándo se decidió");
  });

  it("una acción ajena no se ve ni se toca, y sigue pendiente para su dueño", async () => {
    const dueno = usuario("turn");
    const ajeno = usuario("turn");
    const { id } = await archivar(dueno);
    const execute = mock.fn(async (_p: unknown) => json({ ok: true }));

    const rechazo = aa.rejectAction(ajeno.email, id);
    assert.equal(rechazo.status, 404);
    const rb = await rechazo.json();
    assert.equal(rb.error, "not_pending");
    assert.equal(rb.status, "not_found");

    const confirmacion = await aa.confirmAction(ajeno.email, id, execute);
    assert.equal(confirmacion.status, 404);

    assert.equal(execute.mock.calls.length, 0, "no se ejecuta con la identidad de otro");
    assert.equal(aa.getPendingAction(id).status, "pending");
    assert.deepEqual(pendientes(dueno.email), [id]);
  });

  it("pasados 15 minutos la acción vence, sale de pendientes, y las de otro usuario no se tocan", async () => {
    const dueno = usuario("turn");
    const otro = usuario("turn");
    const vieja = await archivar(dueno);
    const fresca = await archivar(otro);
    envejecer(vieja.id);
    envejecer(fresca.id); // también vencida por reloj: el barrido debe ser por usuario

    assert.deepEqual(pendientes(dueno.email), [], "la vencida sale de pendientes");
    const fila = aa.getPendingAction(vieja.id);
    assert.equal(fila.status, "expired");
    assert.ok(fila.decided_at, "queda registrado cuándo venció");

    aa.expireStaleActions(dueno.email);
    assert.equal(aa.getPendingAction(fresca.id).status, "pending", "el barrido es de quien se pide");
  });

  it("confirmar una acción inexistente da 404 y una vencida 409 expired, sin ejecutar", async () => {
    const user = usuario("turn");
    const execute = mock.fn(async (_p: unknown) => json({ ok: true }));

    const noExiste = await aa.confirmAction(user.email, crypto.randomUUID(), execute);
    assert.equal(noExiste.status, 404);
    assert.equal((await noExiste.json()).status, "not_found");

    const { id } = await archivar(user);
    envejecer(id);
    const vencida = await aa.confirmAction(user.email, id, execute);
    assert.equal(vencida.status, 409);
    const vb = await vencida.json();
    assert.equal(vb.status, "expired");
    assert.equal(vb.outcome, "expired");

    assert.equal(execute.mock.calls.length, 0, "no se ejecuta lo que ya no está pendiente");
  });

  it("confirmar dos veces ejecuta UNA vez y recibe la petición archivada", async () => {
    const user = usuario("turn");
    const { id } = await archivar(user);
    const execute = mock.fn(async (_p: unknown) => json({ ok: true, hecho: true }));

    const primera = await aa.confirmAction(user.email, id, execute);
    assert.equal(primera.status, 200);
    assert.equal((await primera.json()).outcome, "executed");

    const segunda = await aa.confirmAction(user.email, id, execute);
    assert.equal(segunda.status, 409);
    const sb = await segunda.json();
    assert.equal(sb.error, "not_pending");
    assert.equal(sb.outcome, "executed");

    assert.equal(execute.mock.calls.length, 1, "el segundo clic no vuelve a ejecutar");
    assert.deepEqual(execute.mock.calls[0].arguments[0], { method: "DELETE", path: "/api/domains/d1" });
    assert.equal(aa.getPendingAction(id).status, "executed");
  });

  it("dos confirmaciones a la vez ejecutan UNA vez", async () => {
    const user = usuario("turn");
    const { id } = await archivar(user);
    const execute = mock.fn(async (_p: unknown) => json({ ok: true }));

    const [a, b] = await Promise.all([
      aa.confirmAction(user.email, id, execute),
      aa.confirmAction(user.email, id, execute),
    ]);

    assert.deepEqual([a.status, b.status].sort(), [200, 409]);
    assert.equal(execute.mock.calls.length, 1, "la fila se reclama antes de ejecutar");
  });

  it("si la ejecución falla, queda failed y responde 422 con el resultado guardado", async () => {
    const user = usuario("turn");
    const { id } = await archivar(user);
    const execute = mock.fn(async (_p: unknown) => json({ error: "boom" }, 500));

    const res = await aa.confirmAction(user.email, id, execute);
    assert.equal(res.status, 422);
    const body = await res.json();
    assert.equal(body.outcome, "failed");
    assert.equal(body.status, "failed");
    assert.equal(body.error, "boom");

    const fila = aa.getPendingAction(id);
    assert.equal(fila.status, "failed");
    assert.deepEqual(JSON.parse(fila.result), { status: 500, body: { error: "boom" } });
  });

  it("si la ejecución lanza, queda failed en vez de tumbar la petición", async () => {
    const user = usuario("turn");
    const { id } = await archivar(user);
    const execute = mock.fn(async (_p: unknown) => {
      throw new Error("sin red");
    });

    const res = await aa.confirmAction(user.email, id, execute);
    assert.equal(res.status, 422);
    assert.equal((await res.json()).outcome, "failed");

    const fila = aa.getPendingAction(id);
    assert.equal(fila.status, "failed");
    assert.match(fila.result, /sin red/, "el motivo del fallo queda guardado");
  });
});
