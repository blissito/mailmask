// checkRateLimit: el contador por ventana que protege login, OAuth, API keys y reenvío
// de correo. Estaba sin pruebas, así que un cambio en el upsert SQL podía dejar pasar
// abusos o bloquear a todos sin que el CI lo notara.
//
// Lo que se fija aquí es el CONTRATO —cuántas pasan, qué reporta `remaining` y cuándo se
// reinicia la ventana—, no la forma del SQL: un refactor que conserve el contrato debe
// dejar estas pruebas en verde. Lo que hoy se comporta raro pero NO se arregla en este
// PR (las bloqueadas siguen sumando `count`; `expires_at` no limpia filas) queda abajo
// como caso documentado, no como expectativa bendecida.

import { describe, it, before, afterEach, mock } from "node:test";
import assert from "node:assert/strict";

// Único por corrida y calculado ANTES de mockear el reloj: `data/test.db` persiste entre
// corridas y `rate_limits` no se limpia sola, así que cada caso estrena su IP. De un
// `Date.now()` dentro de la prueba no puede salir: ahí el reloj ya está mockeado y dos
// casos con el mismo `t` escribirían la misma fila.
const suffix = Date.now();
let consecutivo = 0;
const ipUnica = (caso: string) => `rl-${suffix}-${caso}-${++consecutivo}`;

describe("checkRateLimit", () => {
  // Tipo explícito y sin `any`: este archivo entra en `npm run typecheck`.
  let checkRateLimit!: typeof import("./rate-limit.ts").checkRateLimit;

  before(async () => {
    ({ checkRateLimit } = await import("./rate-limit.ts"));
  });

  // El reloj es del proceso entero: un caso que no lo restaure contamina a los demás.
  afterEach(() => {
    mock.restoreAll();
  });

  /** Congela `Date.now()` en `inicial` y deja moverlo a mano. */
  const reloj = (inicial: number) => {
    let t = inicial;
    mock.method(Date, "now", () => t);
    return { avanza: (ms: number) => (t += ms) };
  };

  const T0 = 1_760_000_000_000;
  const MINUTO = 60_000;

  it("deja pasar hasta el límite y baja remaining de N-1 a 0", () => {
    reloj(T0);
    const ip = ipUnica("tope");

    assert.deepEqual(checkRateLimit(ip, 3, MINUTO), { allowed: true, remaining: 2, resetAt: T0 + MINUTO });
    assert.deepEqual(checkRateLimit(ip, 3, MINUTO), { allowed: true, remaining: 1, resetAt: T0 + MINUTO });
    assert.deepEqual(checkRateLimit(ip, 3, MINUTO), { allowed: true, remaining: 0, resetAt: T0 + MINUTO });
  });

  it("bloquea la petición N+1 con allowed:false y remaining:0", () => {
    reloj(T0);
    const ip = ipUnica("exceso");
    checkRateLimit(ip, 2, MINUTO);
    checkRateLimit(ip, 2, MINUTO);

    assert.deepEqual(checkRateLimit(ip, 2, MINUTO), { allowed: false, remaining: 0, resetAt: T0 + MINUTO });
  });

  it("al cumplirse windowMs la siguiente pasa y el contador arranca de nuevo", () => {
    const r = reloj(T0);
    const ip = ipUnica("reinicio");
    checkRateLimit(ip, 2, MINUTO);
    checkRateLimit(ip, 2, MINUTO);
    assert.equal(checkRateLimit(ip, 2, MINUTO).allowed, false, "la ventana está agotada");

    r.avanza(MINUTO);

    assert.deepEqual(checkRateLimit(ip, 2, MINUTO), { allowed: true, remaining: 1, resetAt: T0 + 2 * MINUTO });
  });

  it("reinicia justo en el borde t + windowMs (la condición del SQL es <=)", () => {
    const r = reloj(T0);
    const ip = ipUnica("borde-exacto");
    checkRateLimit(ip, 1, MINUTO);
    assert.equal(checkRateLimit(ip, 1, MINUTO).allowed, false);

    r.avanza(MINUTO);

    assert.deepEqual(checkRateLimit(ip, 1, MINUTO), { allowed: true, remaining: 0, resetAt: T0 + 2 * MINUTO });
  });

  it("NO reinicia un milisegundo antes del borde", () => {
    const r = reloj(T0);
    const ip = ipUnica("borde-antes");
    checkRateLimit(ip, 1, MINUTO);

    r.avanza(MINUTO - 1);

    assert.deepEqual(checkRateLimit(ip, 1, MINUTO), { allowed: false, remaining: 0, resetAt: T0 + MINUTO });
  });

  it("las bloqueadas siguen sumando count y no mueven resetAt (vigilar, no arreglar aquí)", () => {
    reloj(T0);
    const ip = ipUnica("bloqueadas");
    checkRateLimit(ip, 1, MINUTO);

    for (let i = 0; i < 5; i++) {
      assert.deepEqual(
        checkRateLimit(ip, 1, MINUTO),
        { allowed: false, remaining: 0, resetAt: T0 + MINUTO },
        `la bloqueada #${i + 1} sigue reportando lo mismo`,
      );
    }
  });

  it("dos IPs con el mismo límite llevan contadores independientes", () => {
    reloj(T0);
    const a = ipUnica("ip-a");
    const b = ipUnica("ip-b");

    assert.deepEqual(checkRateLimit(a, 1, MINUTO), { allowed: true, remaining: 0, resetAt: T0 + MINUTO });
    assert.equal(checkRateLimit(a, 1, MINUTO).allowed, false, "la primera IP ya gastó su cuota");
    assert.deepEqual(checkRateLimit(b, 1, MINUTO), { allowed: true, remaining: 0, resetAt: T0 + MINUTO });
  });

  it("la misma IP con límites distintos no comparte contador", () => {
    reloj(T0);
    const ip = ipUnica("limites");

    assert.equal(checkRateLimit(ip, 2, MINUTO).remaining, 1);
    assert.equal(checkRateLimit(ip, 2, MINUTO).remaining, 0);
    assert.equal(checkRateLimit(ip, 2, MINUTO).allowed, false, "la regla de 2 ya topó");
    // Otra cuota es otra regla: arranca en cero aunque sea la misma IP.
    assert.deepEqual(checkRateLimit(ip, 5, MINUTO), { allowed: true, remaining: 4, resetAt: T0 + MINUTO });
  });

  it("la misma IP con cuotas iguales pero ventanas distintas no comparte contador", () => {
    const r = reloj(T0);
    const ip = ipUnica("ventanas");
    const CORTA = 1_000;

    checkRateLimit(ip, 2, CORTA);
    checkRateLimit(ip, 2, CORTA);
    assert.equal(checkRateLimit(ip, 2, CORTA).allowed, false, "la ventana de 1 s está agotada");
    assert.equal(checkRateLimit(ip, 2, MINUTO).allowed, true, "la de un minuto sigue intacta");

    r.avanza(CORTA);

    assert.equal(checkRateLimit(ip, 2, CORTA).allowed, true, "la ventana corta se reinicia sola");
  });
});
