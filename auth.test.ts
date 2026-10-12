// Pruebas de `auth.ts`: hashing de contraseñas (PBKDF2), el JWT de sesión (HMAC-SHA256), el
// turn token `mt_` del asistente y las cookies. Sin mocks de módulos ni red: funciones puras,
// la SQLite de pruebas y `crypto.subtle` para fabricar a mano los casos límite (hash legado,
// token de otro secreto). Los correos son únicos porque la base es UNA para toda la suite
// (docs/agents/pruebas-mocks.md).
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { sqlite } from "./pg.ts";
import * as dbmod from "./db.ts";
import {
  hashPassword,
  verifyPassword,
  signJwt,
  verifyJwt,
  issueTurnToken,
  verifyTurnToken,
  makeAuthCookie,
  clearAuthCookie,
  makeCsrfCookie,
  generateCsrfToken,
  parseCookies,
  getAuthUser,
} from "./auth.ts";

const suffix = Date.now().toString(36);
const emailDe = (etiqueta: string) => `auth-${etiqueta}-${suffix}@example.com`;

const encoder = new TextEncoder();
const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

/** HMAC-SHA256 con OTRA llave: así se firma un JWT ajeno sin tocar `JWT_SECRET` (se lee al importar). */
async function firmarConOtraLlave(payload: Record<string, unknown>, secreto: string): Promise<string> {
  const b64 = (s: string) => Buffer.from(s).toString("base64url");
  const key = await crypto.subtle.importKey("raw", encoder.encode(secreto), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const data = `${b64(JSON.stringify({ alg: "HS256", typ: "JWT" }))}.${b64(JSON.stringify(payload))}`;
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  return `${data}.${Buffer.from(new Uint8Array(sig)).toString("base64url")}`;
}

/** Hash con el esquema LEGADO (`salt:hash`, 1 000 iteraciones) para probar `needsRehash`. */
async function hashLegado(password: string, salt: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations: 1_000 },
    key,
    256,
  );
  return `${hex(salt)}:${hex(new Uint8Array(bits))}`;
}

const conCookie = (valor: string) => new Request("http://localhost/api/x", { headers: { cookie: valor } });
const conBearer = (valor: string) => new Request("http://localhost/api/x", { headers: { authorization: `Bearer ${valor}` } });

describe("auth: contraseñas (PBKDF2)", () => {
  // Una sola vez: cada `hashPassword` son 600 000 iteraciones.
  let hash = "";
  before(async () => {
    hash = await hashPassword("correcta-123");
  });

  it("hashPassword devuelve `salt:hash` en hex y con sal nueva cada vez", async () => {
    const otro = await hashPassword("correcta-123");
    assert.match(hash, /^[0-9a-f]{32}:[0-9a-f]{64}$/);
    assert.notEqual(hash, otro, "la sal es aleatoria: el mismo password no repite hash");
  });

  it("verifyPassword: la contraseña correcta pasa y no pide rehash", async () => {
    assert.deepEqual(await verifyPassword("correcta-123", hash), { valid: true, needsRehash: false });
  });

  it("verifyPassword: la contraseña incorrecta no pasa", async () => {
    assert.deepEqual(await verifyPassword("correcta-124", hash), { valid: false, needsRehash: false });
  });

  it("verifyPassword: un hash legado (1 000 iteraciones) pasa y pide rehash", async () => {
    const sal = crypto.getRandomValues(new Uint8Array(16));
    const legado = await hashLegado("correcta-123", sal);
    assert.deepEqual(await verifyPassword("correcta-123", legado), { valid: true, needsRehash: true });
    assert.deepEqual(await verifyPassword("incorrecta-123", legado), { valid: false, needsRehash: false });
  });
});

describe("auth: JWT de sesión (HMAC-SHA256)", () => {
  it("un token recién firmado verifica y trae el payload con iat y exp", async () => {
    const ahora = Math.floor(Date.now() / 1000);
    const payload = await verifyJwt(await signJwt({ email: "jwt@example.com" }));
    assert.ok(payload, "el token válido verifica");
    assert.equal(payload.email, "jwt@example.com");
    assert.equal(payload.exp as number, (payload.iat as number) + 3600, "el ttl por defecto es una hora");
    assert.ok((payload.iat as number) >= ahora - 1, "iat es de ahora");
  });

  it("verifyJwt: un token alterado no verifica", async () => {
    const token = await signJwt({ email: "jwt@example.com" });
    const [h, b, s] = token.split(".");

    const ultima = s.at(-1)!;
    const firmaTocada = `${h}.${b}.${s.slice(0, -1)}${ultima === "A" ? "B" : "A"}`;
    assert.equal(await verifyJwt(firmaTocada), null, "la firma ya no cuadra");

    const cuerpoFalso = Buffer.from(JSON.stringify({ email: "otro@example.com", exp: 9_999_999_999 })).toString("base64url");
    assert.equal(await verifyJwt(`${h}.${cuerpoFalso}.${s}`), null, "cambiar el payload invalida la firma");
  });

  it("verifyJwt: expirado no verifica; el ttl 0 todavía sí (`exp < now` es estricto)", async () => {
    assert.equal(await verifyJwt(await signJwt({ email: "jwt@example.com" }, -1)), null);
    assert.ok(await verifyJwt(await signJwt({ email: "jwt@example.com" }, 0)), "un exp igual a ahora no vence");
  });

  it("verifyJwt: un token firmado con otro secreto no verifica", async () => {
    const ajeno = await firmarConOtraLlave(
      { email: "jwt@example.com", exp: Math.floor(Date.now() / 1000) + 600 },
      "otro-secreto",
    );
    assert.equal(await verifyJwt(ajeno), null);
  });

  it("verifyJwt: basura y tokens incompletos devuelven null", async () => {
    for (const t of ["", "a", "a.b", "a.b.c", "no-es-un-jwt"]) {
      assert.equal(await verifyJwt(t), null, `«${t}» no verifica`);
    }
  });
});

describe("auth: turn token `mt_` del asistente", () => {
  const email = emailDe("turn");

  before(() => {
    // El `mt_` vigente exige un usuario REAL: sin él `getUser` devuelve null y la prueba mentiría.
    // El hash no se verifica aquí, así que no se gasta un PBKDF2 de 600 000 iteraciones.
    dbmod.createUser(email, "no-usado:0000");
  });

  it("issueTurnToken/verifyTurnToken: vigente devuelve el correo del usuario", async () => {
    const mt = await issueTurnToken(email);
    assert.match(mt, /^mt_/);
    assert.equal(await verifyTurnToken(mt), email);
  });

  it("verifyTurnToken: vencido devuelve null", async () => {
    const vencido = `mt_${await signJwt({ email, aud: "assistant", jti: "x" }, -1)}`;
    assert.equal(await verifyTurnToken(vencido), null);
  });

  it("verifyTurnToken: un mt_ de un correo que no existe devuelve null", async () => {
    assert.equal(await verifyTurnToken(await issueTurnToken(emailDe("fantasma"))), null);
  });

  it("verifyTurnToken: un JWT de sesión (sin aud) montado como mt_ no sirve", async () => {
    assert.equal(await verifyTurnToken(`mt_${await signJwt({ email })}`), null);
  });

  it("verifyTurnToken: lo que no empieza con mt_ no sirve", async () => {
    assert.equal(await verifyTurnToken(await signJwt({ email, aud: "assistant" })), null);
  });

  it("verifyTurnToken: un mt_ acuñado antes del cambio de contraseña queda revocado", async () => {
    const correo = emailDe("turn-revocado");
    dbmod.createUser(correo, "no-usado:0000");
    const mt = await issueTurnToken(correo);
    // El cambio de contraseña se fecha adelante: así el `iat` del token siempre queda antes.
    sqlite
      .prepare("UPDATE users SET password_changed_at = ? WHERE email = ?")
      .run(new Date(Date.now() + 60_000).toISOString(), correo);
    assert.equal(await verifyTurnToken(mt), null);
  });
});

describe("auth: cookies", () => {
  it("parseCookies: header nulo o vacío devuelve {}", () => {
    assert.deepEqual(parseCookies(null), {});
    assert.deepEqual(parseCookies(""), {});
  });

  it("parseCookies: separa por `;` y respeta los `=` del valor", () => {
    assert.deepEqual(parseCookies("a=1; b=2"), { a: "1", b: "2" });
    assert.deepEqual(parseCookies("token=abc=def"), { token: "abc=def" });
    assert.deepEqual(parseCookies(" a = 1 ; b = 2 "), { a: "1", b: "2" });
    assert.deepEqual(parseCookies("a=1; ; b=2"), { a: "1", b: "2" }, "un trozo vacío no inventa una cookie");
  });

  it("la cookie de sesión trae sus banderas (sin Secure en pruebas: FLY_APP_NAME no está)", () => {
    const c = makeAuthCookie("tok-123");
    assert.match(c, /^token=tok-123;/);
    assert.match(c, /HttpOnly/);
    assert.match(c, /SameSite=Strict/);
    assert.match(c, /Path=\//);
    assert.match(c, /Max-Age=3600/);
    assert.ok(!/Secure/.test(c), "la bandera Secure se enciende sólo con FLY_APP_NAME (producción)");

    const fuera = clearAuthCookie();
    assert.match(fuera, /^token=;/);
    assert.match(fuera, /Max-Age=0/, "borrar la cookie es Max-Age=0");
  });

  it("la cookie CSRF lleva las mismas banderas pero NO es HttpOnly (double-submit)", () => {
    const c = makeCsrfCookie("abc");
    assert.match(c, /^csrf_token=abc;/);
    assert.ok(!/HttpOnly/.test(c), "el JS de la página tiene que poder leerla");
    assert.match(c, /SameSite=Strict/);
    assert.match(c, /Path=\//);
    assert.match(c, /Max-Age=3600/);
  });

  it("generateCsrfToken devuelve 32 bytes en hex y no repite", () => {
    const a = generateCsrfToken();
    assert.match(a, /^[0-9a-f]{64}$/);
    assert.notEqual(a, generateCsrfToken());
  });
});

describe("auth: getAuthUser", () => {
  const email = emailDe("sesion");
  let cookie = "";
  let mt = "";

  before(async () => {
    dbmod.createUser(email, "no-usado:0000");
    cookie = await signJwt({ email });
    mt = await issueTurnToken(email);
  });

  it("sin credenciales devuelve null", async () => {
    assert.equal(await getAuthUser(new Request("http://localhost/api/x")), null);
  });

  it("con una cookie de sesión válida devuelve el usuario y via «session»", async () => {
    assert.deepEqual(await getAuthUser(conCookie(`token=${cookie}`)), { email, via: "session" });
  });

  it("un turn token puesto como cookie no es una sesión", async () => {
    assert.equal(await getAuthUser(conCookie(`token=${mt}`)), null);
  });

  it("un token de sesión de un correo que no existe devuelve null", async () => {
    const ajeno = await signJwt({ email: emailDe("nadie") });
    assert.equal(await getAuthUser(conCookie(`token=${ajeno}`)), null);
  });

  it("con `Bearer mt_` de un usuario real devuelve via «turn»", async () => {
    assert.deepEqual(await getAuthUser(conBearer(mt)), { email, via: "turn" });
  });

  it("con `Bearer mk_` de una llave real devuelve via «apikey»", async () => {
    const llave = (await dbmod.createApiKey(email, "auth-test")).plaintextKey;
    assert.deepEqual(await getAuthUser(conBearer(llave)), { email, via: "apikey" });
  });

  it("una sesión anterior al cambio de contraseña queda revocada", async () => {
    const correo = emailDe("revocado");
    dbmod.createUser(correo, "no-usado:0000");
    const tok = await signJwt({ email: correo });
    sqlite
      .prepare("UPDATE users SET password_changed_at = ? WHERE email = ?")
      .run(new Date(Date.now() + 60_000).toISOString(), correo);
    assert.equal(await getAuthUser(conCookie(`token=${tok}`)), null);
  });
});
