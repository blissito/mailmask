// Perfil de la cuenta: nombre y foto (`profile.ts`). S3 simulado: el mock de ses.ts va
// antes de cargar main.ts, igual que en assistant.test.ts.
import { describe, it, before, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";

const suffix = Date.now().toString(36);
const avatars = new Map<string, { body: Uint8Array; contentType: string }>();
const deleted: string[] = [];
const uploads = new Map<string, { body: Uint8Array; contentType: string }>();

// Cabeceras mínimas de cada formato: el tipo se decide por los bytes, no por el nombre.
const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4]);
const JPG = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0, 0x10, 0x4a, 0x46]);

describe("Perfil de la cuenta", () => {
  // deno-lint-ignore no-explicit-any
  let app: any, dbmod: any, sqlite: any, authmod: any, asis: any, profile: any;
  const email = `perfil-${suffix}@example.com`;
  const otro = `perfil-otro-${suffix}@example.com`;
  let session = { cookie: "", csrf: "" };
  let domainId = "";

  const req = (path: string, init: RequestInit = {}) => app.fetch(new Request(`http://localhost${path}`, init));
  const withSession = (extra: Record<string, string> = {}) => ({
    cookie: `${session.cookie}; csrf_token=${session.csrf}`,
    "x-csrf-token": session.csrf,
    ...extra,
  });
  const putName = (displayName: unknown) =>
    req("/api/profile", { method: "PUT", headers: withSession({ "content-type": "application/json" }), body: JSON.stringify({ displayName }) });
  const upload = (bytes: Uint8Array, type = "image/png") => {
    const fd = new FormData();
    fd.append("file", new File([bytes as BlobPart], "foto", { type }));
    return req("/api/profile/avatar", { method: "POST", headers: withSession(), body: fd });
  };
  const fromUrl = (url: string) =>
    req("/api/profile/avatar", { method: "POST", headers: withSession({ "content-type": "application/json" }), body: JSON.stringify({ fromUrl: url }) });

  before(async () => {
    const realSes = await import("./ses.ts");
    mock.module("./ses.ts", { namedExports: {
      ...realSes,
      putUserAvatarToS3: async (k: string, body: Uint8Array, contentType: string) => { avatars.set(k, { body, contentType }); },
      getUserAvatarFromS3: async (k: string) => avatars.get(k) ?? null,
      deleteUserAvatarFromS3: async (k: string) => { deleted.push(k); avatars.delete(k); },
      putAssistantUploadToS3: async (k: string, body: Uint8Array, contentType: string) => { uploads.set(k, { body, contentType }); },
      getAssistantUploadFromS3: async (k: string) => uploads.get(k) ?? null,
    } });
    ({ app } = await import("./main.ts"));
    dbmod = await import("./db.ts");
    ({ sqlite } = await import("./pg.ts"));
    authmod = await import("./auth.ts");
    asis = await import("./assistant.ts");
    profile = await import("./profile.ts");

    dbmod.createUser(email, await authmod.hashPassword("password123"));
    dbmod.createUser(otro, await authmod.hashPassword("password123"));
    session = { cookie: `token=${await authmod.signJwt({ email })}`, csrf: authmod.generateCsrfToken() };
    domainId = dbmod.createDomain(email, `perfil-${suffix}.com`, ["d1", "d2", "d3"], "vt").id;
  });
  beforeEach(() => sqlite.prepare("DELETE FROM rate_limits").run());

  it("nombre: válido se guarda, largo o con caracteres de control es 400", async () => {
    assert.equal((await putName("x".repeat(61))).status, 400);
    assert.equal((await putName("Ana\u0000Ruiz")).status, 400);
    assert.equal((await putName("Ana\nRuiz")).status, 400);
    assert.equal((await putName(42)).status, 400);
    const ok = await putName("  Ana   Ruiz ");
    assert.equal(ok.status, 200);
    assert.equal((await ok.json()).displayName, "Ana Ruiz");
    const get = await (await req("/api/profile", { headers: { cookie: session.cookie } })).json();
    assert.deepEqual(get, { email, displayName: "Ana Ruiz", avatarUrl: null });
  });

  it("foto: tipo inválido o de más de 2 MB es 400", async () => {
    assert.equal((await upload(new TextEncoder().encode("<svg></svg>"), "image/png")).status, 400, "los bytes mandan, no el tipo declarado");
    const gif = new TextEncoder().encode("GIF89a.......");
    assert.equal((await upload(gif, "image/gif")).status, 400);
    const big = new Uint8Array(2 * 1024 * 1024 + 1);
    big.set(PNG);
    assert.equal((await upload(big)).status, 400);
    assert.equal(avatars.size, 0);
  });

  it("al reemplazar la foto se borra la anterior y se sirve inmutable", async () => {
    const r1 = await upload(PNG);
    assert.equal(r1.status, 201);
    const a1 = (await r1.json()).avatarUrl as string;
    assert.match(a1, /^\/api\/avatar\/[0-9a-f]{24}\/[0-9a-f-]{36}\.png$/);

    const r2 = await upload(JPG, "image/jpeg");
    assert.equal(r2.status, 201);
    const a2 = (await r2.json()).avatarUrl as string;
    assert.match(a2, /\.jpg$/);
    assert.ok(deleted.includes(a1.slice("/api/avatar/".length)), "la anterior se borró de S3");

    const img = await req(a2);
    assert.equal(img.status, 200);
    assert.equal(img.headers.get("content-type"), "image/jpeg");
    assert.match(img.headers.get("cache-control") ?? "", /immutable/);
    assert.equal((await req("/api/avatar/../x")).status, 404);
  });

  it("fromUrl: ajena, sin firma o con firma inválida es 400; la propia firmada funciona", async () => {
    const mine = `${asis.userKey(email)}/${crypto.randomUUID()}-foto.png`;
    uploads.set(mine, { body: PNG, contentType: "image/png" });
    const theirs = `${asis.userKey(otro)}/${crypto.randomUUID()}-foto.png`;
    uploads.set(theirs, { body: PNG, contentType: "image/png" });

    assert.equal((await fromUrl("https://evil.example/foto.png")).status, 400);
    assert.equal((await fromUrl("http://169.254.169.254/latest/meta-data")).status, 400);
    assert.equal((await fromUrl(asis.signedUploadUrl("http://localhost", theirs))).status, 400, "adjunto de otra cuenta");
    const forged = asis.signedUploadUrl("http://localhost", mine).replace(/sig=[0-9a-f]+/, `sig=${"0".repeat(64)}`);
    assert.equal((await fromUrl(forged)).status, 400);

    const ok = await fromUrl(asis.signedUploadUrl("https://www.mailmask.studio", mine));
    assert.equal(ok.status, 201, await ok.clone().text());
    assert.match((await ok.json()).avatarUrl, /\.png$/);
  });

  it("/me regresa el perfil y DELETE quita la foto", async () => {
    let me = await (await req("/api/auth/me", { headers: { cookie: session.cookie } })).json();
    assert.equal(me.email, email);
    assert.equal(me.displayName, "Ana Ruiz");
    assert.match(me.avatarUrl, /^\/api\/avatar\//);
    const del = await req("/api/profile/avatar", { method: "DELETE", headers: withSession() });
    assert.equal(del.status, 200);
    me = await (await req("/api/auth/me", { headers: { cookie: session.cookie } })).json();
    assert.equal(me.avatarUrl, null);
  });

  it("/agents trae nombre y foto del dueño y de cada miembro; un agente lo lee sin invitaciones", async () => {
    dbmod.updateUserProfile(otro, { displayName: "Beto", avatarKey: `${asis.userKey(otro)}/${crypto.randomUUID()}.webp` });
    dbmod.createAgent({ domainId, email: otro, name: "Invitado", role: "agent" });
    dbmod.createAgentInvite(domainId, `pendiente-${suffix}@example.com`, "Pendiente", "agent");

    const owner = await (await req(`/api/domains/${domainId}/agents`, { headers: { cookie: session.cookie } })).json();
    assert.equal(owner.owner.email, email);
    assert.equal(owner.owner.displayName, "Ana Ruiz");
    const beto = owner.members.find((m: { email: string }) => m.email === otro);
    assert.equal(beto.displayName, "Beto");
    assert.match(beto.avatarUrl, /\.webp$/);
    assert.ok(beto.id, "el dueño sigue viendo el id para quitarlo");
    assert.equal(owner.invites.length, 1);

    const agentCookie = `token=${await authmod.signJwt({ email: otro })}`;
    const asAgent = await req(`/api/domains/${domainId}/agents`, { headers: { cookie: agentCookie } });
    assert.equal(asAgent.status, 200);
    const a = await asAgent.json();
    assert.deepEqual(a.invites, []);
    assert.equal(a.owner.displayName, "Ana Ruiz");
    assert.equal(a.members[0].displayName, "Beto");
    assert.equal(a.members[0].id, undefined, "sin ids ni ligas para quien no administra");
  });

  it("Google sólo llena lo que está vacío y sólo baja de googleusercontent", async () => {
    const g = `perfil-google-${suffix}@example.com`;
    dbmod.createUser(g, "hash");
    const fetched: string[] = [];
    const fakeFetch = (async (url: string) => {
      fetched.push(String(url));
      return new Response(PNG, { headers: { "content-type": "image/png" } });
    }) as unknown as typeof fetch;

    // Host ajeno: no se descarga nada.
    await profile.applyGoogleProfile(g, { name: "Gabi Google", picture: "https://evil.example/a.png" }, fakeFetch);
    assert.equal(fetched.length, 0);
    let u = dbmod.getUser(g);
    assert.equal(u.displayName, "Gabi Google");
    assert.equal(u.avatarKey, undefined);

    await profile.applyGoogleProfile(g, { name: "Otro Nombre", picture: "https://lh3.googleusercontent.com/a/xyz" }, fakeFetch);
    u = dbmod.getUser(g);
    assert.equal(u.displayName, "Gabi Google", "no pisa el nombre que ya había");
    assert.match(u.avatarKey, /\.png$/);
    const firstKey = u.avatarKey;

    await profile.applyGoogleProfile(g, { name: "X", picture: "https://lh3.googleusercontent.com/a/otra" }, fakeFetch);
    assert.equal(dbmod.getUser(g).avatarKey, firstKey, "no pisa la foto");
    assert.equal(fetched.length, 1);

    // Demasiado grande: se descarta sin tumbar nada.
    const h = `perfil-google2-${suffix}@example.com`;
    dbmod.createUser(h, "hash");
    const huge = new Uint8Array(3 * 1024 * 1024);
    huge.set(PNG);
    await profile.applyGoogleProfile(h, { picture: "https://lh3.googleusercontent.com/a/big" }, (async () => new Response(huge)) as unknown as typeof fetch);
    assert.equal(dbmod.getUser(h).avatarKey, undefined);
  });
});
