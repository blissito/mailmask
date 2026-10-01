// Perfil de la cuenta de MailMask: nombre visible y foto.
//
// Es el perfil del USUARIO (quien entra a /app), no el de una máscara ni el avatar que
// ve quien recibe el correo. Se ve en la cabecera de /app, en la Bandeja (asignado a,
// presencia, notas) y en el dock de Mask.
//
// La foto se guarda tal cual (no hay `sharp` en las dependencias): tope de 2 MB y el
// tipo se decide por los bytes mágicos, nunca por el Content-Type que manda el cliente.
// Vive en `user-avatars/<sha256(email)[:24]>/<uuid>.<ext>` y se sirve inmutable: la
// llave cambia en cada subida, así que ningún navegador se queda con la vieja.
import { getUser, updateUserProfile, type User } from "./db.js";
import { putUserAvatarToS3, getUserAvatarFromS3, deleteUserAvatarFromS3, getAssistantUploadFromS3 } from "./ses.js";
import { isOwnUpload, userKey } from "./assistant.js";
import { log } from "./logger.js";

export const DISPLAY_NAME_MAX = 60;
export const AVATAR_MAX_BYTES = 2 * 1024 * 1024;

type ImageExt = "png" | "jpg" | "webp";
const CONTENT_TYPES: Record<ImageExt, string> = { png: "image/png", jpg: "image/jpeg", webp: "image/webp" };

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

/** Tipo real de la imagen por sus primeros bytes. GIF y SVG quedan fuera a propósito. */
export function sniffImage(b: Uint8Array): ImageExt | null {
  if (b.length >= 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 && b[4] === 0x0d && b[5] === 0x0a && b[6] === 0x1a && b[7] === 0x0a) return "png";
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "jpg";
  if (b.length >= 12 && String.fromCharCode(...b.subarray(0, 4)) === "RIFF" && String.fromCharCode(...b.subarray(8, 12)) === "WEBP") return "webp";
  return null;
}

export function avatarUrl(key: string | null | undefined): string | null {
  return key ? `/api/avatar/${key}` : null;
}

export function profileOf(user: Pick<User, "email" | "displayName" | "avatarKey">) {
  return { email: user.email, displayName: user.displayName ?? null, avatarUrl: avatarUrl(user.avatarKey) };
}

/** Perfil público de cualquier correo (miembros de la Bandeja). Sin cuenta, todo null. */
export function profileForEmail(email: string): { displayName: string | null; avatarUrl: string | null } {
  const u = getUser(email);
  return { displayName: u?.displayName ?? null, avatarUrl: avatarUrl(u?.avatarKey) };
}

/** Valida el nombre. Cadena vacía lo borra. Control chars → error, no se "limpian" en silencio. */
export function cleanDisplayName(raw: unknown): { ok: true; value: string | null } | { ok: false; error: string } {
  if (raw === null) return { ok: true, value: null };
  if (typeof raw !== "string") return { ok: false, error: "displayName debe ser texto" };
  // deno-lint-ignore no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(raw)) return { ok: false, error: "El nombre tiene caracteres no permitidos" };
  const value = raw.normalize("NFC").replace(/\s+/g, " ").trim();
  if ([...value].length > DISPLAY_NAME_MAX) return { ok: false, error: `El nombre no puede pasar de ${DISPLAY_NAME_MAX} caracteres` };
  return { ok: true, value: value || null };
}

/**
 * Guarda la foto y apunta el perfil a ella. El anterior se borra DESPUÉS de apuntar el
 * nuevo: si el borrado falla quedan unos KB huérfanos, que es mejor que quedarse sin foto.
 */
export async function storeAvatar(email: string, bytes: Uint8Array): Promise<{ ok: true; avatarUrl: string } | { ok: false; status: number; error: string }> {
  if (bytes.byteLength > AVATAR_MAX_BYTES) return { ok: false, status: 400, error: "La foto no puede pesar más de 2 MB" };
  const ext = sniffImage(bytes);
  if (!ext) return { ok: false, status: 400, error: "Formato no permitido. Usa PNG, JPG o WebP" };
  const key = `${userKey(email)}/${crypto.randomUUID()}.${ext}`;
  try {
    await putUserAvatarToS3(key, bytes, CONTENT_TYPES[ext]);
  } catch (err) {
    log("error", "profile", "Avatar upload failed", { error: String(err) });
    return { ok: false, status: 500, error: "No se pudo subir la foto" };
  }
  const previous = getUser(email)?.avatarKey;
  updateUserProfile(email, { avatarKey: key });
  if (previous && previous !== key) {
    try { await deleteUserAvatarFromS3(previous); } catch { /* mejor esfuerzo */ }
  }
  return { ok: true, avatarUrl: avatarUrl(key)! };
}

// --- Rutas (las monta main.ts después de autenticar) ---

export function handleGetProfile(email: string): Response {
  const user = getUser(email);
  if (!user) return json({ error: "No autenticado" }, 401);
  return json(profileOf(user));
}

export function handleUpdateProfile(email: string, body: unknown): Response {
  const b = (body ?? {}) as { displayName?: unknown };
  if (!("displayName" in b)) return json({ error: "Falta displayName" }, 400);
  const name = cleanDisplayName(b.displayName);
  if (!name.ok) return json({ error: name.error }, 400);
  updateUserProfile(email, { displayName: name.value });
  return json(profileOf(getUser(email)!));
}

/**
 * Multipart con `file`, o JSON `{fromUrl}`. `fromUrl` SÓLO acepta un adjunto firmado que
 * el mismo usuario subió al dock (`/api/asistente/files/*`, HMAC): se lee de S3 por su
 * llave y nunca se hace fetch, así que no hay forma de convertir esto en un SSRF.
 */
export async function handleUploadAvatar(email: string, request: Request): Promise<Response> {
  const ct = (request.headers.get("content-type") ?? "").toLowerCase();
  let bytes: Uint8Array;
  if (ct.startsWith("multipart/form-data")) {
    const form = await request.formData().catch(() => null);
    const file = form?.get("file");
    if (!(file instanceof File)) return json({ error: "Falta el archivo" }, 400);
    if (file.size > AVATAR_MAX_BYTES) return json({ error: "La foto no puede pesar más de 2 MB" }, 400);
    bytes = new Uint8Array(await file.arrayBuffer());
  } else {
    const b = await request.json().catch(() => null) as { fromUrl?: unknown } | null;
    const fromUrl = typeof b?.fromUrl === "string" ? b.fromUrl : "";
    if (!fromUrl) return json({ error: "Manda el archivo (multipart `file`) o `fromUrl`" }, 400);
    if (!isOwnUpload(fromUrl, email)) {
      return json({ error: "fromUrl sólo acepta una imagen que adjuntaste en el chat del asistente" }, 400);
    }
    const key = decodeURIComponent(new URL(fromUrl).pathname.slice("/api/asistente/files/".length));
    if (key.includes("..")) return json({ error: "fromUrl inválida" }, 400);
    const obj = await getAssistantUploadFromS3(key);
    if (!obj) return json({ error: "No encontré ese adjunto; vuelve a subirlo" }, 404);
    bytes = obj.body;
  }
  const r = await storeAvatar(email, bytes);
  if (!r.ok) return json({ error: r.error }, r.status);
  return json({ ok: true, ...profileOf(getUser(email)!) }, 201);
}

export async function handleDeleteAvatar(email: string): Promise<Response> {
  const previous = getUser(email)?.avatarKey;
  updateUserProfile(email, { avatarKey: null });
  if (previous) {
    try { await deleteUserAvatarFromS3(previous); } catch { /* mejor esfuerzo */ }
  }
  return json({ ok: true, ...profileOf(getUser(email)!) });
}

/** Público: la foto sale en la Bandeja de los compañeros. La llave no se puede adivinar. */
export async function handleServeAvatar(hash: string, file: string): Promise<Response> {
  // El prefijo vive en el mismo bucket que el correo entrante: nada de `..`.
  if (!/^[0-9a-f]{24}$/.test(hash) || !/^[0-9a-f-]{36}\.(png|jpg|webp)$/i.test(file)) {
    return new Response("No encontrado", { status: 404 });
  }
  const obj = await getUserAvatarFromS3(`${hash}/${file}`);
  if (!obj) return new Response("No encontrado", { status: 404 });
  const ext = file.split(".").pop()!.toLowerCase() as ImageExt;
  return new Response(Buffer.from(obj.body), {
    headers: {
      "content-type": CONTENT_TYPES[ext],
      "content-disposition": "inline",
      "x-content-type-options": "nosniff",
      "cache-control": "public, max-age=31536000, immutable",
    },
  });
}

// --- Google ---

const GOOGLE_PICTURE_HOST = /(^|\.)googleusercontent\.com$/i;

/**
 * Al entrar con Google se llena SÓLO lo vacío: nunca se pisa un nombre o una foto que el
 * usuario ya eligió. La foto se baja con tiempo límite y tope de tamaño, y sólo de
 * `*.googleusercontent.com` aunque el id_token venga de Google. Nada de esto puede
 * tumbar el login: cualquier fallo se registra y se sigue.
 */
export async function applyGoogleProfile(
  email: string,
  claims: { name?: unknown; picture?: unknown },
  doFetch: typeof fetch = fetch,
): Promise<void> {
  try {
    const user = getUser(email);
    if (!user) return;
    if (!user.displayName && typeof claims.name === "string") {
      const name = cleanDisplayName(claims.name.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ").slice(0, DISPLAY_NAME_MAX));
      if (name.ok && name.value) updateUserProfile(email, { displayName: name.value });
    }
    if (user.avatarKey || typeof claims.picture !== "string") return;
    let url: URL;
    try { url = new URL(claims.picture); } catch { return; }
    if (url.protocol !== "https:" || !GOOGLE_PICTURE_HOST.test(url.hostname)) return;
    const res = await doFetch(url.toString(), { signal: AbortSignal.timeout(5_000), redirect: "error" });
    if (!res.ok || !res.body) return;
    const declared = Number(res.headers.get("content-length") ?? "0");
    if (declared > AVATAR_MAX_BYTES) return;
    // Se lee en trozos con tope: un content-length mentiroso no llena la memoria.
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > AVATAR_MAX_BYTES) { await reader.cancel().catch(() => {}); return; }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { bytes.set(c, off); off += c.byteLength; }
    // Entre la lectura de arriba y ahora el usuario pudo haber subido una propia.
    if (getUser(email)?.avatarKey) return;
    await storeAvatar(email, bytes);
  } catch (err) {
    log("warn", "profile", "Google profile import failed", { error: String(err) });
  }
}
