// El 404 lo sirve main.ts leyendo public/404.html; que no se rompa en silencio.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";

const html = readFileSync(new URL("./public/404.html", import.meta.url), "utf8");

function medidasJpeg(buf: Buffer): { w: number; h: number } {
  let i = 2;
  while (i < buf.length) {
    if (buf[i] !== 0xff) { i++; continue; }
    const m = buf[i + 1];
    if (m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) return { h: buf.readUInt16BE(i + 5), w: buf.readUInt16BE(i + 7) };
    i += 2 + buf.readUInt16BE(i + 2);
  }
  throw new Error("JPEG sin SOF");
}

test("404.html: noindex, un solo H1 y sin el tema oscuro viejo", () => {
  assert.match(html, /<meta name="robots" content="noindex"/);
  assert.equal((html.match(/<h1[\s>]/g) ?? []).length, 1);
  assert.doesNotMatch(html, /zinc-950/);
});

test("404.html: enlaces de salida a /, /docs, /pricing y /blog", () => {
  for (const href of ["/", "/docs", "/pricing", "/blog"]) assert.ok(html.includes(`href="${href}"`), `falta ${href}`);
});

test("404.html: la ilustración existe, mide lo que declara y trae alt", () => {
  const img = html.match(/<img[^>]*src="(\/img\/404-il\.jpg)"[^>]*>/);
  assert.ok(img, "falta la imagen del 404");
  assert.match(img[0], /alt="[^"]{10,}"/);
  const ruta = new URL("./public/img/404-il.jpg", import.meta.url);
  assert.ok(existsSync(ruta));
  const { w, h } = medidasJpeg(readFileSync(ruta));
  assert.match(img[0], new RegExp(`width="${w}"`));
  assert.match(img[0], new RegExp(`height="${h}"`));
});
