// El 404 lo sirve main.ts leyendo public/404.html; que no se rompa en silencio.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";

const html = readFileSync(new URL("./public/404.html", import.meta.url), "utf8");

test("404.html: noindex, un H1 y enlaces de salida", () => {
  assert.match(html, /<meta name="robots" content="noindex"/);
  assert.equal((html.match(/<h1[\s>]/g) ?? []).length, 1);
  for (const href of ["/", "/docs", "/pricing", "/blog"]) assert.ok(html.includes(`href="${href}"`), `falta ${href}`);
});

test("404.html: la ilustración existe y declara su tamaño y alt", () => {
  const img = html.match(/<img[^>]*src="(\/img\/404-il\.jpg)"[^>]*>/);
  assert.ok(img, "falta la imagen del 404");
  assert.match(img[0], /alt="[^"]{10,}"/);
  assert.match(img[0], /width="1200"/);
  assert.match(img[0], /height="800"/);
  assert.ok(existsSync(new URL("./public/img/404-il.jpg", import.meta.url)));
});
