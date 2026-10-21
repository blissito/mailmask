// /video/* contesta Range con 206: sin eso Safari en iPhone no reproduce el MP4 de la landing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { statSync } from "node:fs";
import { app } from "./main.ts";

const URL_VIDEO = "http://localhost/video/correo-en-tu-dominio.mp4";
const SIZE = statSync(new URL("./public/video/correo-en-tu-dominio.mp4", import.meta.url)).size;

test("sin Range devuelve el archivo entero y anuncia accept-ranges", async () => {
  const res = await app.handle(new Request(URL_VIDEO));
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("content-type"), "video/mp4");
  assert.equal(res.headers.get("accept-ranges"), "bytes");
  assert.equal((await res.arrayBuffer()).byteLength, SIZE);
});

test("con Range devuelve 206 y sólo esos bytes", async () => {
  const res = await app.handle(new Request(URL_VIDEO, { headers: { range: "bytes=0-1" } }));
  assert.equal(res.status, 206);
  assert.equal(res.headers.get("content-range"), `bytes 0-1/${SIZE}`);
  assert.equal((await res.arrayBuffer()).byteLength, 2);
});

test("un Range fuera del archivo da 416", async () => {
  const res = await app.handle(new Request(URL_VIDEO, { headers: { range: `bytes=${SIZE}-` } }));
  assert.equal(res.status, 416);
});

test("no sirve nada fuera de public/video ni extensiones raras", async () => {
  for (const p of ["/video/../main.ts", "/video/correo-en-tu-dominio.html"]) {
    const res = await app.handle(new Request("http://localhost" + p));
    assert.equal(res.status, 404, p);
  }
});
