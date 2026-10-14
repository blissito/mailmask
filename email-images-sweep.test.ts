// Barrido de imágenes y archivos huérfanos de correo en S3 (sweepOrphanEmailImages de ses.ts).
//
// Reglas que se fijan aquí:
//  - Borra sólo lo más viejo que `maxAgeHours`; lo reciente se queda.
//  - Recorre TODAS las páginas del listado (ContinuationToken), no sólo la primera.
//  - Un DeleteObject que falla no detiene el barrido y no cuenta.
//  - Lista únicamente los prefijos de imágenes y archivos de correo, nunca domain-assets/.
//
// Se dobla sólo `S3Client` con el módulo real esparcido, ANTES de importar `ses.ts`. Los comandos
// (ListObjectsV2Command, DeleteObjectCommand) son los reales: el doble despacha por
// `command.constructor.name` y lee `command.input`. El doble respeta el filtro por Prefix y sólo
// manda IsTruncated/NextContinuationToken en páginas intermedias, como lo haría S3.

import { describe, it, before, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";

const HOUR_MS = 3600_000;
const PAGE_SIZE = 2;

type StoredObject = { Key: string; LastModified: Date };
type ListInput = { Prefix?: string; ContinuationToken?: string };

let storedObjects: StoredObject[] = [];
let listCalls: ListInput[] = [];
let deletedKeys: string[] = [];
let keysThatFailToDelete = new Set<string>();

class FakeS3Client {
  async send(command: { constructor: { name: string }; input: ListInput & { Key?: string } }) {
    const input = command.input;
    switch (command.constructor.name) {
      case "ListObjectsV2Command": {
        listCalls.push({ ...input });
        const prefix = input.Prefix ?? "";
        const matching = storedObjects
          .filter((object) => object.Key.startsWith(prefix))
          .sort((a, b) => a.Key.localeCompare(b.Key));
        // La página se identifica por su índice de inicio, que es lo que viaja como token.
        const start = input.ContinuationToken ? Number(input.ContinuationToken) : 0;
        const page = matching.slice(start, start + PAGE_SIZE);
        const nextStart = start + PAGE_SIZE;
        const hasMore = nextStart < matching.length;
        return {
          Contents: page,
          IsTruncated: hasMore,
          NextContinuationToken: hasMore ? String(nextStart) : undefined,
        };
      }
      case "DeleteObjectCommand": {
        const key = input.Key!;
        if (keysThatFailToDelete.has(key)) {
          throw new Error(`AccessDenied al borrar ${key}`);
        }
        deletedKeys.push(key);
        storedObjects = storedObjects.filter((object) => object.Key !== key);
        return {};
      }
      default:
        throw new Error(`comando S3 no esperado: ${command.constructor.name}`);
    }
  }
}

const hoursAgo = (hours: number) => new Date(Date.now() - hours * HOUR_MS);

describe("sweepOrphanEmailImages: barrido de S3", () => {
  let sweepOrphanEmailImages: (maxAgeHours?: number) => Promise<number>;
  let EMAIL_IMAGE_PREFIX: string;
  let EMAIL_FILE_PREFIX: string;
  let DOMAIN_ASSET_PREFIX: string;

  before(async () => {
    const realS3 = await import("@aws-sdk/client-s3");
    mock.module("@aws-sdk/client-s3", {
      namedExports: { ...realS3, S3Client: FakeS3Client },
    });
    const ses = await import("./ses.ts");
    ({ sweepOrphanEmailImages } = ses);
    ({ EMAIL_IMAGE_PREFIX, EMAIL_FILE_PREFIX, DOMAIN_ASSET_PREFIX } = ses);
  });

  beforeEach(() => {
    storedObjects = [];
    listCalls = [];
    deletedKeys = [];
    keysThatFailToDelete = new Set();
  });

  it("borra un objeto de hace 25 h y conserva uno de hace 1 h", async () => {
    const oldKey = `${EMAIL_IMAGE_PREFIX}old-image.png`;
    const freshKey = `${EMAIL_IMAGE_PREFIX}fresh-image.png`;
    storedObjects = [
      { Key: oldKey, LastModified: hoursAgo(25) },
      { Key: freshKey, LastModified: hoursAgo(1) },
    ];

    await sweepOrphanEmailImages(24);

    assert.deepEqual(deletedKeys, [oldKey]);
    assert.ok(storedObjects.some((object) => object.Key === freshKey), "el objeto reciente debe quedar");
  });

  it("recorre todas las páginas del listado, no sólo la primera", async () => {
    const pageOneKeys = [`${EMAIL_IMAGE_PREFIX}a.png`, `${EMAIL_IMAGE_PREFIX}b.png`];
    const pageTwoOldKey = `${EMAIL_IMAGE_PREFIX}c-old.png`;
    storedObjects = [
      ...pageOneKeys.map((Key) => ({ Key, LastModified: hoursAgo(1) })),
      { Key: pageTwoOldKey, LastModified: hoursAgo(30) },
    ];

    await sweepOrphanEmailImages(24);

    const imageCalls = listCalls.filter((call) => call.Prefix === EMAIL_IMAGE_PREFIX);
    assert.ok(imageCalls.length >= 2, `esperaba al menos 2 páginas, hubo ${imageCalls.length}`);
    assert.equal(imageCalls[0].ContinuationToken, undefined);
    assert.equal(imageCalls[1].ContinuationToken, String(PAGE_SIZE));
    assert.deepEqual(deletedKeys, [pageTwoOldKey]);
  });

  it("un DeleteObject que falla no detiene el barrido y no cuenta como borrado", async () => {
    const failingKey = `${EMAIL_IMAGE_PREFIX}falla.png`;
    const okKey = `${EMAIL_IMAGE_PREFIX}ok.png`;
    storedObjects = [
      { Key: failingKey, LastModified: hoursAgo(48) },
      { Key: okKey, LastModified: hoursAgo(48) },
    ];
    keysThatFailToDelete = new Set([failingKey]);

    const removed = await sweepOrphanEmailImages(24);

    assert.deepEqual(deletedKeys, [okKey]);
    assert.equal(removed, 1);
  });

  it("suma lo borrado de los dos prefijos: imágenes y archivos", async () => {
    storedObjects = [
      { Key: `${EMAIL_IMAGE_PREFIX}img-old.png`, LastModified: hoursAgo(26) },
      { Key: `${EMAIL_FILE_PREFIX}file-old.pdf`, LastModified: hoursAgo(26) },
      { Key: `${EMAIL_FILE_PREFIX}file-fresh.pdf`, LastModified: hoursAgo(2) },
    ];

    const removed = await sweepOrphanEmailImages(24);

    assert.equal(removed, 2);
    assert.deepEqual(deletedKeys.sort(), [`${EMAIL_FILE_PREFIX}file-old.pdf`, `${EMAIL_IMAGE_PREFIX}img-old.png`].sort());
  });

  it("nunca lista el prefijo de assets del dominio ni borra objetos bajo él", async () => {
    const logoKey = `${DOMAIN_ASSET_PREFIX}logo-firma.png`;
    storedObjects = [
      { Key: logoKey, LastModified: hoursAgo(24 * 90) },
      { Key: `${EMAIL_IMAGE_PREFIX}huerfana.png`, LastModified: hoursAgo(48) },
    ];

    await sweepOrphanEmailImages(24);

    const listedPrefixes = listCalls.map((call) => call.Prefix);
    assert.ok(listedPrefixes.every((prefix) => prefix === EMAIL_IMAGE_PREFIX || prefix === EMAIL_FILE_PREFIX),
      `prefijos listados inesperados: ${JSON.stringify(listedPrefixes)}`);
    assert.ok(!deletedKeys.some((key) => key.startsWith(DOMAIN_ASSET_PREFIX)), "no debe borrar domain-assets/");
    assert.ok(storedObjects.some((object) => object.Key === logoKey), "el logo debe seguir en S3");
  });
});
