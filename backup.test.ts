// Respaldo completo de la base (backup.ts).
//
// Lo que sube tiene que ABRIR, estar íntegro y traer los mismos usuarios que la base viva —
// un archivo que se ve bien pero no restaura es la falla que este respaldo existe para
// evitar. Y si la subida falla, el temporal no puede quedarse tirado en el disco.
//
// Nada sale a S3: `./ses.ts` va doblado con `mock.module` y `backup.ts` se importa DESPUÉS,
// en caliente, que es lo único que hace que el doble lo intercepte (patrón de
// `domain-renewal.test.ts`).

import { describe, it, before, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { gunzipSync } from "node:zlib";
import Database from "better-sqlite3";

/** Lo último que se intentó subir. */
let subida: { key: string; bytes: Buffer } | null = null;
let borradosViejos = 0;
let laSubidaFalla = false;

const putBackupBinaryToS3 = async (key: string, bytes: Buffer) => {
  if (laSubidaFalla) throw new Error("S3 no responde");
  subida = { key, bytes };
};
const deleteOldBackups = async () => { borradosViejos++; };

describe("backup: respaldo completo de la base", () => {
  // deno-lint-ignore no-explicit-any
  let dbmod: any, backup: any, sqlite: any;
  const email = `backup-${crypto.randomUUID().slice(0, 8)}@test.com`;

  /** Los temporales que deja `runDbBackup` mientras trabaja. */
  const temporales = () =>
    fs.readdirSync(os.tmpdir()).filter((f) => f.startsWith("mailmask-backup-") && f.endsWith(".sqlite"));

  before(async () => {
    // El módulo real primero: el doble sustituye sólo las dos funciones de S3 y deja el
    // resto de `ses.ts` en pie, que es lo que espera el resto del grafo de imports.
    const realSes = await import("./ses.ts");
    mock.module("./ses.ts", {
      namedExports: { ...realSes, putBackupBinaryToS3, deleteOldBackups },
    });
    dbmod = await import("./db.ts");
    sqlite = (await import("./pg.ts")).sqlite;
    backup = await import("./backup.ts");
    dbmod.createUser(email, "x");
  });

  beforeEach(() => {
    subida = null;
    borradosViejos = 0;
    laSubidaFalla = false;
  });

  it("sube una SQLite íntegra con los mismos usuarios que la base viva", async () => {
    const enVivo = (sqlite.prepare("SELECT count(*) AS c FROM users").get() as { c: number }).c;

    const resultado = await backup.runDbBackup();

    assert.ok(
      resultado.key.endsWith(backup.DB_BACKUP_SUFFIX),
      `la llave ${resultado.key} no termina en ${backup.DB_BACKUP_SUFFIX}`,
    );
    assert.ok(resultado.tables >= 10, `sólo ${resultado.tables} tablas en el respaldo`);
    assert.equal(resultado.users, enVivo);
    assert.equal(borradosViejos, 1, "se limpian los respaldos viejos una vez, tras subir");
    assert.ok(subida, "no se subió nada");
    assert.equal(subida.key, resultado.key);
    assert.equal(subida.bytes.length, resultado.gzipBytes);

    const crudo = gunzipSync(subida.bytes);
    assert.equal(crudo.length, resultado.rawBytes);

    const copia = path.join(os.tmpdir(), `respaldo-verificado-${crypto.randomUUID()}.sqlite`);
    fs.writeFileSync(copia, crudo);
    try {
      const abierta = new Database(copia, { readonly: true });
      try {
        assert.equal(abierta.pragma("integrity_check", { simple: true }), "ok");
        const usuarios = (abierta.prepare("SELECT count(*) AS c FROM users").get() as { c: number }).c;
        assert.equal(usuarios, enVivo);
      } finally {
        abierta.close();
      }
    } finally {
      fs.unlinkSync(copia);
    }
  });

  it("si la subida falla, no deja el temporal tirado ni borra los respaldos viejos", async () => {
    const antes = temporales();
    laSubidaFalla = true;

    await assert.rejects(() => backup.runDbBackup(), /S3 no responde/);

    const despues = temporales();
    const nuevos = despues.filter((f) => !antes.includes(f));
    assert.deepEqual(nuevos, [], `quedaron temporales: ${nuevos.join(", ")}`);
    assert.equal(borradosViejos, 0);
  });
});
