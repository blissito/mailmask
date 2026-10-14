// Retención de respaldos en S3 (deleteOldBackups de ses.ts).
//
// Reglas que se fijan aquí:
//  - La retención es por FAMILIA: los snapshots `.sqlite.gz` y los JSON legados no
//    compiten por los mismos cupos, o un JSON nuevo desalojaría un snapshot restaurable.
//  - Cuenta DÍAS calendario, no archivos: de cada día sólo cuenta el respaldo más nuevo.
//    Varios respaldos del mismo día no desalojan la semana anterior.
//  - Se conservan exactamente los BACKUP_RETENTION (7) días más recientes por familia.
//
// S3 no se toca: el cliente se dobla con `mock.module` ANTES de importar `ses.ts`, y el
// módulo real va esparcido para no perder nada más de lo que se dobla.

import { describe, it, before, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";

const listedKeys: { Key: string }[] = [];
let deletedKeys: string[] = [];

class ListObjectsV2Command {
  constructor(public input: unknown) {}
}
class DeleteObjectCommand {
  constructor(public input: { Key: string }) {}
}
class FakeS3Client {
  async send(command: unknown) {
    if (command instanceof ListObjectsV2Command) return { Contents: listedKeys };
    if (command instanceof DeleteObjectCommand) {
      deletedKeys.push(command.input.Key);
      return {};
    }
    throw new Error("comando S3 no esperado");
  }
}

/** Un respaldo por cada llave; el orden de la listado de S3 se mezcla a propósito. */
function listing(keys: string[]) {
  listedKeys.splice(0, listedKeys.length, ...keys.map((Key) => ({ Key })));
}

const dbKey = (day: string, time = "03-00-00") =>
  `backups/mailmask-db-${day}T${time}.sqlite.gz`;
const legacyKey = (day: string, time = "03-00-00") =>
  `backups/mailmask-backup-${day}T${time}.json`;

describe("deleteOldBackups: retención por familia y por día", () => {
  let deleteOldBackups: () => Promise<void>;

  before(async () => {
    const realS3 = await import("@aws-sdk/client-s3");
    mock.module("@aws-sdk/client-s3", {
      namedExports: {
        ...realS3,
        S3Client: FakeS3Client,
        ListObjectsV2Command,
        DeleteObjectCommand,
      },
    });
    ({ deleteOldBackups } = await import("./ses.ts"));
  });

  beforeEach(() => {
    listing([]);
    deletedKeys = [];
  });

  it("tres respaldos del mismo día cuentan como uno y no desalojan días anteriores", async () => {
    // Siete días con un respaldo cada uno, y tres extra el último día.
    const days = ["2026-10-01", "2026-10-02", "2026-10-03", "2026-10-04", "2026-10-05", "2026-10-06", "2026-10-07"];
    const dayKeys = days.map((d) => dbKey(d));
    const extras = [dbKey("2026-10-07", "09-00-00"), dbKey("2026-10-07", "12-00-00"), dbKey("2026-10-07", "18-00-00")];
    listing([...extras, ...dayKeys].reverse());

    await deleteOldBackups();

    // Del día 7 sólo sobrevive el de las 18:00 (el más nuevo); se van los otros tres.
    // Los días 1 a 6 no se tocan.
    assert.deepEqual(deletedKeys.sort(), [dayKeys[6], extras[0], extras[1]].sort());
    for (const key of dayKeys.slice(0, 6)) assert.ok(!deletedKeys.includes(key), `se borró ${key}`);
  });

  it("los JSON legados no desalojan snapshots .sqlite.gz", async () => {
    // Siete días de snapshots y siete de JSON legado: ninguno de los dos llega a su tope
    // de familia, así que no debe borrarse nada. Un pool único sí desalojaría.
    const dbDays = ["2026-10-01", "2026-10-02", "2026-10-03", "2026-10-04", "2026-10-05", "2026-10-06", "2026-10-07"];
    const legacyDays = ["2026-09-25", "2026-09-26", "2026-09-27", "2026-09-28", "2026-09-29", "2026-09-30", "2026-10-01"];
    listing([...dbDays.map((d) => dbKey(d)), ...legacyDays.map((d) => legacyKey(d))]);

    await deleteOldBackups();

    assert.deepEqual(deletedKeys, []);
  });

  it("conserva exactamente los 7 días más recientes de cada familia", async () => {
    // Diez días de snapshots (se borran los 3 más viejos) y nueve de JSON legado (se borran 2).
    const dbDays = Array.from({ length: 10 }, (_, i) => `2026-10-${String(i + 1).padStart(2, "0")}`);
    const legacyDays = Array.from({ length: 9 }, (_, i) => `2026-09-${String(i + 18).padStart(2, "0")}`);
    const dbKeys = dbDays.map((d) => dbKey(d));
    const legacyKeys = legacyDays.map((d) => legacyKey(d));
    listing([...dbKeys, ...legacyKeys].reverse());

    await deleteOldBackups();

    assert.deepEqual(
      deletedKeys.sort(),
      [...dbKeys.slice(0, 3), ...legacyKeys.slice(0, 2)].sort(),
    );
  });
});
