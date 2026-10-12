// `plans.ts` es la tabla de precios en código y vive fuera de `db.ts` justo para poder
// probarse sin abrir SQLite. Nadie cubría `addonPriceCents`, `addonLabel`, `planPriceCents`
// ni `isLegacyPlan`, y la lista de lo que el CLI puede comprar (`BILLING_KINDS`, en
// `cli/src/args.ts`) podía desfasarse en silencio del catálogo del servidor
// (`ADDONS_FOR_SALE`, en `plans.ts`).
//
// No repite lo que ya fijan otras pruebas: `planLabel` está en `orders.test.ts` y el precio
// de `ADDONS_FOR_SALE` en `addons.test.ts`. Aquí van los bordes —legado, desconocido y
// nulo— y el contrato con el CLI.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  ADDONS,
  ADDONS_FOR_SALE,
  LEGACY_ADDONS,
  PLANS,
  addonLabel,
  addonPriceCents,
  isLegacyPlan,
  planPriceCents,
} from "./plans.ts";

const leer = (ruta: string) => readFileSync(new URL(ruta, import.meta.url), "utf8");

describe("addonPriceCents: precio de cualquier add-on, vigente o legado", () => {
  it("los vigentes cobran el precio del catálogo", () => {
    for (const kind of ADDONS_FOR_SALE) {
      assert.equal(addonPriceCents(kind), ADDONS[kind].price, `${kind} no devolvió su precio`);
    }
  });

  it("los legados siguen cobrando aunque ya no se vendan", () => {
    // El catálogo de antes del 7-sep-2026 se respeta para quien lo tiene contratado.
    assert.equal(addonPriceCents("sends25"), LEGACY_ADDONS.sends25.price);
    assert.equal(addonPriceCents("mailbox"), LEGACY_ADDONS.mailbox.price);
  });

  it("un add-on desconocido no tiene precio", () => {
    assert.equal(addonPriceCents("cortesia_2027"), null);
    assert.equal(addonPriceCents(""), null);
  });
});

describe("addonLabel: etiqueta de cualquier cosa cobrable", () => {
  it("nombra los vigentes y los legados", () => {
    assert.equal(addonLabel("domain"), ADDONS.domain.label);
    assert.equal(addonLabel("sends25"), "Envíos 25/día");
    assert.equal(addonLabel("mailbox"), "Buzón IMAP 10 GB");
  });

  it("un add-on sin etiqueta cae a su propia llave, sin inventarla", () => {
    // `kind` no se valida a propósito: una cortesía que se invente mañana tiene que poder
    // etiquetarse hoy, aunque sea con su llave cruda.
    assert.equal(addonLabel("cortesia_2027"), "cortesia_2027");
  });
});

describe("planPriceCents: los planes que ya no se venden", () => {
  it("un plan del catálogo conserva su precio para las suscripciones viejas", () => {
    assert.equal(planPriceCents("basico"), PLANS.basico.price);
  });

  it("nulo, vacío o desconocido cuestan 0", () => {
    for (const plan of [null, undefined, "", "garbage"]) {
      assert.equal(planPriceCents(plan), 0, `${String(plan)} no costó 0`);
    }
  });
});

describe("isLegacyPlan: sólo los cuatro planes retirados son legado", () => {
  it("marca los retirados", () => {
    for (const plan of ["freelancer", "developer", "pro", "agencia"]) {
      assert.equal(isLegacyPlan(plan), true, `${plan} no se marcó como legado`);
    }
  });

  it("los vigentes y lo vacío no son legado", () => {
    for (const plan of ["basico", "equipo", null, undefined, ""]) {
      assert.equal(isLegacyPlan(plan), false, `${String(plan)} se marcó como legado`);
    }
  });
});

describe("contrato con el CLI: lo que se puede comprar es lo que el servidor vende", () => {
  /**
   * `BILLING_KINDS` de `cli/src/args.ts`, leída como TEXTO: importar el archivo arrastraría
   * `@easybits.cloud/mailmask`, que no está en el root y `tsc` daría TS2307. Se lee el fuente
   * y se extrae con regex, como `docs-cli.test.ts` lee los comandos de la CLI.
   */
  function billingKindsDelCli(): string[] {
    const src = leer("./cli/src/args.ts");
    const match = src.match(/export const BILLING_KINDS\s*=\s*\[([^\]]*)\]\s*as const/);
    assert.ok(match, "no se encontró `BILLING_KINDS = [...] as const` en cli/src/args.ts: ¿cambió de forma?");
    const kinds = [...match[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
    assert.ok(kinds.length > 0, "BILLING_KINDS salió vacía: esta prueba no vigilaría nada");
    return kinds;
  }

  it("el CLI no vende nada que el servidor no venda, ni al revés", () => {
    assert.deepEqual(billingKindsDelCli(), [...ADDONS_FOR_SALE]);
  });
});
