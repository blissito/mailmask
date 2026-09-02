// Reconciliación base vs SES. Un dominio puede estar verificado (la identidad
// existe) y aun así rebotar todo con 550 porque falta su regla de recepción:
// pasó con brendago.design cuando la fila revivió de un respaldo después de que
// el DELETE limpiara SES. `ensureDomainInbound` recrea la regla sólo si falta.

import { describe, it, before, mock } from "node:test";
import assert from "node:assert/strict";

const comandos: string[] = [];
let reglaExiste = false;

describe("ensureDomainInbound", () => {
  // deno-lint-ignore no-explicit-any
  let ensureDomainInbound: any;

  before(async () => {
    process.env.SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:1:test";
    mock.module("@aws-sdk/client-ses", {
      namedExports: {
        SESClient: class {
          // deno-lint-ignore no-explicit-any
          async send(cmd: any) {
            comandos.push(cmd.tipo);
            if (cmd.tipo === "DescribeReceiptRule" && !reglaExiste) {
              throw new Error("RuleDoesNotExistException: Rule does not exist");
            }
            if (cmd.tipo === "CreateReceiptRule") reglaExiste = true;
            if (cmd.tipo === "CreateConfigurationSet") {
              throw new Error("ConfigurationSetAlreadyExistsException: AlreadyExists");
            }
            return {};
          }
        },
        DescribeReceiptRuleCommand: class { tipo = "DescribeReceiptRule"; constructor(public input: any) {} },
        CreateReceiptRuleCommand: class { tipo = "CreateReceiptRule"; constructor(public input: any) {} },
        CreateConfigurationSetCommand: class { tipo = "CreateConfigurationSet"; constructor(public input: any) {} },
        CreateConfigurationSetEventDestinationCommand: class { tipo = "CreateEventDest"; constructor(public input: any) {} },
      },
    });
    ({ ensureDomainInbound } = await import("./ses.ts"));
  });

  it("recrea la regla cuando falta y tolera un config set ya existente", async () => {
    comandos.length = 0;
    reglaExiste = false;
    const r = await ensureDomainInbound("brendago.design");
    assert.equal(r.ruleCreated, true);
    assert.ok(comandos.includes("CreateReceiptRule"));
  });

  it("no toca la regla si ya existe", async () => {
    comandos.length = 0;
    reglaExiste = true;
    const r = await ensureDomainInbound("brendago.design");
    assert.equal(r.ruleCreated, false);
    assert.ok(!comandos.includes("CreateReceiptRule"));
  });
});
