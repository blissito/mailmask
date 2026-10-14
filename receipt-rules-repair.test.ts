// Reparación de reglas de recepción de SES. Sólo se reenvían a SES las reglas
// con una S3Action sin TopicArn, con el ARN configurado. Se dobla el cliente de SES
// (no ses.ts) para ver qué comandos manda y qué regla recibe cada UpdateReceiptRule.

import { describe, it, before, mock } from "node:test";
import assert from "node:assert/strict";

const TOPIC_ARN = "arn:aws:sns:us-east-1:1:inbound";
const RULE_SET = "test-rule-set";

// Estado del doble: las reglas que devuelve Describe y lo que llega a Update.
let sesRules: any[] | undefined;
let sentCommands: string[] = [];
let updatesReceived: any[] = [];

function reset(rules?: any[]) {
  sesRules = rules;
  sentCommands = [];
  updatesReceived = [];
}

// Regla tal como la devuelve SES: una S3Action sin TopicArn y una LambdaAction que no se toca.
function brokenRule(name: string) {
  return {
    Name: name,
    Enabled: true,
    Recipients: [`${name}@example.com`],
    Actions: [
      { S3Action: { BucketName: "mailmask-inbound", ObjectKeyPrefix: `${name}/` } },
      { LambdaAction: { FunctionArn: "arn:aws:lambda:us-east-1:1:function:x", InvocationType: "Event" } },
    ],
  };
}

// Regla ya reparada: su S3Action trae el TopicArn configurado.
function fixedRule(name: string) {
  return {
    Name: name,
    Enabled: true,
    Recipients: [`${name}@example.com`],
    Actions: [
      { S3Action: { BucketName: "mailmask-inbound", ObjectKeyPrefix: `${name}/`, TopicArn: TOPIC_ARN } },
    ],
  };
}

describe("repairReceiptRules", () => {
  // deno-lint-ignore no-explicit-any
  let repairReceiptRules: any;
  // deno-lint-ignore no-explicit-any
  let repairWithoutTopic: any;

  before(async () => {
    process.env.SES_RULE_SET = RULE_SET;
    process.env.SNS_TOPIC_ARN = TOPIC_ARN;
    const real = await import("@aws-sdk/client-ses");
    mock.module("@aws-sdk/client-ses", {
      namedExports: {
        ...real,
        SESClient: class {
          // deno-lint-ignore no-explicit-any
          async send(cmd: any) {
            sentCommands.push(cmd.kind);
            if (cmd.kind === "Describe") {
              // Copia: la función muta la regla in situ y el estado del doble no debe cambiar con ella.
              // Sin Rules: el caso 'no trae Rules' necesita que la respuesta venga sin la llave.
              return sesRules === undefined ? {} : { Rules: structuredClone(sesRules) };
            }
            updatesReceived.push(structuredClone(cmd.input));
            return {};
          }
        },
        DescribeReceiptRuleSetCommand: class { kind = "Describe"; constructor(public input: any) {} },
        UpdateReceiptRuleCommand: class { kind = "Update"; constructor(public input: any) {} },
      },
    });
    ({ repairReceiptRules } = await import("./ses.ts"));
    // SNS_TOPIC_ARN se lee al importar el módulo: el caso sin tópico usa una copia con la variable vacía.
    process.env.SNS_TOPIC_ARN = "";
    ({ repairReceiptRules: repairWithoutTopic } = await import(`./ses.ts?v=${Math.random()}`));
    process.env.SNS_TOPIC_ARN = TOPIC_ARN;
  });

  it("reenvía a SES una regla sin TopicArn con el ARN configurado y deja lo demás intacto", async () => {
    reset([brokenRule("uno")]);
    const n = await repairReceiptRules();
    assert.equal(n, 1);
    assert.equal(updatesReceived.length, 1);
    const sent = updatesReceived[0];
    assert.equal(sent.RuleSetName, RULE_SET);
    assert.equal(sent.Rule.Name, "uno");
    assert.equal(sent.Rule.Actions[0].S3Action.TopicArn, TOPIC_ARN);
    assert.equal(sent.Rule.Actions[0].S3Action.ObjectKeyPrefix, "uno/");
    assert.deepEqual(sent.Rule.Actions[1], brokenRule("uno").Actions[1]);
    assert.deepEqual(sent.Rule.Recipients, ["uno@example.com"]);
  });

  it("no reenvía a SES una regla que ya trae TopicArn", async () => {
    reset([fixedRule("ok")]);
    const n = await repairReceiptRules();
    assert.equal(n, 0);
    assert.equal(updatesReceived.length, 0);
  });

  it("sin SNS_TOPIC_ARN devuelve 0 y no llama a SES", async () => {
    reset([brokenRule("uno"), brokenRule("dos")]);
    const n = await repairWithoutTopic();
    assert.equal(n, 0);
    assert.deepEqual(sentCommands, []);
  });

  it("el conteo coincide con las reglas reparadas, contando cada regla una sola vez", async () => {
    const dosS3 = {
      Name: "dos-s3",
      Enabled: true,
      Recipients: ["dos-s3@example.com"],
      Actions: [
        { S3Action: { BucketName: "mailmask-inbound", ObjectKeyPrefix: "a/" } },
        { S3Action: { BucketName: "mailmask-inbound", ObjectKeyPrefix: "b/", TopicArn: "arn:aws:sns:us-east-1:1:otro" } },
      ],
    };
    const tresS3 = {
          Name: "tres-s3",
          Enabled: true,
          Recipients: ["tres-s3@example.com"],
          Actions: [
            { S3Action: { BucketName: "mailmask-inbound", ObjectKeyPrefix: "c/" } },
            { S3Action: { BucketName: "mailmask-inbound", ObjectKeyPrefix: "d/" } },
          ],
        };
        reset([brokenRule("a"), fixedRule("b"), dosS3, tresS3]);
    const n = await repairReceiptRules();
    assert.equal(n, 3);
    assert.deepEqual(updatesReceived.map((u) => u.Rule.Name), ["a", "dos-s3", "tres-s3"]);
    // La S3Action que ya tenía su TopicArn conserva el suyo: no se pisa.
    assert.equal(updatesReceived[1].Rule.Actions[1].S3Action.TopicArn, "arn:aws:sns:us-east-1:1:otro");
    assert.equal(updatesReceived[1].Rule.Actions[0].S3Action.TopicArn, TOPIC_ARN);
    assert.equal(updatesReceived[2].Rule.Actions[0].S3Action.TopicArn, TOPIC_ARN);
    assert.equal(updatesReceived[2].Rule.Actions[1].S3Action.TopicArn, TOPIC_ARN);
  });

  it("no toca una regla sin S3Action (sólo Lambda)", async () => {
    const soloLambda = {
      Name: "solo-lambda",
      Enabled: true,
      Recipients: ["solo-lambda@example.com"],
      Actions: [{ LambdaAction: { FunctionArn: "arn:aws:lambda:us-east-1:1:function:x", InvocationType: "Event" } }],
    };
    reset([soloLambda]);
    const n = await repairReceiptRules();
    assert.equal(n, 0);
    assert.equal(updatesReceived.length, 0);
  });

  it("devuelve 0 cuando el conjunto de reglas no trae Rules", async () => {
    reset(undefined);
    const n = await repairReceiptRules();
    assert.equal(n, 0);
    assert.equal(updatesReceived.length, 0);
  });
});
