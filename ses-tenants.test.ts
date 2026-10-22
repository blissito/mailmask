// SES Tenants: cada dominio de cliente con su tenant para que la reputación de uno no
// pause a todos. Se simulan los dos SDK (v1 y sesv2) porque el envío con tenant va por
// sesv2 y el de siempre —y el respaldo— por v1. Lo que importa fijar: que el tenant se
// asegura sin duplicarse, que el MIME no cambia de camino, que sin bandera sesv2 ni se
// toca y que un fallo del tenant no pierde el correo.

import { describe, it, before, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";

// deno-lint-ignore no-explicit-any
type Cmd = { tipo: string; input: any };
const v1: Cmd[] = [];
const v2: Cmd[] = [];
const tenants = new Map<string, string>(); // nombre → arn
const associations = new Set<string>();
// deno-lint-ignore no-explicit-any
let sendEmailFailure: any = null;

function awsError(name: string): Error {
  const err = new Error(`${name}: simulated`);
  err.name = name;
  return err;
}

// deno-lint-ignore no-explicit-any
const cmdClass = (tipo: string) => class { tipo = tipo; constructor(public input: any) {} };

describe("SES Tenants", () => {
  // deno-lint-ignore no-explicit-any
  let ses: any;

  before(async () => {
    process.env.SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:1:test";
    process.env.SNS_OUTBOUND_TOPIC_ARN = "arn:aws:sns:us-east-1:1:out";
    mock.module("@aws-sdk/client-ses", {
      namedExports: {
        SESClient: class {
          // deno-lint-ignore no-explicit-any
          async send(cmd: any) {
            v1.push({ tipo: cmd.tipo, input: cmd.input });
            if (cmd.tipo === "CreateConfigurationSet" || cmd.tipo === "CreateEventDest") {
              throw awsError("AlreadyExistsException");
            }
            if (cmd.tipo === "SendRawEmail") return { MessageId: "v1-id" };
            return {};
          }
        },
        SendRawEmailCommand: cmdClass("SendRawEmail"),
        DescribeReceiptRuleCommand: cmdClass("DescribeReceiptRule"),
        CreateReceiptRuleCommand: cmdClass("CreateReceiptRule"),
        CreateConfigurationSetCommand: cmdClass("CreateConfigurationSet"),
        CreateConfigurationSetEventDestinationCommand: cmdClass("CreateEventDest"),
      },
    });
    mock.module("@aws-sdk/client-sesv2", {
      namedExports: {
        SESv2Client: class {
          // deno-lint-ignore no-explicit-any
          async send(cmd: any) {
            v2.push({ tipo: cmd.tipo, input: cmd.input });
            const name = cmd.input?.TenantName;
            switch (cmd.tipo) {
              case "CreateTenant": {
                if (tenants.has(name)) throw awsError("AlreadyExistsException");
                const arn = `arn:aws:ses:us-east-1:123456789012:tenant/${name}/t-1`;
                tenants.set(name, arn);
                return { TenantName: name, TenantArn: arn };
              }
              case "GetTenant":
                if (!tenants.has(name)) throw awsError("NotFoundException");
                return { Tenant: { TenantName: name, TenantArn: tenants.get(name) } };
              case "CreateTenantResourceAssociation": {
                const key = `${name}|${cmd.input.ResourceArn}`;
                if (associations.has(key)) throw awsError("AlreadyExistsException");
                associations.add(key);
                return {};
              }
              case "SendEmail":
                if (sendEmailFailure) throw sendEmailFailure;
                return { MessageId: "v2-id" };
            }
            return {};
          }
        },
        CreateTenantCommand: cmdClass("CreateTenant"),
        GetTenantCommand: cmdClass("GetTenant"),
        CreateTenantResourceAssociationCommand: cmdClass("CreateTenantResourceAssociation"),
        DeleteTenantResourceAssociationCommand: cmdClass("DeleteTenantResourceAssociation"),
        DeleteTenantCommand: cmdClass("DeleteTenant"),
        SendEmailCommand: cmdClass("SendEmail"),
      },
    });
    ses = await import("./ses.ts");
  });

  beforeEach(() => {
    v1.length = 0;
    v2.length = 0;
    sendEmailFailure = null;
    process.env.SES_TENANTS = "1";
  });

  describe("tenantNameFor", () => {
    it("da un nombre válido para la API, estable y sin choques entre dominios con guiones", () => {
      const a = ses.tenantNameFor("a-b.com");
      assert.equal(a, "mailmask-a-b_com");
      assert.notEqual(a, ses.tenantNameFor("a.b-com"));
      assert.equal(ses.tenantNameFor("Kandey.COM.mx"), "mailmask-kandey_com_mx");
      assert.equal(ses.tenantNameFor("kandey.com.mx"), ses.tenantNameFor("kandey.com.mx"));
    });

    it("recorta los dominios largos a 64 con un hash que los distingue", () => {
      const long1 = `${"x".repeat(60)}.uno.com`;
      const long2 = `${"x".repeat(60)}.dos.com`;
      const n1 = ses.tenantNameFor(long1);
      assert.ok(n1.length <= 64);
      assert.match(n1, /^[A-Za-z0-9_-]+$/);
      assert.notEqual(n1, ses.tenantNameFor(long2));
      assert.equal(n1, ses.tenantNameFor(long1));
    });
  });

  describe("ensureDomainTenant", () => {
    it("crea el tenant y asocia identidad, config set del dominio y el de reenvío", async () => {
      const r = await ses.ensureDomainTenant("brendago.design");
      assert.equal(r.tenantName, "mailmask-brendago_design");
      assert.equal(r.created, true);
      assert.equal(r.associated, 3);
      const arns = v2.filter((c) => c.tipo === "CreateTenantResourceAssociation").map((c) => c.input.ResourceArn);
      assert.deepEqual(arns, [
        "arn:aws:ses:us-east-1:123456789012:identity/brendago.design",
        "arn:aws:ses:us-east-1:123456789012:configuration-set/mailmask-brendago-design",
        "arn:aws:ses:us-east-1:123456789012:configuration-set/mailmask-forwarding",
      ]);
    });

    it("es idempotente: la segunda corrida no crea otro tenant ni falla", async () => {
      await ses.ensureDomainTenant("idem.com");
      v2.length = 0;
      const r = await ses.ensureDomainTenant("idem.com");
      assert.equal(r.created, false);
      assert.equal(r.associated, 0);
      assert.equal(r.tenantName, "mailmask-idem_com");
      // Mismo nombre en las dos llamadas: nada de Date.now() en el nombre.
      const names = new Set(v2.filter((c) => c.input?.TenantName).map((c) => c.input.TenantName));
      assert.deepEqual([...names], ["mailmask-idem_com"]);
      assert.equal([...tenants.keys()].filter((k) => k === "mailmask-idem_com").length, 1);
    });

    it("la reconciliación (ensureDomainInbound) lo asegura sólo con la bandera", async () => {
      await ses.ensureDomainInbound("reconcilia.com");
      assert.ok(v2.some((c) => c.tipo === "CreateTenant" && c.input.TenantName === "mailmask-reconcilia_com"));

      delete process.env.SES_TENANTS;
      v2.length = 0;
      await ses.ensureDomainInbound("otro.com");
      assert.equal(v2.length, 0);
    });
  });

  describe("envío", () => {
    const opts = (domain: string) => ({ configSet: ses.getConfigSetName(domain), bcc: ["oculto@example.com"], cc: ["copia@example.com"] });

    it("con la bandera sale por sesv2 con TenantName y el MIME idéntico al que se arma", async () => {
      const sent = await ses.sendFromDomain("hola@cliente.com", "dest@example.com", "Cotización", "cuerpo", opts("cliente.com"));
      assert.equal(sent.sesMessageId, "v2-id");
      assert.ok(sent.messageId.endsWith("@cliente.com>"));
      const send = v2.find((c) => c.tipo === "SendEmail");
      assert.ok(send);
      assert.equal(send!.input.TenantName, "mailmask-cliente_com");
      assert.equal(send!.input.ConfigurationSetName, "mailmask-cliente-com");
      assert.equal(send!.input.FromEmailAddress, "hola@cliente.com");
      assert.deepEqual(send!.input.Destination.ToAddresses, ["dest@example.com", "copia@example.com", "oculto@example.com"]);
      const raw = new TextDecoder().decode(send!.input.Content.Raw.Data);
      assert.equal(raw, sent.raw);
      assert.match(raw, new RegExp(`Message-ID: ${sent.messageId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
      assert.doesNotMatch(raw, /^Bcc:/mi);
      assert.equal(v1.filter((c) => c.tipo === "SendRawEmail").length, 0);
    });

    it("sin la bandera no toca sesv2 y sale por SendRawEmail como siempre", async () => {
      delete process.env.SES_TENANTS;
      const sent = await ses.sendFromDomain("hola@cliente.com", "dest@example.com", "Hola", "cuerpo", opts("cliente.com"));
      assert.equal(v2.length, 0);
      assert.equal(sent.sesMessageId, "v1-id");
      const raw1 = v1.find((c) => c.tipo === "SendRawEmail")!;
      assert.equal(raw1.input.ConfigurationSetName, "mailmask-cliente-com");
      assert.equal(new TextDecoder().decode(raw1.input.RawMessage.Data), sent.raw);
    });

    it("si el envío con tenant falla, cae a v1 con el mismo MIME y no pierde el correo", async () => {
      sendEmailFailure = awsError("NotFoundException");
      const sent = await ses.sendFromDomain("hola@cliente.com", "dest@example.com", "Hola", "cuerpo", opts("cliente.com"));
      assert.equal(sent.sesMessageId, "v1-id");
      const raw1 = v1.find((c) => c.tipo === "SendRawEmail")!;
      assert.equal(new TextDecoder().decode(raw1.input.RawMessage.Data), sent.raw);
      assert.deepEqual(raw1.input.Destinations, ["dest@example.com", "copia@example.com", "oculto@example.com"]);
    });

    it("un tenant pausado NO se salta por v1: el error sube", async () => {
      sendEmailFailure = awsError("SendingPausedException");
      await assert.rejects(
        ses.sendFromDomain("hola@cliente.com", "dest@example.com", "Hola", "cuerpo", opts("cliente.com")),
        /SendingPaused/,
      );
      assert.equal(v1.filter((c) => c.tipo === "SendRawEmail").length, 0);
    });

    it("el transaccional (sin config set del dominio) sale sin tenant aunque haya bandera", async () => {
      await ses.sendFromDomain("MailMask <noreply@mailmask.studio>", "user@example.com", "Recibo", "cuerpo");
      assert.equal(v2.length, 0);
      assert.equal(v1.filter((c) => c.tipo === "SendRawEmail").length, 1);
    });

    it("sendRawFromDomain (Apple Mail vía relay) lleva tenant y el MIME intacto", async () => {
      const raw = "From: buzon@cliente.com\r\nTo: x@example.com\r\nSubject: hi\r\nMessage-ID: <abc@cliente.com>\r\n\r\ncuerpo";
      const id = await ses.sendRawFromDomain(raw, "buzon@cliente.com", ["x@example.com"], ses.getConfigSetName("cliente.com"));
      assert.equal(id, "v2-id");
      const send = v2.find((c) => c.tipo === "SendEmail")!;
      assert.equal(send.input.TenantName, "mailmask-cliente_com");
      assert.equal(new TextDecoder().decode(send.input.Content.Raw.Data), raw);
    });

    it("el reenvío va en el tenant de la máscara con el config set compartido de reenvío", async () => {
      const original = "From: alguien@gmail.com\r\nTo: hola@cliente.com\r\nSubject: hola\r\n\r\ncuerpo";
      await ses.forwardEmail(original, "alguien@gmail.com", "dueno@gmail.com", "cliente.com");
      const send = v2.find((c) => c.tipo === "SendEmail")!;
      assert.equal(send.input.TenantName, "mailmask-cliente_com");
      assert.equal(send.input.ConfigurationSetName, "mailmask-forwarding");
      assert.equal(send.input.FromEmailAddress, "reenvio@cliente.com");
      assert.deepEqual(send.input.Destination.ToAddresses, ["dueno@gmail.com"]);
      assert.equal(v1.filter((c) => c.tipo === "SendRawEmail").length, 0);
    });

    it("SES_TENANTS_DOMAINS lo enciende sólo para los dominios de la lista", async () => {
      delete process.env.SES_TENANTS;
      process.env.SES_TENANTS_DOMAINS = " Fixter.org , otro.com ";
      try {
        assert.equal(ses.sesTenantsEnabled("fixter.org"), true);
        assert.equal(ses.sesTenantsEnabled("cliente.com"), false);
        assert.equal(ses.sesTenantsEnabled(), false);
        await ses.forwardEmail("From: a@b.com\r\nSubject: x\r\n\r\ny", "a@b.com", "dueno@gmail.com", "fixter.org");
        assert.equal(v2.find((c) => c.tipo === "SendEmail")!.input.TenantName, "mailmask-fixter_org");
        v2.length = 0;
        await ses.forwardEmail("From: a@b.com\r\nSubject: x\r\n\r\ny", "a@b.com", "dueno@gmail.com", "cliente.com");
        assert.equal(v2.length, 0, "un dominio fuera de la lista no va por tenant");
        // Vacía: manda la bandera global.
        process.env.SES_TENANTS_DOMAINS = "";
        process.env.SES_TENANTS = "1";
        assert.equal(ses.sesTenantsEnabled("cliente.com"), true);
      } finally {
        delete process.env.SES_TENANTS_DOMAINS;
      }
    });

    it("el reenvío sin bandera no cambia: SendRawEmail sin config set", async () => {
      delete process.env.SES_TENANTS;
      await ses.forwardEmail("From: a@b.com\r\nSubject: x\r\n\r\ny", "a@b.com", "dueno@gmail.com", "cliente.com");
      assert.equal(v2.length, 0);
      const raw1 = v1.find((c) => c.tipo === "SendRawEmail")!;
      assert.equal(raw1.input.ConfigurationSetName, undefined);
    });
  });
});
