import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { zipSync, strToU8 } from "fflate";
import { eq, gte } from "drizzle-orm";

import { processInbound } from "./forwarding.ts";
import {
  parseDmarcXml, extractXmlFromAttachment, ingestDmarcReport, saveDmarcReport, computeDmarcDigest,
} from "./dmarc-reports.ts";
import { dmarcWeeklyDigest } from "./emails.ts";
import { createUser, createDomain, updateDomain, createAlias, listConversations, isMessageProcessed } from "./db.ts";
import { hashPassword } from "./auth.ts";
import { db } from "./pg.ts";
import { dmarcReports, dmarcRecords } from "./schema.ts";

const suffix = `dmarc-${Date.now()}`;
const ourDomain = `${suffix}.test`;
const clientDomain = `cliente-${suffix}.test`;

function googleXml(reportId: string, domain = ourDomain): string {
  return `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <extra_contact_info>https://support.google.com/a/answer/2466580</extra_contact_info>
    <report_id>${reportId}</report_id>
    <date_range><begin>1790985600</begin><end>1791071999</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>${domain}</domain><adkim>r</adkim><aspf>r</aspf><p>none</p><sp>none</sp><pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>54.240.8.1</source_ip>
      <count>40</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>${domain}</header_from></identifiers>
    <auth_results>
      <dkim><domain>${domain}</domain><result>pass</result><selector>abc</selector></dkim>
      <dkim><domain>amazonses.com</domain><result>pass</result><selector>xyz</selector></dkim>
      <spf><domain>amazonses.com</domain><result>pass</result></spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>203.0.113.9</source_ip>
      <count>3</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>${domain}</header_from></identifiers>
    <auth_results>
      <spf><domain>spammer.example</domain><result>softfail</result></spf>
    </auth_results>
  </record>
</feedback>`;
}

function microsoftXml(reportId: string): string {
  return `<?xml version="1.0"?>
<feedback xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <version>1.0</version>
  <report_metadata>
    <org_name>Enterprise Outlook</org_name>
    <email>dmarcreport@microsoft.com</email>
    <report_id>${reportId}</report_id>
    <date_range><begin>1790985600</begin><end>1791072000</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>${ourDomain}</domain><adkim>r</adkim><aspf>r</aspf><p>none</p><sp>none</sp><pct>100</pct><fo>1</fo>
  </policy_published>
  <record>
    <row>
      <source_ip>54.240.8.2</source_ip>
      <count>7</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><envelope_to>outlook.com</envelope_to><envelope_from>amazonses.com</envelope_from><header_from>${ourDomain}</header_from></identifiers>
    <auth_results>
      <dkim><domain>${ourDomain}</domain><selector>abc</selector><result>pass</result></dkim>
      <spf><domain>amazonses.com</domain><scope>mfrom</scope><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>`;
}

/** Correo MIME con un adjunto binario, como los que mandan los reporteros. */
function mimeWithAttachment(opts: { to: string; filename: string; mime: string; content: Uint8Array; messageId: string }): string {
  const b64 = Buffer.from(opts.content).toString("base64").replace(/(.{76})/g, "$1\r\n");
  return [
    "From: noreply-dmarc-support@google.com",
    `To: ${opts.to}`,
    `Subject: Report domain: ${ourDomain} Submitter: google.com`,
    `Message-ID: <${opts.messageId}@google.com>`,
    "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="b1"',
    "",
    "--b1",
    "Content-Type: text/plain; charset=UTF-8",
    "",
    "This is an aggregate report.",
    "--b1",
    `Content-Type: ${opts.mime}; name="${opts.filename}"`,
    `Content-Disposition: attachment; filename="${opts.filename}"`,
    "Content-Transfer-Encoding: base64",
    "",
    b64,
    "--b1--",
    "",
  ].join("\r\n");
}

function sns(to: string, raw: string, messageId: string) {
  return {
    Type: "Notification",
    MessageId: messageId,
    TopicArn: "arn:aws:sns:us-east-1:123456:test",
    Message: JSON.stringify({
      notificationType: "Received",
      receipt: {
        action: { type: "S3", bucketName: "test-bucket", objectKey: "test-key" },
        recipients: [to],
        spamVerdict: { status: "PASS" },
        virusVerdict: { status: "PASS" },
        spfVerdict: { status: "PASS" },
        dkimVerdict: { status: "PASS" },
        dmarcVerdict: { status: "PASS" },
      },
      mail: {
        source: "noreply-dmarc-support@google.com",
        destination: [to],
        commonHeaders: { from: ["noreply-dmarc-support@google.com"], to: [to], subject: "Report" },
        messageId,
      },
      content: raw,
    }),
  };
}

function reportRows(reportId: string) {
  return db.select().from(dmarcReports).where(eq(dmarcReports.reportId, reportId)).all();
}

const prevAddress = process.env.DMARC_REPORT_ADDRESS;
let ourDomainId: string;
let clientDomainId: string;

describe("reportes DMARC", () => {
  before(async () => {
    process.env.DMARC_REPORT_ADDRESS = `dmarc@${ourDomain}`;
    const owner = `owner-${suffix}@example.com`;
    createUser(owner, await hashPassword("testpass123"));
    const d1 = createDomain(owner, ourDomain, ["dkim1"], "v1");
    updateDomain(d1.id, { verified: true });
    ourDomainId = d1.id;
    const d2 = createDomain(owner, clientDomain, ["dkim2"], "v2");
    updateDomain(d2.id, { verified: true });
    clientDomainId = d2.id;
    createAlias(d2.id, "dmarc", ["dest@example.com"]);
  });

  after(() => {
    if (prevAddress === undefined) delete process.env.DMARC_REPORT_ADDRESS;
    else process.env.DMARC_REPORT_ADDRESS = prevAddress;
  });

  it("parsea el XML de Google: metadatos, records y auth_results", () => {
    const r = parseDmarcXml(googleXml("12345678901234567890"));
    assert.equal(r.orgName, "google.com");
    // Sin parseTagValue el id largo no pierde precisión.
    assert.equal(r.reportId, "12345678901234567890");
    assert.equal(r.domain, ourDomain);
    assert.equal(r.policy, "none");
    assert.equal(r.records.length, 2);
    assert.deepEqual(r.records[0], {
      sourceIp: "54.240.8.1", count: 40, disposition: "none", dkimPass: true, spfPass: true,
      headerFrom: ourDomain, dkimDomain: ourDomain, spfDomain: "amazonses.com",
    });
    assert.equal(r.records[1].dkimPass, false);
    assert.equal(r.records[1].dkimDomain, null);
  });

  it("descomprime .zip (Google) y .gz (Microsoft)", () => {
    const zip = zipSync({ "google.com!x!1!2.xml": strToU8(googleXml("z1")) });
    const fromZip = extractXmlFromAttachment("google.com!x.zip", "application/zip", zip);
    assert.equal(parseDmarcXml(fromZip[0]).reportId, "z1");

    const gz = gzipSync(microsoftXml("g1"));
    const fromGz = extractXmlFromAttachment("enterprise.protection.outlook.com!x.xml.gz", "application/gzip", gz);
    assert.equal(parseDmarcXml(fromGz[0]).orgName, "Enterprise Outlook");
  });

  it("rechaza un zip bomb y un gz bomb", () => {
    const big = new Uint8Array(25 * 1024 * 1024); // ceros: comprime a casi nada
    const zip = zipSync({ "bomb.xml": big }, { level: 9 });
    assert.ok(zip.byteLength < 5 * 1024 * 1024);
    assert.throws(() => extractXmlFromAttachment("bomb.zip", "application/zip", zip), /descomprime/);
    const gz = gzipSync(big, { level: 9 });
    assert.throws(() => extractXmlFromAttachment("bomb.xml.gz", "application/gzip", gz));
  });

  it("un reporte duplicado no se duplica", async () => {
    const id = `dup-${suffix}`;
    const raw = mimeWithAttachment({
      to: `dmarc@${ourDomain}`, filename: "r.zip", mime: "application/zip",
      content: zipSync({ "r.xml": strToU8(googleXml(id)) }), messageId: `m-${id}`,
    });
    const first = await ingestDmarcReport(raw);
    const second = await ingestDmarcReport(raw);
    assert.equal(first.saved, 1);
    assert.equal(second.saved, 0);
    assert.equal(second.duplicates, 1);
    const rows = reportRows(id);
    assert.equal(rows.length, 1);
    const recs = db.select().from(dmarcRecords).where(eq(dmarcRecords.reportId, rows[0].id)).all();
    assert.equal(recs.length, 2);
  });

  it("processInbound al rua guarda el reporte y no crea conversación", async () => {
    const id = `inb-${suffix}`;
    const msgId = `dmarc-inb-${crypto.randomUUID()}`;
    const raw = mimeWithAttachment({
      to: `dmarc@${ourDomain}`, filename: "r.xml.gz", mime: "application/gzip",
      content: gzipSync(googleXml(id)), messageId: msgId,
    });
    const result = await processInbound(sns(`dmarc@${ourDomain}`, raw, msgId) as any);
    assert.equal(result.action, "processed");
    assert.equal(reportRows(id).length, 1);
    assert.equal(listConversations(ourDomainId).length, 0);
    assert.equal(isMessageProcessed(msgId), true);
  });

  it("XML basura no tumba el inbound", async () => {
    const msgId = `dmarc-junk-${crypto.randomUUID()}`;
    const raw = mimeWithAttachment({
      to: `dmarc@${ourDomain}`, filename: "r.xml", mime: "text/xml",
      content: strToU8("<html><not-dmarc/>"), messageId: msgId,
    });
    const result = await processInbound(sns(`dmarc@${ourDomain}`, raw, msgId) as any);
    assert.equal(result.action, "processed");
    assert.equal(listConversations(ourDomainId).length, 0);
  });

  it("dmarc@ de un cliente sigue el camino normal", async () => {
    const id = `cli-${suffix}`;
    const msgId = `dmarc-cli-${crypto.randomUUID()}`;
    const raw = mimeWithAttachment({
      to: `dmarc@${clientDomain}`, filename: "r.xml.gz", mime: "application/gzip",
      content: gzipSync(googleXml(id, clientDomain)), messageId: msgId,
    });
    await processInbound(sns(`dmarc@${clientDomain}`, raw, msgId) as any);
    assert.equal(reportRows(id).length, 0);
    assert.equal(listConversations(clientDomainId).length, 1);
  });
});

describe("resumen DMARC semanal", () => {
  // Una semana en el futuro lejano para no mezclarse con lo que sembraron otras pruebas.
  const now = new Date("2031-03-10T15:00:00Z");
  const day = 86400_000;
  const lookup = async (ip: string) => (ip.startsWith("54.240.") ? `a8-1.smtp-out.amazonses.com` : null);

  // La base de pruebas persiste entre corridas: se limpia lo sembrado en 2031.
  before(() => {
    db.delete(dmarcReports).where(gte(dmarcReports.receivedAt, "2031-01-01")).run();
  });

  it("sin reportes dice que no llegó nada", async () => {
    const d = await computeDmarcDigest(new Date("2031-01-05T15:00:00Z"), lookup);
    assert.equal(d.reports, 0);
    const email = dmarcWeeklyDigest(d);
    assert.match(email.subject, /no llegó ningún reporte/);
    assert.match(email.text, /rua/);
  });

  it("arma el correo con lo que falló y no da luz verde sin semana previa", async () => {
    const r = parseDmarcXml(googleXml(`dig-${suffix}`));
    saveDmarcReport(r, new Date(now.getTime() - 2 * day).toISOString());
    const d = await computeDmarcDigest(now, lookup);
    assert.equal(d.reports, 1);
    assert.equal(d.total, 43);
    assert.equal(d.passed, 40);
    assert.equal(d.alignedPct, 93);
    assert.equal(d.failing.length, 1);
    assert.equal(d.failing[0].sourceIp, "203.0.113.9");
    assert.equal(d.sources[0].known, "SES (nosotros)");
    assert.equal(d.readyForQuarantine, false);
    const email = dmarcWeeklyDigest(d);
    assert.match(email.html, /203\.0\.113\.9/);
    assert.match(email.text, /Lo que falló DMARC/);
    assert.match(email.text, /Todavía no para quarantine/);
  });

  it("dos semanas ≥ 99% alineado y sin fuentes nuestras fallando → listo para quarantine", async () => {
    const t = new Date("2031-06-10T15:00:00Z");
    const clean = (id: string) => {
      const r = parseDmarcXml(googleXml(id));
      return { ...r, records: [r.records[0]] };
    };
    saveDmarcReport(clean(`ok1-${suffix}`), new Date(t.getTime() - 9 * day).toISOString());
    saveDmarcReport(clean(`ok2-${suffix}`), new Date(t.getTime() - 2 * day).toISOString());
    const d = await computeDmarcDigest(t, lookup);
    assert.equal(d.alignedPct, 100);
    assert.equal(d.previousAlignedPct, 100);
    assert.equal(d.readyForQuarantine, true);
    assert.match(dmarcWeeklyDigest(d).text, /Listo para quarantine/);
  });
});
