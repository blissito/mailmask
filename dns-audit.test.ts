import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { auditDnsRecords, isPrivateIp, type AuditDeps } from "./dns-audit.ts";
import type { RRSetAnotado } from "./dns-records.ts";

const apex = "fixter.org";
const rr = (name: string, type: string, values: string[], managed = false) =>
  ({ name, type, ttl: 300, values, managed, editable: !managed }) as unknown as RRSetAnotado;

function deps(over: Partial<AuditDeps> = {}): AuditDeps & { probed: string[] } {
  const probed: string[] = [];
  return {
    probed,
    resolve4: async (h) => {
      if (h.endsWith("elasticbeanstalk.com")) throw Object.assign(new Error("nx"), { code: "ENOTFOUND" });
      return ["203.0.113.10"];
    },
    resolveCname: async () => [],
    httpGet: async (url) => url.includes("pelusina") ? { status: 404, body: "There's nothing here, yet." } : { status: 200, body: "ok" },
    tcpOpen: async (ip) => { probed.push(ip); return ip === "203.0.113.10"; },
    ...over,
  };
}

describe("auditDnsRecords", () => {
  it("clasifica el caso de fixter.org", async () => {
    const records = [
      rr(apex, "MX", ["1 aspmx.l.google.com"]),
      rr(apex, "NS", ["ns-1.awsdns-1.org"]),
      rr(`pelusina.${apex}`, "CNAME", ["still-harbor-68517.herokuapp.com"]),
      rr(`rocket.${apex}`, "CNAME", ["rocketfund.us-east-2.elasticbeanstalk.com"]),
      rr(`s1._domainkey.${apex}.${apex}`, "CNAME", ["s1.domainkey.u1.wl1.sendgrid.net"]),
      rr(`s1._domainkey.${apex}`, "CNAME", ["s1.domainkey.u1.wl1.sendgrid.net"]),
      rr(`_domainconnect.${apex}`, "CNAME", ["_domainconnect.gd.domaincontrol.com"]),
      rr(`_83122ec3df556c8c94311369176322e9.rocket.${apex}`, "CNAME", ["_x.tljzshvwok.acm-validations.aws"]),
      rr(`_655120f33fb3ab717c2daf7a8195f395.test.${apex}`, "CNAME", ["_y.tljzshvwok.acm-validations.aws"]),
      rr(`blog.${apex}`, "A", ["198.51.100.7"]),
      rr(`www.${apex}`, "A", ["203.0.113.10"]),
      rr(`_amazonses.${apex}`, "TXT", ["x"], true),
    ];
    const a = await auditDnsRecords({ domain: apex, dnsPreviousNs: ["ns15.domaincontrol.com"] }, records, deps());
    const v = Object.fromEntries(a.findings.map((f) => [`${f.name}|${f.type}`, f.verdict]));
    assert.equal(v[`pelusina.${apex}|CNAME`], "takeover_risk");
    assert.equal(v[`rocket.${apex}|CNAME`], "takeover_risk");
    assert.equal(v[`s1._domainkey.${apex}.${apex}|CNAME`], "duplicated_name");
    assert.equal(v[`s1._domainkey.${apex}|CNAME`], "keep");
    assert.equal(v[`_domainconnect.${apex}|CNAME`], "previous_provider");
    assert.equal(v[`blog.${apex}|A`], "not_responding");
    assert.equal(v[`www.${apex}|A`], "in_use");
    assert.equal(v[`${apex}|MX`], "keep");
    assert.ok(!(`${apex}|NS` in v), "el NS de la raíz no se audita");
    assert.ok(!(`_amazonses.${apex}|TXT` in v), "los gestionados no se auditan");
    const cert = a.findings.filter((f) => f.verdict === "cert_validation");
    assert.equal(cert.find((f) => f.name.includes(".rocket."))!.action, "Déjalo mientras uses ese certificado.");
    assert.equal(cert.find((f) => f.name.includes(".test."))!.action, "Bórralo.");
    assert.equal(a.findings[0].verdict, "takeover_risk", "lo urgente primero");
    assert.match(a.note, /proveedor anterior/);
  });

  it("nunca sondea IPs privadas", async () => {
    const d = deps();
    const a = await auditDnsRecords({ domain: apex }, [rr(`intra.${apex}`, "A", ["10.0.0.5"])], d);
    assert.deepEqual(d.probed, []);
    assert.equal(a.findings[0].verdict, "not_responding");
    assert.ok(isPrivateIp("169.254.169.254") && isPrivateIp("127.0.0.1") && !isPrivateIp("8.8.8.8"));
  });

  it("se corta en 120 registros", async () => {
    const many = Array.from({ length: 130 }, (_, i) => rr(`h${i}.${apex}`, "A", ["203.0.113.10"]));
    const a = await auditDnsRecords({ domain: apex }, many, deps());
    assert.equal(a.findings.length, 120);
    assert.equal(a.truncated, true);
  });

  it("sin proveedor anterior conocido, _domainconnect no se marca", async () => {
    const a = await auditDnsRecords({ domain: apex, dnsPreviousNs: [] }, [rr(`_domainconnect.${apex}`, "CNAME", ["x.example.com"])], deps());
    assert.notEqual(a.findings[0].verdict, "previous_provider");
  });
});
