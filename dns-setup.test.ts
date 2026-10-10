// Los registros que se pegan en el registrador y su comprobación contra el DNS público.
// El resolver es falso: estas pruebas no salen a internet.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildDnsSetup, dnsSetupRecords, mergeSpf, registrarFromNameservers } from "./dns-setup.ts";

const dom = { domain: "ejemplo.com.mx", verificationToken: "VTOK", dkimTokens: ["aaa", "bbb", "ccc"] };

const notFound = () => Object.assign(new Error("nf"), { code: "ENOTFOUND" });
const timeout = () => Object.assign(new Error("to"), { code: "ETIMEOUT" });

// deno-lint-ignore no-explicit-any
function resolver(tabla: Record<string, any>) {
  const pick = (k: string) => async () => {
    const v = tabla[k];
    if (v instanceof Error) throw v;
    if (v === undefined) throw notFound();
    return v;
  };
  return {
    resolveMx: (n: string) => pick(`MX ${n}`)(),
    resolveTxt: (n: string) => pick(`TXT ${n}`)(),
    resolveCname: (n: string) => pick(`CNAME ${n}`)(),
    resolveNs: (n: string) => pick(`NS ${n}`)(),
  // deno-lint-ignore no-explicit-any
  } as any;
}

describe("dns-setup", () => {
  it("con buzones agrega el autodescubrimiento; sin buzones no", () => {
    assert.ok(!dnsSetupRecords(dom).some((x) => x.id === "autodiscover"));
    const r = dnsSetupRecords({ ...dom, mailboxes: true });
    const srv = r.find((x) => x.id === "autodiscover")!;
    assert.equal(srv.type, "SRV");
    assert.equal(srv.fqdn, "_autodiscover._tcp.ejemplo.com.mx");
    assert.equal(srv.value, "0 0 443 imap.mailmask.studio");
    assert.equal(r.find((x) => x.id === "autoconfig")!.value, "imap.mailmask.studio");
  });

  it("los registros son los de la tabla de /app, con la ayuda en markdown", () => {
    const r = dnsSetupRecords(dom);
    assert.deepEqual(r.map((x) => x.id), ["mx", "verification", "dkim1", "dkim2", "dkim3", "spf", "dmarc"]);
    assert.equal(r[0].value, "10 inbound-smtp.us-east-1.amazonaws.com");
    assert.equal(r[2].name, "aaa._domainkey");
    assert.equal(r[2].value, "aaa.dkim.amazonses.com");
    assert.match(r[2].hints[0], /Los 3 registros CNAME/);
    assert.ok(!r[3].hints.some((h) => /Los 3 registros CNAME/.test(h)), "la explicación común va sólo en el primero");
    assert.ok(r.every((x) => x.hints.every((h) => !/<\w+>/.test(h))), "nada de HTML en la API");
  });

  it("sin live no consulta el DNS", async () => {
    const r = await buildDnsSetup(dom, { resolver: resolver({}) });
    assert.equal(r.live, false);
    assert.equal(r.records[0].ok, undefined);
  });

  it("live: marca lo que ya está, distingue 'no está' de 'no se pudo' y deduce Hostinger", async () => {
    const r = await buildDnsSetup(dom, {
      live: true,
      resolver: resolver({
        "MX ejemplo.com.mx": [{ priority: 5, exchange: "mx1.hostinger.com" }, { priority: 10, exchange: "inbound-smtp.us-east-1.amazonaws.com" }],
        "TXT _amazonses.ejemplo.com.mx": [["VTOK"]],
        "CNAME aaa._domainkey.ejemplo.com.mx": ["aaa.dkim.amazonses.com"],
        "CNAME bbb._domainkey.ejemplo.com.mx": timeout(),
        "TXT ejemplo.com.mx": [["v=spf1 include:_spf.mail.hostinger.com ~all"], ["google-site-verification=x"]],
        "NS ejemplo.com.mx": ["ns1.dns-parking.com", "ns2.dns-parking.com"],
      }),
    });
    const by = (id: string) => r.records.find((x) => x.id === id)!;
    assert.equal(by("mx").ok, false, "un MX de Hostinger con más prioridad se lleva el correo");
    assert.equal(by("verification").ok, true);
    assert.equal(by("dkim1").ok, true);
    assert.equal(by("dkim2").ok, null);
    assert.equal(by("dkim3").ok, false);
    assert.equal(by("spf").ok, false);
    assert.equal(by("spf").suggestedValue, "v=spf1 include:_spf.mail.hostinger.com include:amazonses.com ~all");
    assert.match(by("spf").hints[0], /No crees otro/);
    assert.equal(by("dmarc").ok, false);
    assert.equal(r.registrarHint?.provider, "hostinger");
    assert.match(r.summary!, /Faltan 3 de 5/);
  });

  it("subdominio: sube hasta encontrar los NS de la zona", async () => {
    const r = await buildDnsSetup({ ...dom, domain: "correo.ejemplo.com" }, {
      live: true,
      resolver: resolver({ "NS ejemplo.com": ["kate.ns.cloudflare.com"] }),
    });
    assert.equal(r.registrarHint?.provider, "cloudflare");
    assert.match(r.registrarHint!.note, /DNS only/);
  });

  it("registradores por sus nameservers; Route 53 con zona propia es MailMask", () => {
    assert.equal(registrarFromNameservers(["ns51.domaincontrol.com"], false)?.provider, "godaddy");
    assert.equal(registrarFromNameservers(["dns1.registrar-servers.com"], false)?.provider, "namecheap");
    assert.equal(registrarFromNameservers(["ns-1.awsdns-01.com"], false)?.provider, "route53");
    assert.equal(registrarFromNameservers(["ns-1.awsdns-01.com"], true)?.provider, "mailmask");
    assert.equal(registrarFromNameservers(["ns1.desconocido.net"], false), null);
  });

  it("mergeSpf conserva lo que había y respeta el -all", () => {
    assert.equal(mergeSpf("v=spf1 include:_spf.google.com -all"), "v=spf1 include:_spf.google.com include:amazonses.com -all");
    assert.equal(mergeSpf("v=spf1 include:amazonses.com ~all"), "v=spf1 include:amazonses.com ~all");
    assert.equal(mergeSpf("v=spf1 mx"), "v=spf1 mx include:amazonses.com");
  });
});
