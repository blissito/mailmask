import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { lookupDns, checkHttps, checkDmarc, checkDomainBlocklists, registrationInfo, type DiagnosticsDeps } from "./domain-diagnostics.ts";
import { parseRdap } from "./rdap.ts";

const nx = () => Object.assign(new Error("nx"), { code: "ENOTFOUND" });
const future = new Date(Date.now() + 60 * 864e5).toUTCString();
const past = new Date(Date.now() - 2 * 864e5).toUTCString();

function deps(over: Partial<DiagnosticsDeps> = {}): DiagnosticsDeps & { tlsCalls: string[] } {
  const tlsCalls: string[] = [];
  return {
    tlsCalls,
    resolve: async () => ["151.101.1.195"],
    tlsPeer: async (host, ip) => { tlsCalls.push(ip); return { issuer: "Let's Encrypt", validTo: future, altNames: [host] }; },
    httpHead: async () => ({ status: 200, location: null }),
    rdap: async () => null,
    ...over,
  };
}

describe("lookupDns", () => {
  it("propagado y coincide con la zona", async () => {
    const r = await lookupDns("fixter.org", "MX", { zoneValues: ["1 aspmx.l.google.com"] }, deps({ resolve: async () => ["1 aspmx.l.google.com"] }));
    assert.equal(r.propagated, true);
    assert.equal(r.matchesZone, true);
    assert.equal(r.answers.length, 3);
  });

  it("resolvers en desacuerdo = todavía propagando", async () => {
    const r = await lookupDns("www.fixter.org", "A", {}, deps({ resolve: async (server) => [server === "8.8.8.8" ? "1.1.1.1" : "2.2.2.2"] }));
    assert.equal(r.propagated, false);
    assert.equal(r.matchesZone, null);
    assert.match(r.summary, /propag/);
  });

  it("NXDOMAIN es respuesta («no existe»), no error", async () => {
    const r = await lookupDns("nada.fixter.org", "A", { zoneValues: [] }, deps({ resolve: async () => { throw nx(); } }));
    assert.equal(r.propagated, true);
    assert.equal(r.matchesZone, true);
    assert.match(r.summary, /no tiene registro/);
  });
});

describe("checkHttps", () => {
  it("válido con redirección", async () => {
    let n = 0;
    const r = await checkHttps("www.fixter.org", deps({ httpHead: async () => (n++ === 0 ? { status: 301, location: "https://fixter.org/" } : { status: 200, location: null }) }));
    assert.equal(r.ok, true);
    assert.equal(r.redirects.length, 2);
    assert.match(r.summary, /redirige a https:\/\/fixter\.org/);
  });

  it("certificado de otro nombre o vencido", async () => {
    const otro = await checkHttps("demo.fixter.org", deps({ tlsPeer: async () => ({ issuer: "Google", validTo: future, altNames: ["*.firebaseapp.com"] }) }));
    assert.equal(otro.ok, false);
    assert.equal(otro.certificate!.coversHost, false);
    const vencido = await checkHttps("fixter.org", deps({ tlsPeer: async (h) => ({ issuer: "X", validTo: past, altNames: [h] }) }));
    assert.match(vencido.summary, /venció/);
  });

  it("nunca se conecta a una IP privada", async () => {
    const d = deps({ resolve: async () => ["10.0.0.5"] });
    const r = await checkHttps("intra.fixter.org", d);
    assert.deepEqual(d.tlsCalls, []);
    assert.equal(r.ok, false);
  });

  it("el comodín cubre un solo nivel", async () => {
    const r = await checkHttps("a.b.fixter.org", deps({ tlsPeer: async () => ({ issuer: "X", validTo: future, altNames: ["*.fixter.org"] }) }));
    assert.equal(r.certificate!.coversHost, false);
  });
});

describe("checkDmarc", () => {
  it("ausente, p=none sin rua y p=reject", async () => {
    assert.equal((await checkDmarc("a.org", deps({ resolve: async () => { throw nx(); } }))).ok, false);
    const none = await checkDmarc("a.org", deps({ resolve: async () => ["v=DMARC1; p=none"] }));
    assert.equal(none.policy, "none");
    assert.match(none.detail, /sin reportes/);
    const rej = await checkDmarc("a.org", deps({ resolve: async () => ["v=DMARC1; p=reject; rua=mailto:d@a.org"] }));
    assert.equal(rej.policy, "reject");
    assert.equal(rej.rua, "mailto:d@a.org");
  });
});

describe("checkDomainBlocklists", () => {
  it("listado, limpio y consulta rechazada no se confunden", async () => {
    const listed = await checkDomainBlocklists("a.org", deps({ resolve: async (_s, n) => (n.includes("spamhaus") ? ["127.0.1.2"] : (() => { throw nx(); })()) }));
    assert.equal(listed.ok, false);
    assert.match(listed.detail, /Spamhaus DBL/);
    const refused = await checkDomainBlocklists("a.org", deps({ resolve: async () => ["127.255.255.254"] }));
    assert.equal(refused.ok, true, "rechazar la consulta no es estar listado");
    assert.ok(refused.lists.every((l) => l.listed === null));
    const clean = await checkDomainBlocklists("a.org", deps({ resolve: async () => { throw nx(); } }));
    assert.match(clean.detail, /Limpio/);
  });
});

describe("registrationInfo", () => {
  it("parsea RDAP: registrador, vencimiento y candado", async () => {
    const info = parseRdap({
      events: [{ eventAction: "registration", eventDate: "2015-01-01T00:00:00Z" }, { eventAction: "expiration", eventDate: new Date(Date.now() + 100 * 864e5).toISOString() }],
      status: ["client transfer prohibited"],
      nameservers: [{ ldhName: "NS-1272.AWSDNS-31.ORG" }],
      entities: [{ roles: ["registrar"], vcardArray: ["vcard", [["fn", {}, "text", "GoDaddy.com, LLC"]]] }],
    });
    assert.equal(info.registrar, "GoDaddy.com, LLC");
    assert.deepEqual(info.nameservers, ["ns-1272.awsdns-31.org"]);
    const r = await registrationInfo("fixter.org", deps({ rdap: async () => info }));
    assert.equal(r.transferLocked, true);
    assert.ok(r.daysToExpire! >= 99);
    assert.match(r.summary, /GoDaddy/);
    const none = await registrationInfo("kandey.com.mx", deps());
    assert.match(none.summary, /no respondió/);
  });
});
