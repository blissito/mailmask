// El vigía de 48 h compara lo que resuelve el mundo contra el inventario aprobado antes de mudar los NS.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { checkDomain, describeFinding, type LiveResolver } from "./dns-watch.ts";

const PRE = [
  { name: "ejemplo.org", type: "MX" as const, ttl: 3600, values: ["1 aspmx.l.google.com.", "5 alt1.aspmx.l.google.com."] },
  { name: "ejemplo.org", type: "A" as const, ttl: 600, values: ["76.76.21.21"] },
  { name: "www.ejemplo.org", type: "CNAME" as const, ttl: 3600, values: ["cname.vercel-dns.com."] },
];

const live = (over: Partial<Record<"mx" | "a" | "cname", Record<string, string[]>>> = {}): LiveResolver => ({
  mx: async (n) => over.mx?.[n] ?? (n === "ejemplo.org" ? ["5 alt1.aspmx.l.google.com", "1 aspmx.l.google.com"] : []),
  a: async (n) => over.a?.[n] ?? (n === "ejemplo.org" ? ["76.76.21.21"] : ["1.2.3.4"]),
  cname: async (n) => over.cname?.[n] ?? (n === "www.ejemplo.org" ? ["cname.vercel-dns.com"] : []),
});

describe("checkDomain", () => {
  it("sin cambios no reporta nada (orden y punto final no importan; la A de un www con CNAME no se mira)", async () => {
    assert.deepEqual(await checkDomain("ejemplo.org", PRE, live()), []);
  });

  it("si el MX deja de apuntar a Google, lo reporta con lo esperado y lo observado", async () => {
    const f = await checkDomain("ejemplo.org", PRE, live({ mx: { "ejemplo.org": ["10 inbound-smtp.us-east-1.amazonaws.com"] } }));
    assert.equal(f.length, 1);
    assert.equal(f[0].type, "MX");
    assert.match(describeFinding(f[0]), /el correo \(MX\)/);
  });

  it("si la web deja de resolver, lo reporta como «nada»", async () => {
    const f = await checkDomain("ejemplo.org", PRE, live({ a: { "ejemplo.org": [] } }));
    assert.equal(f[0].type, "A");
    assert.match(describeFinding(f[0]), /ahora nada/);
  });

  it("un registro que no estaba en el inventario no es falla", async () => {
    const f = await checkDomain("ejemplo.org", PRE.filter((r) => r.type !== "A"), live({ a: { "ejemplo.org": ["9.9.9.9"] } }));
    assert.deepEqual(f, []);
  });
});

describe("runDnsWatch", () => {
  it("avisa una sola vez por registro y sólo dentro de las 48 h", async () => {
    const claimed = new Set<string>();
    const sent: string[] = [];
    const deps = {
      domains: [
        { id: "d1", domain: "ejemplo.org", ownerEmail: "dueno@ejemplo.org", dnsDelegatedAt: new Date(Date.now() - 3600_000).toISOString(), dnsPreSnapshot: PRE },
        { id: "d2", domain: "viejo.org", ownerEmail: "x@viejo.org", dnsDelegatedAt: new Date(Date.now() - 72 * 3600_000).toISOString(), dnsPreSnapshot: PRE },
      ],
      live: live({ mx: { "ejemplo.org": [] } }),
      claimOnce: (k: string, t: string) => (claimed.has(k + t) ? false : (claimed.add(k + t), true)),
      notify: async (to: string) => { sent.push(to); },
    };
    const { runDnsWatch } = await import("./dns-watch.ts");
    assert.equal(await runDnsWatch(deps), 1);
    assert.deepEqual(sent, ["team", "dueno@ejemplo.org"]);
    assert.equal(await runDnsWatch(deps), 0, "la segunda corrida no repite el aviso");
  });
});
