import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { detectPlatform, hostIssues, hostsFromZone, hostsFromPublicDns, getWebsiteStatus } from "./website.js";
import type { RRSet } from "./dns-records.js";

describe("website: detección de plataforma", () => {
  it("por IP en A y por destino en CNAME", () => {
    assert.equal(detectPlatform([{ type: "A", values: ["76.76.21.21"] }])?.id, "vercel");
    assert.equal(detectPlatform([{ type: "CNAME", values: ["cname.vercel-dns.com."] }])?.id, "vercel");
    assert.equal(detectPlatform([{ type: "CNAME", values: ["cname.sandboxes.easybits.cloud"] }])?.id, "easybits");
    assert.equal(detectPlatform([{ type: "A", values: ["216.24.57.1"] }])?.id, "render");
    assert.equal(detectPlatform([{ type: "A", values: ["1.2.3.4"] }]), null);
  });

  it("un AAAA viejo junto al A de la plataforma es un problema; en Fly no", () => {
    const recs = [{ type: "A" as const, values: ["76.76.21.21"] }, { type: "AAAA" as const, values: ["2001:db8::1"] }];
    assert.equal(hostIssues(recs, { id: "vercel", label: "Vercel" }).length, 1);
    assert.equal(hostIssues(recs, { id: "fly", label: "Fly.io" }).length, 0);
  });

  it("A que mezcla IPs de la plataforma con otras", () => {
    const issues = hostIssues([{ type: "A", values: ["76.76.21.21", "9.9.9.9"] }], { id: "vercel", label: "Vercel" });
    assert.match(issues[0], /9\.9\.9\.9/);
  });
});

describe("website: hosts de una zona", () => {
  const zone: RRSet[] = [
    { name: "ej.com", type: "A", ttl: 300, values: ["76.76.21.21"] },
    { name: "ej.com", type: "MX", ttl: 300, values: ["10 inbound-smtp.us-east-1.amazonaws.com"] },
    { name: "app.ej.com", type: "CNAME", ttl: 300, values: ["cname.sandboxes.easybits.cloud."] },
    { name: "abc._domainkey.ej.com", type: "CNAME", ttl: 300, values: ["abc.dkim.amazonses.com"] },
    { name: "autoconfig.ej.com", type: "CNAME", ttl: 300, values: ["imap.mailmask.studio"] },
    { name: "otro.com", type: "A", ttl: 300, values: ["1.1.1.1"] },
  ];

  it("raíz y www siempre; subdominios web sí; correo y verificación no", () => {
    const hosts = hostsFromZone("ej.com", zone, new Set());
    assert.deepEqual([...hosts.keys()], ["ej.com", "www.ej.com", "app.ej.com"]);
    assert.deepEqual(hosts.get("app.ej.com"), [{ type: "CNAME", values: ["cname.sandboxes.easybits.cloud"] }]);
  });

  it("www vacío con raíz apuntada avisa; sin registros no se sondea HTTPS", async () => {
    const probed: string[] = [];
    const { hosts } = await getWebsiteStatus("ej.com", hostsFromZone("ej.com", zone, new Set()), async (h) => { probed.push(h); return { ok: true, status: 200 }; });
    const www = hosts.find((h) => h.label === "www")!;
    assert.match(www.issues.join(" "), /no apunta/);
    assert.equal(www.https, null);
    assert.deepEqual(probed.sort(), ["app.ej.com", "ej.com"]);
    assert.equal(hosts.find((h) => h.label === "app")!.platform?.id, "easybits");
  });
});

describe("website: sin zona, DNS público", () => {
  it("raíz por A/AAAA y www por CNAME", async () => {
    const r = {
      resolve4: async (n: string) => (n === "ej.com" ? ["75.2.60.5"] : []),
      resolve6: async () => [] as string[],
      resolveCname: async (n: string) => (n === "www.ej.com" ? ["mi-sitio.netlify.app"] : []),
    };
    const hosts = await hostsFromPublicDns("ej.com", r as never);
    assert.deepEqual(hosts.get("ej.com"), [{ type: "A", values: ["75.2.60.5"] }]);
    assert.deepEqual(hosts.get("www.ej.com"), [{ type: "CNAME", values: ["mi-sitio.netlify.app"] }]);
  });
});
