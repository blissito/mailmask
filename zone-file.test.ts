// Lector de exportaciones de zona y su comparación: lo que el proveedor tiene y MailMask no, sale como faltante.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseZoneFile, compareZones } from "./zone-file.ts";

// Al estilo de la exportación de GoDaddy: $ORIGIN, `@`, nombres relativos, SOA en varias líneas, `;` en un DKIM.
const GODADDY = `; Domain: ejemplo.org
; Exported (y-m-d hh:mm:ss): 2026-10-22 10:00:00
$ORIGIN ejemplo.org.

; SOA Record
@	3600	 IN 	SOA	ns15.domaincontrol.com.	dns.jomax.net. (
					2026102201
					28800
					7200
					604800
					3600
					)

; A Record
@	600	 IN 	A	76.76.21.21

; CNAME Records
www	3600	 IN 	CNAME	cname.vercel-dns.com.
_domainconnect	3600	 IN 	CNAME	_domainconnect.gd.domaincontrol.com.

; MX Records
@	3600	 IN 	MX	1	aspmx.l.google.com.
@	3600	 IN 	MX	5	alt1.aspmx.l.google.com.

; TXT Records
@	3600	 IN 	TXT	"google-site-verification=abc123"
google._domainkey	3600	 IN 	TXT	"v=DKIM1; k=rsa; p=MIIBIjANBg"

; NS Records
@	3600	 IN 	NS	ns15.domaincontrol.com.
@	3600	 IN 	NS	ns16.domaincontrol.com.
`;

// Al estilo de Cloudflare: nombres completos con punto final y TTL 1 (automático).
const CLOUDFLARE = `;; Domain:     ejemplo.org.
ejemplo.org.	1	IN	A	76.76.21.21
www.ejemplo.org.	1	IN	CNAME	cname.vercel-dns.com.
blog.ejemplo.org.	300	IN	CNAME	hashnode.network.
ejemplo.org.	1	IN	MX	1 aspmx.l.google.com.
ejemplo.org.	1	IN	TXT	"v=spf1 include:_spf.google.com ~all"
_sip._tcp.ejemplo.org.	300	IN	SRV	10 5 5060 sip.proveedor.com.
ejemplo.org.	86400	IN	NS	ana.ns.cloudflare.com.
`;

describe("parseZoneFile", () => {
  it("lee la exportación de GoDaddy: sin SOA ni NS del apex, MX agrupados, DKIM con `;` entre comillas", () => {
    const sets = parseZoneFile(GODADDY, "ejemplo.org");
    const get = (n: string, t: string) => sets.find((s) => s.name === n && s.type === t);
    assert.equal(sets.some((s) => s.type === "NS" && s.name === "ejemplo.org"), false);
    assert.deepEqual(get("ejemplo.org", "A")?.values, ["76.76.21.21"]);
    assert.equal(get("ejemplo.org", "A")?.ttl, 600);
    assert.deepEqual(get("www.ejemplo.org", "CNAME")?.values, ["cname.vercel-dns.com."]);
    assert.deepEqual(get("ejemplo.org", "MX")?.values, ["1 aspmx.l.google.com.", "5 alt1.aspmx.l.google.com."]);
    assert.deepEqual(get("google._domainkey.ejemplo.org", "TXT")?.values, ['"v=DKIM1; k=rsa; p=MIIBIjANBg"']);
    assert.equal(sets.length, 6);
  });

  it("lee la exportación de Cloudflare con nombres completos y SRV", () => {
    const sets = parseZoneFile(CLOUDFLARE, "ejemplo.org");
    assert.deepEqual(sets.find((s) => s.type === "SRV")?.values, ["10 5 5060 sip.proveedor.com."]);
    assert.equal(sets.find((s) => s.name === "blog.ejemplo.org")?.ttl, 300);
    assert.equal(sets.some((s) => s.type === "NS"), false);
  });
});

describe("compareZones", () => {
  it("lo que el proveedor tiene y MailMask no sale como faltante; lo distinto, como distinto", () => {
    const exported = parseZoneFile(GODADDY, "ejemplo.org");
    const current = [
      { name: "ejemplo.org", type: "A" as const, ttl: 300, values: ["76.76.21.21"] },
      { name: "www.ejemplo.org", type: "CNAME" as const, ttl: 300, values: ["cname.vercel-dns.com"] }, // sin punto: igual
      { name: "ejemplo.org", type: "MX" as const, ttl: 300, values: ["1 aspmx.l.google.com."] }, // le falta alt1
      { name: "ejemplo.org", type: "TXT" as const, ttl: 300, values: ['"google-site-verification=abc123"', '"v=spf1 include:amazonses.com ~all"'] },
    ];
    const diff = compareZones(exported, current);
    assert.deepEqual(diff.missing.map((m) => `${m.name} ${m.type}`).sort(),
      ["_domainconnect.ejemplo.org CNAME", "google._domainkey.ejemplo.org TXT"]);
    assert.deepEqual(diff.different.map((d) => `${d.name} ${d.type}`), ["ejemplo.org MX"]);
  });

  it("una zona idéntica no reporta nada", () => {
    const sets = parseZoneFile(CLOUDFLARE, "ejemplo.org");
    assert.deepEqual(compareZones(sets, sets), { missing: [], different: [] });
  });
});
