/**
 * Da de alta en MailMask un dominio NUESTRO que ya está registrado en Route 53 (misma cuenta),
 * sin pasar por el checkout: SES (verificación + recepción), fila en `domains`, zona ADOPTADA
 * (`ensureHostedZone` no crea otra), registros de correo y, opcional, catch-all.
 *
 *   npx tsx scripts/alta-dominio-propio.ts --email x@y.com --domain ejemplo.page [--catchall destino@z.com] [--apply]
 *
 * Dry-run por defecto. Nació para `ghosty.page` (3-oct-2026, comprado directo en AWS).
 */
import { getUser, getDomainByName, createDomain, createAlias, updateDomain } from "../db.js";
import { verifyDomain, createReceiptRule } from "../ses.js";
import { ensureHostedZone, configureDnsRecords } from "../route53.js";

const arg = (k: string) => { const i = process.argv.indexOf(k); return i > -1 ? process.argv[i + 1] : undefined; };
const email = arg("--email"); const domain = arg("--domain"); const catchall = arg("--catchall");
const apply = process.argv.includes("--apply");
if (!email || !domain) { console.error("uso: --email --domain [--catchall destino] [--apply]"); process.exit(1); }
if (!getUser(email)) { console.error(`no existe el usuario ${email}`); process.exit(1); }
if (getDomainByName(domain)) { console.error(`${domain} ya está en MailMask`); process.exit(1); }
console.log(`${apply ? "APLICANDO" : "dry-run"}: ${domain} → ${email}${catchall ? `, catch-all → ${catchall}` : ""}`);
if (!apply) process.exit(0);

const dns = await verifyDomain(domain);
try { await createReceiptRule(domain); } catch (e) { if (!String(e).includes("AlreadyExists")) throw e; }
const d = createDomain(email, domain, dns.dkimTokens, dns.verificationToken);
const zona = await ensureHostedZone(domain);
console.log("zona", zona.hostedZoneId, zona.created ? "(creada)" : "(adoptada)");
await configureDnsRecords(zona.hostedZoneId, domain, dns.verificationToken, dns.dkimTokens, { preserveMx: true });
// Registrado en esta misma cuenta de AWS: la delegación ya apunta a la zona.
const now = new Date().toISOString();
updateDomain(d.id, { hostedZoneId: zona.hostedZoneId, dnsZoneStatus: "active", dnsNameservers: zona.nameservers, dnsDelegatedAt: now, dnsCheckedAt: now });
if (catchall) { createAlias(d.id, "*", [catchall]); console.log("catch-all listo"); }
console.log("listo", d.id);
process.exit(0);
