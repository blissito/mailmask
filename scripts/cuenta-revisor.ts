/**
 * Cuenta de revisión para los directorios de Claude y ChatGPT (13-oct-2026). Idempotente:
 * crea lo que falte y no toca lo que ya está.
 *
 *   REVIEWER_PASSWORD_HASH='<salt:hash de hashPassword>' npx tsx scripts/cuenta-revisor.ts [--reset-password] [--apply]
 *
 * - Usuario `directory-review@mailmask.studio`, entra con correo + contraseña (sin Google,
 *   sin códigos). Por el sufijo `-review@mailmask.studio` es cuenta de revisión: su correo
 *   no sale a terceros reales (`sandbox.ts`).
 * - Dominio `demo.mailmask.studio` de verdad (SES + registros en la zona de mailmask.studio),
 *   activado por cortesía, con direcciones y una Bandeja con conversaciones de muestra.
 *   Al dominio NO se le asigna la zona: es la de mailmask.studio y el editor de DNS la
 *   dejaría tocar entera.
 *
 * La contraseña nunca viaja: sólo su hash (se calcula en local). Dry-run por defecto.
 * En prod: subir a /app/data con `CAJA_SID=<mailmask-prod> scripts/caja.sh put` y correr con
 * `docker exec -e REVIEWER_PASSWORD_HASH=… app node_modules/.bin/tsx /app/data/cuenta-revisor.ts`
 * (el import relativo resuelve a /app, donde vive la app).
 */
import {
  getUser, createUser, getDomainByName, createDomain, listAliases, createAlias, listEffectiveAddonsForDomain,
  createCourtesyAddon, listConversations, createConversation, addMessage, indexMessage,
} from "../db.js";
import { sqlite } from "../pg.js";
import { verifyDomain, createReceiptRule } from "../ses.js";
import { configureDnsRecords, applyRecordChanges } from "../route53.js";

const EMAIL = "directory-review@mailmask.studio";
const DOMAIN = "demo.mailmask.studio";
const PARENT_ZONE = "Z08346981IZZVV2BD4Q0W"; // mailmask.studio
const apply = process.argv.includes("--apply");
const resetPassword = process.argv.includes("--reset-password");
const hash = process.env.REVIEWER_PASSWORD_HASH ?? "";

const say = (m: string) => console.log(`${apply ? "" : "(dry-run) "}${m}`);

// 1. Usuario
let user = getUser(EMAIL);
if (!user) {
  if (!/^[0-9a-f]{32}:[0-9a-f]+$/.test(hash)) { console.error("Falta REVIEWER_PASSWORD_HASH (salt:hash)."); process.exit(1); }
  say(`crea ${EMAIL}`);
  if (apply) { createUser(EMAIL, hash); sqlite.prepare("UPDATE users SET email_verified = 1, display_name = 'Directory Reviewer' WHERE email = ?").run(EMAIL); }
} else if (resetPassword) {
  if (!/^[0-9a-f]{32}:[0-9a-f]+$/.test(hash)) { console.error("Falta REVIEWER_PASSWORD_HASH (salt:hash)."); process.exit(1); }
  say(`repone la contraseña de ${EMAIL}`);
  if (apply) sqlite.prepare("UPDATE users SET password_hash = ?, password_changed_at = ? WHERE email = ?").run(hash, new Date().toISOString(), EMAIL);
} else {
  say(`${EMAIL} ya existe`);
}
if (!apply) { console.log("(dry-run: nada escrito; corre con --apply)"); process.exit(0); }
user = getUser(EMAIL)!;

// 2. Dominio real: SES + registros en la zona padre
let dom = getDomainByName(DOMAIN);
if (dom && dom.ownerEmail !== EMAIL) { console.error(`${DOMAIN} es de ${dom.ownerEmail}`); process.exit(1); }
if (!dom) {
  const dns = await verifyDomain(DOMAIN);
  try { await createReceiptRule(DOMAIN); } catch (e) { if (!String(e).includes("AlreadyExists")) throw e; }
  dom = createDomain(EMAIL, DOMAIN, dns.dkimTokens, dns.verificationToken);
  await configureDnsRecords(PARENT_ZONE, DOMAIN, dns.verificationToken, dns.dkimTokens, { preserveMx: true });
  await applyRecordChanges(PARENT_ZONE, [{ action: "UPSERT", rrset: { name: `_dmarc.${DOMAIN}`, type: "TXT", ttl: 300, values: ['"v=DMARC1; p=none"'] } }], "MailMask reviewer DMARC");
  console.log(`dominio ${DOMAIN} creado (${dom.id}); SES verifica en minutos`);
} else {
  console.log(`dominio ${DOMAIN} ya existe (${dom.id})`);
}

// 3. Activado por cortesía (sin 7 días de recorte, con equipo y envío; el envío lo frena sandbox.ts)
if (!listEffectiveAddonsForDomain(dom.id).some((a) => a.kind === "domain")) {
  createCourtesyAddon({ userEmail: EMAIL, kind: "domain", domainId: dom.id, currentPeriodEnd: "2027-12-31T00:00:00.000Z", note: "Cuenta de revisión de directorios", grantedBy: "script" });
  console.log("cortesía domain creada");
}

// 4. Direcciones de muestra (reenvían al propio correo de la cuenta)
const existentes = new Set(listAliases(dom.id).map((a) => a.alias));
for (const alias of ["hello", "support", "billing"]) {
  if (!existentes.has(alias)) { createAlias(dom.id, alias, [EMAIL]); console.log(`dirección ${alias}@ creada`); }
}

// 5. Bandeja de muestra: remitentes de example.com (no entregan a nadie)
const muestras = [
  { from: "Laura Méndez <laura.mendez@example.com>", to: `support@${DOMAIN}`, subject: "Can't log in to my account", hoursAgo: 2,
    body: "Hi,\n\nSince this morning I can't log in to my account. I reset my password twice and I still get \"invalid credentials\". My username is laura.mendez.\n\nCould you help me?\n\nThanks,\nLaura" },
  { from: "Carlos Ruiz <carlos@example.org>", to: `billing@${DOMAIN}`, subject: "Invoice for September", hoursAgo: 20,
    body: "Hello,\n\nCould you send me the invoice for September? Our company details are the same as last month.\n\nBest regards,\nCarlos Ruiz\nAcme Supplies" },
  { from: "Ana Torres <ana.torres@example.net>", to: `hello@${DOMAIN}`, subject: "Partnership proposal", hoursAgo: 48,
    body: "Hi team,\n\nI run a small design studio and I'd love to explore a partnership. Do you have 20 minutes next week for a call? Tuesday or Thursday afternoon works for me.\n\nCheers,\nAna" },
];
const convs = listConversations(dom.id);
for (const m of muestras) {
  if (convs.some((c) => c.subject === m.subject)) continue;
  const at = new Date(Date.now() - m.hoursAgo * 3600_000).toISOString();
  const conv = createConversation({
    domainId: dom.id, from: m.from, to: m.to, subject: m.subject, status: "open", priority: "normal",
    lastMessageAt: at, messageCount: 1, tags: [], threadReferences: [],
  } as Parameters<typeof createConversation>[0]);
  const msg = addMessage({
    conversationId: conv.id, from: m.from, body: m.body, direction: "inbound",
    messageId: `<${crypto.randomUUID()}@example.com>`, createdAt: at,
  } as Parameters<typeof addMessage>[0]);
  indexMessage({ messageId: msg.id, conversationId: conv.id, domainId: dom.id, from: m.from, subject: m.subject, text: m.body });
  console.log(`conversación «${m.subject}» sembrada`);
}

console.log(`✅ ${EMAIL} · ${DOMAIN} listo`);
process.exit(0);
