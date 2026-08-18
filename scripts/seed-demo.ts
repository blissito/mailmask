// Siembra una cuenta usable en la base de DESARROLLO para poder abrir la Bandeja
// real y probar el compositor con datos, sin depender de AWS ni de MercadoPago.
//
// No es parte del producto. Correr con:
//   DATABASE_PATH=... npx tsx scripts/seed-demo.ts
//
// Se niega a correr contra la base de producción por si alguien lo lanza distraído.

import { hashPassword } from "../auth.ts";
import * as db from "../db.ts";
import { sqlite } from "../pg.ts";

// Se pueden pasar por argumento para sembrar la cuenta con la que uno ya tiene
// memoria muscular:  npx tsx scripts/seed-demo.ts correo@ejemplo.com miclave
const EMAIL = process.argv[2] ?? "demo@mailmask.local";
const PASSWORD = process.argv[3] ?? "demo12345";
// Un dominio por cuenta: la columna es única y dos siembras chocarían.
const DOMAIN = `estudio-${EMAIL.split("@")[0].replace(/[^a-z0-9]/gi, "").toLowerCase()}.com`;

const dbPath = process.env.DATABASE_PATH ?? "";
if (!dbPath || dbPath.includes("mailmask.db")) {
  console.error("Este script es sólo para una base de prueba. Pasa DATABASE_PATH explícito.");
  process.exit(1);
}

const hashed = await hashPassword(PASSWORD);
const existing = await db.getUser(EMAIL);
if (existing) {
  // Se repone la contraseña a propósito: si no, volver a correr el script sobre una
  // cuenta existente no dejaría entrar y no habría forma de saber por qué.
  sqlite.prepare("UPDATE users SET password_hash = ? WHERE email = ?").run(hashed, EMAIL);
  console.log("La cuenta ya existía; se repuso la contraseña.");
} else {
  db.createUser(EMAIL, hashed);
}

await db.updateUserSubscription(EMAIL, {
  plan: "freelancer",
  status: "active",
  mpSubscriptionId: "sub-demo-local",
  currentPeriodEnd: new Date(Date.now() + 365 * 864e5).toISOString(),
});

// El add-on de envíos es lo que habilita redactar correo nuevo: sin él, el plan
// básico sólo responde. Aquí se activa para poder probar los dos caminos.
const addon = db.createAddon(EMAIL, "sends100");
db.updateAddon(addon.id, {
  status: "active",
  currentPeriodEnd: new Date(Date.now() + 365 * 864e5).toISOString(),
});

let domain = db.getDomainByName(DOMAIN);
if (!domain) {
  domain = db.createDomain(EMAIL, DOMAIN, ["dkim1", "dkim2", "dkim3"], "verif-demo");
  db.createAlias(domain.id, "hola", ["brenda@example.com"]);
}
// Verificado a mano: aquí no hay DNS ni SES que consultar.
sqlite.prepare("UPDATE domains SET verified = 1 WHERE id = ?").run(domain.id);

const conversations = db.listConversations(domain.id, {});
if (!conversations.length) {
  // Convención invertida, igual que en el código real: `from` es el contacto externo
  // y `to` nuestro alias. El reply deriva el remitente de `to`.
  const conv = db.createConversation({
    domainId: domain.id,
    from: "cliente@example.com",
    to: `hola@${DOMAIN}`,
    subject: "Cotización de identidad",
    status: "open",
    priority: "normal",
    lastMessageAt: new Date().toISOString(),
    messageCount: 1,
    tags: [],
    threadReferences: ["<demo-1@example.com>"],
  });
  db.addMessage({
    conversationId: conv.id,
    from: "cliente@example.com",
    body: "Hola, ¿me pasas la cotización de la identidad y los tiempos de entrega?\n\nGracias,\nAna",
    html: "",
    direction: "inbound",
    createdAt: new Date().toISOString(),
    messageId: "<demo-1@example.com>",
  });
}

console.log(`Cuenta:   ${EMAIL}`);
console.log(`Password: ${PASSWORD}`);
console.log(`Dominio:  ${DOMAIN} (verificado)`);
console.log("Abre http://localhost:8000/login");
