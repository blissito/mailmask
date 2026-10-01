// Apunta la ruta de salida `ses` de Stalwart al relay SMTP de la app (outbound-relay.ts),
// para que lo que manda Apple Mail pase por la app: cuota, supresión, log y Bandeja.
//
// Por defecto NO cambia nada: imprime la ruta actual, el parche y la definición de
// `MtaRoute` del esquema de la caja, para comparar los nombres de campo antes de aplicar.
//
//   npx tsx scripts/stalwart-outbound-via-app.ts             # dry-run
//   npx tsx scripts/stalwart-outbound-via-app.ts --apply     # aplica (idempotente)
//   npx tsx scripts/stalwart-outbound-via-app.ts --rollback  # vuelve a SES directo
//
// Entorno:
//   STALWART_ADMIN_URL, STALWART_ADMIN_USER, STALWART_ADMIN_PASSWORD  (los de Fly)
//   OUTBOUND_RELAY_SECRET   el mismo valor que el secreto de Fly (obligatorio en --apply)
//   OUTBOUND_RELAY_HOST     default mailmask.fly.dev (certificado *.fly.dev del borde)
//   OUTBOUND_RELAY_PORT     default 2465 (TLS implícito, lo termina Fly)
//   OUTBOUND_RELAY_USER     default stalwart
//   STALWART_ROUTE_NAME     default ses
//
// Se modifica la ruta EN SU LUGAR y no se crea otra: la expresión de la estrategia
// (`is_local_address(rcpt) ? 'local' : 'ses'`) no se toca, así que lo local sigue local.
// Antes de tocarla se guarda la ruta original en ~/.mailmask-stalwart-ses-route.json
// (0600: trae la credencial SMTP de SES), que es de donde lee el rollback.

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const BASE = (process.env.STALWART_ADMIN_URL ?? "").replace(/\/+$/, "");
const USER = process.env.STALWART_ADMIN_USER ?? "admin";
const PASS = process.env.STALWART_ADMIN_PASSWORD ?? "";
const ROUTE_NAME = process.env.STALWART_ROUTE_NAME ?? "ses";
const TARGET = {
  address: process.env.OUTBOUND_RELAY_HOST ?? "mailmask.fly.dev",
  port: parseInt(process.env.OUTBOUND_RELAY_PORT ?? "2465", 10),
  user: process.env.OUTBOUND_RELAY_USER ?? "stalwart",
  secret: process.env.OUTBOUND_RELAY_SECRET ?? "",
};
const BACKUP = path.join(os.homedir(), ".mailmask-stalwart-ses-route.json");
const FIELDS = ["address", "port", "protocol", "implicitTls", "allowInvalidCerts", "authUsername", "authSecret"] as const;

const mode = process.argv.includes("--apply") ? "apply" : process.argv.includes("--rollback") ? "rollback" : "dry-run";

if (!BASE || !PASS) {
  console.error("Faltan STALWART_ADMIN_URL / STALWART_ADMIN_PASSWORD");
  process.exit(1);
}
const auth = `Basic ${Buffer.from(`${USER}:${PASS}`).toString("base64")}`;

// Sin barra final: con ella Stalwart redirige y el POST pierde el cuerpo (`notRequest`).
async function jmap(methodCalls: unknown[][]): Promise<any> {
  const res = await fetch(`${BASE}/jmap`, {
    method: "POST",
    headers: { authorization: auth, "content-type": "application/json" },
    body: JSON.stringify({ using: ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"], methodCalls }),
  });
  if (!res.ok) throw new Error(`JMAP ${res.status}: ${await res.text()}`);
  const r = await res.json();
  const [name, body] = r.methodResponses?.[0] ?? [];
  if (name === "error") throw new Error(`JMAP error: ${JSON.stringify(body)}`);
  return body;
}

async function findRoute(): Promise<any> {
  const q = await jmap([["x:MtaRoute/query", {}, "c0"]]);
  const ids: string[] = q?.ids ?? [];
  const g = await jmap([["x:MtaRoute/get", { ids }, "c0"]]);
  const routes: any[] = g?.list ?? [];
  console.log("Rutas en la caja:", routes.map((r) => `${r.name} (${r["@type"]}) → ${r.address ?? "-"}:${r.port ?? "-"}`).join(", "));
  const route = routes.find((r) => r.name === ROUTE_NAME);
  if (!route) throw new Error(`No hay ruta llamada "${ROUTE_NAME}"`);
  return route;
}

/** Mismo variante de secreto que ya usa la ruta, con el valor nuevo. */
function secretLike(current: any, value: string): Record<string, unknown> {
  if (current && current["@type"] === "Value") {
    const key = Object.keys(current).find((k) => k !== "@type") ?? "secret";
    return { "@type": "Value", [key]: value };
  }
  return { "@type": "Value", secret: value };
}

function redact(o: any): any {
  return JSON.parse(JSON.stringify(o, (k, v) => (/secret|password/i.test(k) && typeof v === "string" ? "***" : v)));
}

function pick(route: any): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  // Nunca `null`: Stalwart tumba la petición entera con `400 notRequest`.
  for (const f of FIELDS) if (route[f] !== undefined && route[f] !== null) out[f] = route[f];
  return out;
}

async function update(id: string, patch: Record<string, unknown>): Promise<void> {
  const r = await jmap([["x:MtaRoute/set", { update: { [id]: patch } }, "c0"]]);
  if (!(id in (r?.updated ?? {}))) throw new Error(`No se actualizó: ${JSON.stringify(r?.notUpdated?.[id] ?? r)}`);
}

async function printSchema(): Promise<void> {
  try {
    const res = await fetch(`${BASE}/api/schema`, { headers: { authorization: auth } });
    const text = await res.text();
    const i = text.indexOf("MtaRoute");
    console.log(i >= 0 ? `\nEsquema (extracto de MtaRoute):\n${text.slice(i, i + 1500)}\n` : "\n(el esquema no menciona MtaRoute; revisar GET /api/schema a mano)\n");
  } catch (err) {
    console.log("No se pudo leer /api/schema:", String(err));
  }
}

const pointsToApp = (r: any) => r.address === TARGET.address && Number(r.port) === TARGET.port;

async function main() {
  const route = await findRoute();
  console.log(`\nRuta "${ROUTE_NAME}" actual:`, JSON.stringify(redact(route), null, 2));

  if (mode === "rollback") {
    if (!fs.existsSync(BACKUP)) throw new Error(`No existe ${BACKUP}; restaura a mano a email-smtp.us-east-1.amazonaws.com:465 con STALWART_RELAY_*`);
    const original = JSON.parse(fs.readFileSync(BACKUP, "utf8"));
    if (!pointsToApp(route) && route.address === original.address) {
      console.log("Ya apunta a SES. Nada que hacer.");
      return;
    }
    await update(route.id, original);
    console.log("Rollback aplicado: la ruta vuelve a", original.address, original.port);
    return;
  }

  const patch = {
    "@type": "Relay",
    address: TARGET.address,
    port: TARGET.port,
    protocol: "smtp",
    implicitTls: true,
    allowInvalidCerts: false,
    authUsername: TARGET.user,
    authSecret: secretLike(route.authSecret, TARGET.secret || "<OUTBOUND_RELAY_SECRET>"),
  };
  // `@type` no se manda en un update (no se cambia la variante); sólo se comprueba.
  delete (patch as any)["@type"];
  if (route["@type"] && route["@type"] !== "Relay") throw new Error(`La ruta es ${route["@type"]}, no Relay`);

  console.log("\nParche:", JSON.stringify(redact(patch), null, 2));

  if (mode === "dry-run") {
    await printSchema();
    console.log("Dry-run: no se cambió nada. Corre con --apply para aplicarlo.");
    return;
  }

  if (!TARGET.secret) throw new Error("Falta OUTBOUND_RELAY_SECRET");
  if (!pointsToApp(route)) {
    if (!fs.existsSync(BACKUP)) {
      fs.writeFileSync(BACKUP, JSON.stringify(pick(route), null, 2), { mode: 0o600 });
      console.log("Ruta original guardada en", BACKUP);
    }
  } else {
    console.log("Ya apuntaba a la app; se reescribe la credencial por si cambió.");
  }
  await update(route.id, patch);

  const after = await findRoute();
  if (!pointsToApp(after)) throw new Error("La ruta no quedó apuntando a la app");
  console.log(`Listo: "${ROUTE_NAME}" → ${TARGET.address}:${TARGET.port} (TLS implícito).`);
  console.log("Si el siguiente envío de Apple Mail no aparece en la Bandeja, reinicia Stalwart (`systemctl restart stalwart`).");
}

main().catch((err) => {
  console.error(String(err));
  process.exit(1);
});
