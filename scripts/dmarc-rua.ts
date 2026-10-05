/**
 * Agrega el `rua` al DMARC de mailmask.studio para que los reportes agregados lleguen a
 * dmarc-reports.ts. De un solo uso; se corre DESPUÉS del deploy que trae el lector.
 *
 *   set -a; source .env; set +a; npx tsx scripts/dmarc-rua.ts [--apply]
 *
 * Dry-run por defecto: imprime el TXT actual y el nuevo. `_dmarc.<dominio>` es su propio
 * RRSet, así que el UPSERT no toca el SPF ni las verificaciones del apex. Se niega a
 * correr si la política actual ya no es `p=none`: bajarla de golpe sería un retroceso.
 */
import {
  Route53Client, ListHostedZonesByNameCommand, ListResourceRecordSetsCommand, ChangeResourceRecordSetsCommand,
} from "@aws-sdk/client-route-53";

const DOMAIN = process.env.DMARC_DOMAIN ?? "mailmask.studio";
const ADDRESS = process.env.DMARC_REPORT_ADDRESS ?? `dmarc@${DOMAIN}`;
const NEW_VALUE = `v=DMARC1; p=none; rua=mailto:${ADDRESS}; fo=1`;
const apply = process.argv.includes("--apply");

const r53 = new Route53Client({ region: "us-east-1" });
const name = `_dmarc.${DOMAIN}.`;

const zones = await r53.send(new ListHostedZonesByNameCommand({ DNSName: DOMAIN, MaxItems: 1 }));
const zone = zones.HostedZones?.find((z) => z.Name === `${DOMAIN}.`);
if (!zone?.Id) { console.error(`No hay hosted zone para ${DOMAIN}`); process.exit(1); }

const sets = await r53.send(new ListResourceRecordSetsCommand({
  HostedZoneId: zone.Id, StartRecordName: name, StartRecordType: "TXT", MaxItems: 1,
}));
const current = sets.ResourceRecordSets?.find((s) => s.Name === name && s.Type === "TXT");
const currentValue = current?.ResourceRecords?.map((r) => (r.Value ?? "").replace(/^"|"$/g, "").replace(/" "/g, "")).join(" ") ?? null;

console.log(`Zona:   ${zone.Id}`);
console.log(`Actual: ${currentValue ?? "(sin registro)"}`);
console.log(`Nuevo:  ${NEW_VALUE}`);

if (currentValue && !/;\s*p=none\b/i.test(currentValue)) {
  console.error("La política actual no es p=none; no se toca. Edita el script si de verdad quieres cambiarla.");
  process.exit(1);
}
if (currentValue === NEW_VALUE) { console.log("Ya está así; nada que hacer."); process.exit(0); }
if (!apply) { console.log("\nDry-run. Repite con --apply para escribirlo."); process.exit(0); }

const res = await r53.send(new ChangeResourceRecordSetsCommand({
  HostedZoneId: zone.Id,
  ChangeBatch: {
    Comment: "DMARC: rua a dmarc-reports.ts",
    Changes: [{
      Action: "UPSERT",
      ResourceRecordSet: { Name: name, Type: "TXT", TTL: current?.TTL ?? 300, ResourceRecords: [{ Value: `"${NEW_VALUE}"` }] },
    }],
  },
}));
console.log(`Aplicado: ${res.ChangeInfo?.Id} (${res.ChangeInfo?.Status}). Comprueba con: dig +short TXT ${name}`);
