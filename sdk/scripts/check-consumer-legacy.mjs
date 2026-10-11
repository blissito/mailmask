// Prueba de CONSUMIDOR VIEJO: empaqueta el SDK con `npm pack` e instala el .tgz en un proyecto
// aparte con TypeScript 4.9.5 y `moduleResolution: node` (el camino clásico, sin `exports`),
// para confirmar que los tipos publicados se pueden leer desde ahí. Necesita `dist/` construido
// y red (baja typescript@4.9.5 de npm).
//
// A propósito NO corre en CI: agregar dependencias de red a un check requerido de `main` hace
// que un hipo del registry bloquee todos los PRs. El guardián de CI es postbuild-dts.mjs, que
// truena si vuelve a colarse sintaxis que TS 4.9 no entiende.
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SDK = new URL("../", import.meta.url).pathname;
const TS_VIEJO = "4.9.5";
const trabajo = mkdtempSync(join(tmpdir(), "mailmask-consumer-"));
const correr = (cmd, args, cwd) =>
  execFileSync(cmd, args, { cwd, stdio: "inherit", env: { ...process.env, npm_config_audit: "false", npm_config_fund: "false" } });

console.log(`[consumer] npm pack en ${SDK}`);
correr("npm", ["pack", "--pack-destination", trabajo], SDK);
const tgz = readdirSync(trabajo).find((f) => f.endsWith(".tgz"));
if (!tgz) throw new Error("npm pack no dejó ningún .tgz");

const proyecto = join(trabajo, "consumidor");
mkdirSync(join(proyecto, "src"), { recursive: true });
writeFileSync(join(proyecto, "package.json"), JSON.stringify({ name: "consumidor-ts49", private: true, version: "1.0.0" }, null, 2) + "\n");
// El camino clásico: sin `exports`, sin `bundler`, con skipLibCheck apagado para que mire los .d.ts.
writeFileSync(
  join(proyecto, "tsconfig.json"),
  JSON.stringify(
    {
      compilerOptions: {
        target: "ES2020",
        module: "CommonJS",
        moduleResolution: "node",
        strict: true,
        skipLibCheck: false,
        noEmit: true,
        types: [],
      },
      files: ["src/index.ts"],
    },
    null,
    2
  ) + "\n"
);
writeFileSync(
  join(proyecto, "src/index.ts"),
  `import { MailMask, MailMaskError, verifyWebhookSignature } from "@easybits.cloud/mailmask";
import type { Alias, SendEmailInput, WebhookSignatureHeaders } from "@easybits.cloud/mailmask";

const valores: unknown[] = [MailMask, MailMaskError, verifyWebhookSignature];
const tipos: (Alias | SendEmailInput | WebhookSignatureHeaders)[] = [];
export { valores, tipos };
`
);

console.log(`[consumer] instalando ${tgz} + typescript@${TS_VIEJO}`);
correr("npm", ["install", join(trabajo, tgz), `typescript@${TS_VIEJO}`, "--no-audit", "--no-fund"], proyecto);
try {
  correr("npx", ["tsc", "--noEmit"], proyecto);
} catch {
  console.error(
    `\n[consumer] el paquete publicado NO compila con TypeScript ${TS_VIEJO} (arriba está el error real de tsc).\n` +
      "Normalmente es sintaxis de TS 5+ en los .d.ts: revisa el último paso del build (scripts/postbuild-dts.mjs)."
  );
  process.exit(1);
}
console.log(`[consumer] ok: el .tgz compila en un consumidor con TypeScript ${TS_VIEJO} y moduleResolution node`);
