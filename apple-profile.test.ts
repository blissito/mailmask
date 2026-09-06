import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { generarPerfilApple, nombreArchivoPerfil, IMAP_HOST } from "./apple-profile.ts";

describe("Perfil de Apple Mail", () => {
  const base = { direccion: "brenda@brendago.design", dominio: "brendago.design" };

  it("es un plist válido con la cuenta IMAP configurada", () => {
    const p = generarPerfilApple(base);
    assert.ok(p.startsWith("<?xml"));
    assert.ok(p.includes("<key>PayloadType</key><string>com.apple.mail.managed</string>"));
    assert.ok(p.includes("<key>EmailAccountType</key><string>EmailTypeIMAP</string>"));
    assert.ok(p.includes(`<key>IncomingMailServerHostName</key><string>${IMAP_HOST}</string>`));
    assert.ok(p.includes("<key>IncomingMailServerPortNumber</key><integer>993</integer>"));
    assert.ok(p.includes("<key>IncomingMailServerUseSSL</key><true/>"));
    assert.ok(p.includes("brenda@brendago.design"));
  });

  it("🔴 el mismo buzón produce el mismo UUID", () => {
    // Si el UUID cambiara entre descargas, macOS trataria el perfil como otro
    // distinto y el usuario acabaria con dos cuentas duplicadas.
    const a = generarPerfilApple(base);
    const b = generarPerfilApple({ ...base, nombre: "Brenda Ruiz" });
    const uuid = (s: string) => s.match(/<key>PayloadUUID<\/key><string>([^<]+)/)![1];
    assert.equal(uuid(a), uuid(b));
  });

  it("buzones distintos producen UUIDs distintos", () => {
    const uuid = (s: string) => s.match(/<key>PayloadUUID<\/key><string>([^<]+)/)![1];
    assert.notEqual(
      uuid(generarPerfilApple(base)),
      uuid(generarPerfilApple({ direccion: "ventas@brendago.design", dominio: "brendago.design" })),
    );
  });

  it("🔴 escapa el XML: un apóstrofo rompería el plist entero", () => {
    const p = generarPerfilApple({ ...base, nombre: "Brenda O'Hara & Co <jefa>" });
    assert.ok(p.includes("Brenda O&apos;Hara &amp; Co &lt;jefa&gt;"));
    assert.equal(p.includes("O'Hara"), false);
  });

  it("sin servidor de salida repite el de entrada y reusa la contraseña", () => {
    // Apple exige host de salida aunque la cuenta sea de solo lectura: omitirlo
    // hace fallar la instalacion entera, no solo el envio.
    const p = generarPerfilApple(base);
    assert.ok(p.includes(`<key>OutgoingMailServerHostName</key><string>${IMAP_HOST}</string>`));
    assert.ok(p.includes("<key>OutgoingPasswordSameAsIncoming</key><true/>"));
  });

  it("con servidor de salida propio, pide su contraseña aparte", () => {
    const p = generarPerfilApple({
      ...base,
      salida: { host: "email-smtp.us-east-1.amazonaws.com", puerto: 587, usuario: "AKIAEJEMPLO" },
    });
    assert.ok(p.includes("<key>OutgoingMailServerHostName</key><string>email-smtp.us-east-1.amazonaws.com</string>"));
    assert.ok(p.includes("<key>OutgoingMailServerPortNumber</key><integer>587</integer>"));
    assert.ok(p.includes("<key>OutgoingPasswordSameAsIncoming</key><false/>"));
  });

  it("nunca incluye la contraseña del buzón", () => {
    // El perfil se descarga por HTTP y puede quedar en Descargas: que pida la
    // contraseña al instalar es lo correcto.
    const p = generarPerfilApple(base);
    assert.equal(/Password<\/key>\s*<string>/.test(p), false);
  });

  it("el nombre de archivo no permite caracteres raros de ruta", () => {
    assert.equal(nombreArchivoPerfil("brenda@brendago.design"), "brenda_brendago.design.mobileconfig");
    assert.equal(nombreArchivoPerfil("../../etc/passwd"), ".._.._etc_passwd.mobileconfig");
  });
});
