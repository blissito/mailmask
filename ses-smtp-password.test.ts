import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { deriveSesSmtpPassword } from "./ses.ts";

describe("Contraseña SMTP de SES", () => {
  it("🔴 coincide con el algoritmo de AWS", async () => {
    // Vector calculado aparte con la receta publicada por AWS: cinco HMAC
    // encadenados —fecha, región, "ses", "aws4_request", "SendRawEmail"— y el
    // byte de versión 0x04 ANTEPUESTO, nunca dentro del HMAC.
    //
    // Faltaban los dos últimos pasos. La contraseña salía con pinta correcta y
    // SES la rechazaba siempre con 535, así que el relay SMTP del plan Equipo
    // nunca funcionó. Sin esta prueba el bug es invisible: no hay error al
    // generarla, sólo al usarla.
    const clave = await deriveSesSmtpPassword("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1");
    assert.equal(clave, "BOntiZFm/r+5s3psZ/RpsjB+aSGsj2J0rXdiLuO0cQL7");
  });

  it("la región cambia el resultado", async () => {
    const a = await deriveSesSmtpPassword("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1");
    const b = await deriveSesSmtpPassword("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "eu-west-1");
    assert.notEqual(a, b);
  });

  it("empieza con el byte de versión 0x04", async () => {
    const clave = await deriveSesSmtpPassword("otro-secreto-de-prueba", "us-east-1");
    assert.equal(Buffer.from(clave, "base64")[0], 0x04);
    assert.equal(Buffer.from(clave, "base64").length, 33);
  });
});
