import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import PostalMime from "postal-mime";

// Contrato de postal-mime que usan outbound-relay.ts y dmarc-reports.ts: from, subject,
// messageId, html/text y attachments[].content. Si una versión nueva lo cambia, falla aquí.
describe("postal-mime: .eml con adjunto", () => {
  const raw = readFileSync(new URL("./fixtures/adjunto.eml", import.meta.url), "utf8");

  it("saca from con nombre codificado, subject, html y messageId", async () => {
    const p = await PostalMime.parse(raw);
    assert.equal(p.from?.name, "José Márquez");
    assert.equal(p.from?.address, "jose@cliente.test");
    assert.equal(p.subject, "Cotización año 2026");
    assert.equal(p.messageId, "<fixture-1@cliente.test>");
    assert.match(p.html ?? "", /<b>cotización<\/b>/);
    assert.match(p.text ?? "", /Va la cotizacion/);
  });

  it("saca el adjunto con nombre, tipo y contenido íntegro", async () => {
    const p = await PostalMime.parse(raw);
    assert.equal(p.attachments.length, 1);
    const [att] = p.attachments;
    assert.equal(att.filename, "cotizacion.pdf");
    assert.equal(att.mimeType, "application/pdf");
    assert.ok(att.content instanceof ArrayBuffer);
    assert.equal(Buffer.from(att.content as ArrayBuffer).toString("utf8"), "%PDF-1.4 reporte de prueba\n");
  });
});
