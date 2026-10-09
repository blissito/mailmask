// Los registros de autodescubrimiento: uno por dominio, apuntando al servidor IMAP.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { autoconfigRRSets, ensureMailAutoconfig } from "./mail-autoconfig.ts";

describe("mail-autoconfig", () => {
  it("SRV de Outlook y CNAME de Thunderbird al host IMAP", () => {
    assert.deepEqual(autoconfigRRSets("Kandey.com.mx"), [
      { name: "_autodiscover._tcp.kandey.com.mx", type: "SRV", ttl: 3600, values: ["0 0 443 imap.mailmask.studio"] },
      { name: "autoconfig.kandey.com.mx", type: "CNAME", ttl: 3600, values: ["imap.mailmask.studio"] },
    ]);
  });

  it("sin zona nuestra no toca nada", async () => {
    assert.equal(await ensureMailAutoconfig({ domain: "ejemplo.com", hostedZoneId: null }), 0);
  });
});
