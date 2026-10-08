import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { evaluateInboundMx, checkInboundMx, domainFlagStatus, FLAGS_TTL_MS } from "./domain-flags.ts";

const ses = "inbound-smtp.us-east-1.amazonaws.com";

describe("domain-flags", () => {
  it("evaluateInboundMx: SES con la prioridad más alta es ok; otro antes o ninguno, no", () => {
    assert.equal(evaluateInboundMx([{ priority: 10, exchange: ses }]).ok, true);
    assert.equal(evaluateInboundMx([{ priority: 10, exchange: `${ses}.` }]).ok, true);
    assert.equal(evaluateInboundMx([{ priority: 5, exchange: "mx1.hostinger.com" }, { priority: 10, exchange: ses }]).ok, false);
    assert.equal(evaluateInboundMx([{ priority: 10, exchange: "aspmx.l.google.com" }]).ok, false);
  });

  it("checkInboundMx: sin MX es una respuesta; un timeout no es dato", async () => {
    const err = (code: string) => async () => { throw Object.assign(new Error(code), { code }); };
    assert.deepEqual(await checkInboundMx("x.com", async () => [{ priority: 10, exchange: ses }]), { ok: true, detail: "MX configurado correctamente (prioridad 10)", resolved: true });
    assert.equal((await checkInboundMx("x.com", err("ENODATA"))).resolved, true);
    const t = await checkInboundMx("x.com", err("ETIMEOUT"));
    assert.equal(t.resolved, false);
    assert.equal(t.ok, false);
  });

  it("domainFlagStatus: más de 24 h o nunca = unknown", () => {
    const base = { id: "d", ownerEmail: "a@b.c", domain: "x.com", verified: true, mxConfigured: false, dkimTokens: [], verificationToken: "t", createdAt: "" };
    const now = Date.now();
    assert.equal(domainFlagStatus({ ...base, healthCheckedAt: null }, now).mxStatus, "unknown");
    const fresco = domainFlagStatus({ ...base, healthCheckedAt: new Date(now - 1000).toISOString() }, now);
    assert.deepEqual([fresco.mxStatus, fresco.verifiedStatus, fresco.statusNote], ["missing", "ok", undefined]);
    assert.equal(domainFlagStatus({ ...base, healthCheckedAt: new Date(now - FLAGS_TTL_MS - 1).toISOString() }, now).verifiedStatus, "unknown");
  });
});
