import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { MailMask } from "@easybits.cloud/mailmask";
import { resolveDomainId } from "../src/resolve.js";

function fakeClient(domains: Array<{ id: string; domain: string }>): MailMask {
  return { domains: { list: async () => domains as never } } as unknown as MailMask;
}

describe("resolveDomainId", () => {
  it("resuelve por nombre de dominio", async () => {
    const client = fakeClient([{ id: "dom_1", domain: "acme.com" }]);
    assert.equal(await resolveDomainId(client, "acme.com"), "dom_1");
  });

  it("resuelve por id si ya es un id", async () => {
    const client = fakeClient([{ id: "dom_1", domain: "acme.com" }]);
    assert.equal(await resolveDomainId(client, "dom_1"), "dom_1");
  });

  it("deja pasar el valor tal cual si no aparece en la lista", async () => {
    const client = fakeClient([{ id: "dom_1", domain: "acme.com" }]);
    assert.equal(await resolveDomainId(client, "otro.com"), "otro.com");
  });
});
