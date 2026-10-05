import assert from "node:assert/strict"
import { describe, it } from "node:test"
import { hasNavMarker, parseNavParts, resolveNavTarget } from "./navMarker"

// Portado de agenda con la allowlist de /app (`dominio/<id>[/<pestaña>]`).

describe("resolveNavTarget", () => {
  it("acepta el detalle de un dominio", () => {
    assert.deepStrictEqual(resolveNavTarget("dominio/abc-123"), {
      to: "dominio/abc-123",
      label: "Ver dominio",
    })
  })

  it("acepta una pestaña conocida", () => {
    assert.equal(resolveNavTarget("dominio/abc123/dns")?.label, "Ver DNS")
    assert.equal(resolveNavTarget("dominio/abc123/aliases")?.label, "Ver direcciones")
  })

  describe("rechaza lo que no es un destino de /app", () => {
    for (const raw of [
      "https://evil.com",
      "//evil.com",
      "javascript:alert(1)",
      "dominio/../admin",
      "dominio/abc/../../x",
      "dominio/abc/inexistente",
      "dominio/abc/dns/extra",
      "dominio/",
      "/dash/agenda",
      "",
    ]) {
      it(JSON.stringify(raw), () => assert.equal(resolveNavTarget(raw), null))
    }
  })
})

describe("parseNavParts", () => {
  it("parte el texto y deja el botón donde el modelo lo puso", () => {
    const parts = parseNavParts("Ya lo creé. [[ir:dominio/abc/aliases]] Avísame.")
    assert.deepStrictEqual(
      parts.map((p) => p.type),
      ["text", "nav", "text"],
    )
    assert.deepStrictEqual(parts[0], { type: "text", value: "Ya lo creé. " })
  })

  it("un destino inválido se queda como TEXTO, no desaparece", () => {
    const parts = parseNavParts("Mira esto [[ir:https://evil.com]] ahí.")
    assert.equal(parts.length, 1)
    assert.equal(parts[0].type, "text")
    assert.match((parts[0] as { value: string }).value, /evil\.com/)
  })

  it("recorta un marcador a medio escribir mientras streamea", () => {
    const parts = parseNavParts("Listo. [[ir:domi", true)
    assert.equal((parts[0] as { value: string }).value, "Listo. ")
  })

  it("soporta varios marcadores", () => {
    const parts = parseNavParts("[[ir:dominio/a/dns]] y [[ir:dominio/b]]")
    assert.equal(parts.filter((p) => p.type === "nav").length, 2)
  })
})

describe("hasNavMarker", () => {
  it("es estable entre llamadas (la regex es global)", () => {
    const t = "Listo [[ir:dominio/a/dns]]"
    assert.equal(hasNavMarker(t), true)
    assert.equal(hasNavMarker(t), true)
  })
})
