// El inventario del DNS de un dominio que todavía vive en otro proveedor (`dns-import.ts`),
// sin salir a la red.
//
// De esta lógica depende que a un cliente no se le caiga la web ni el correo al cambiar los
// nameservers: si el inventario omite un registro, ese registro deja de existir cuando el
// dominio ya apunta a nosotros. `dns-api.test.ts` dobla `dns-import.ts` entero, así que hasta
// ahora su lógica real —qué nombres pregunta, cómo descarta el eco de un CNAME y a qué
// servidores le pregunta— no corría en ninguna prueba. Ficha: `docs/agents/pruebas-mocks.md`.

import { describe, it, before, beforeEach, afterEach, mock } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import type { RRSet } from "./dns-records.ts";

type Tipo = "A" | "AAAA" | "CNAME" | "MX" | "TXT" | "CAA" | "NS";

/** Lo que el resolver falso responde para un `nombre|TIPO`, o el fallo que lanza. */
type Entrada = { valor: unknown; ttl: number } | { error: "ENOTFOUND" | "ENODATA" };

const tabla = new Map<string, Entrada>();
/** Todos los resolvers creados en la prueba en curso, en orden. */
const resolvers: FakeResolver[] = [];
/** Con esto en true las consultas de registros no contestan nunca: prueba el corte sin esperarlo. */
let colgado = false;

const llave = (nombre: string, tipo: Tipo) => `${nombre}|${tipo}`;

function sembrar(nombre: string, tipo: Tipo, valor: unknown, ttl = 300): void {
  tabla.set(llave(nombre, tipo), { valor, ttl });
}

/** Un nombre que responde con error en vez de con registros (ENOTFOUND es lo normal). */
function fallar(nombre: string, tipo: Tipo, code: "ENOTFOUND" | "ENODATA" = "ENOTFOUND"): void {
  tabla.set(llave(nombre, tipo), { error: code });
}

function errorDns(code: string): Error & { code: string } {
  const e = new Error(`queryA ${code}`) as Error & { code: string };
  e.code = code;
  return e;
}

/** El doble de `Resolver`: lee una tabla en vez de preguntarle al DNS de verdad. */
class FakeResolver {
  servidores: string[] = [];
  consultas: string[] = [];

  constructor(public opciones?: unknown) {
    resolvers.push(this);
  }

  setServers(servidores: string[]): void {
    this.servidores = servidores;
  }

  private entrada(nombre: string, tipo: Tipo): { valor: unknown; ttl: number } {
    const e = tabla.get(llave(nombre, tipo));
    if (!e) throw errorDns("ENOTFOUND");
    if ("error" in e) throw errorDns(e.error);
    return e;
  }

  /** Consulta que nunca responde: prueba el corte sin esperar los 45 s. */
  private cuelga(nombre: string, tipo: Tipo): Promise<never> {
    this.consultas.push(llave(nombre, tipo));
    return new Promise<never>(() => {});
  }

  async resolve4(nombre: string, opciones?: { ttl?: boolean }): Promise<unknown> {
    if (colgado) return this.cuelga(nombre, "A");
    this.consultas.push(llave(nombre, "A"));
    const e = this.entrada(nombre, "A");
    const direcciones = e.valor as string[];
    // Como el Resolver real: sin `ttl: true` devuelve direcciones pelonas.
    return opciones?.ttl ? direcciones.map((address) => ({ address, ttl: e.ttl })) : direcciones;
  }

  async resolve6(nombre: string, opciones?: { ttl?: boolean }): Promise<unknown> {
    if (colgado) return this.cuelga(nombre, "AAAA");
    this.consultas.push(llave(nombre, "AAAA"));
    const e = this.entrada(nombre, "AAAA");
    const direcciones = e.valor as string[];
    return opciones?.ttl ? direcciones.map((address) => ({ address, ttl: e.ttl })) : direcciones;
  }

  async resolveCname(nombre: string): Promise<string[]> {
    if (colgado) return this.cuelga(nombre, "CNAME");
    this.consultas.push(llave(nombre, "CNAME"));
    return this.entrada(nombre, "CNAME").valor as string[];
  }

  async resolveMx(nombre: string): Promise<unknown> {
    if (colgado) return this.cuelga(nombre, "MX");
    this.consultas.push(llave(nombre, "MX"));
    return this.entrada(nombre, "MX").valor;
  }

  async resolveTxt(nombre: string): Promise<unknown> {
    if (colgado) return this.cuelga(nombre, "TXT");
    this.consultas.push(llave(nombre, "TXT"));
    return this.entrada(nombre, "TXT").valor;
  }

  async resolveCaa(nombre: string): Promise<unknown> {
    if (colgado) return this.cuelga(nombre, "CAA");
    this.consultas.push(llave(nombre, "CAA"));
    return this.entrada(nombre, "CAA").valor;
  }

  async resolveNs(nombre: string): Promise<string[]> {
    // Los NS sí contestan aunque los registros estén colgados: si no, `snapshotDns` se
    // quedaría antes de armar el corte y la prueba del timeout no probaría nada.
    this.consultas.push(llave(nombre, "NS"));
    return this.entrada(nombre, "NS").valor as string[];
  }
}

/** Un dominio propio por prueba: la tabla es compartida y nadie más lo usa. */
const dominio = () => `t-${randomUUID().slice(0, 8)}.mx`;

/** El resolver al que `snapshotDns` le pidió los registros del apex (no los de sus NS). */
function resolverDeRegistros(dom: string): FakeResolver {
  const r = resolvers.find((x) => x.consultas.includes(`${dom}|A`) || x.consultas.includes(`${dom}|MX`));
  assert.ok(r, "ningún resolver falso recibió las consultas del apex");
  return r;
}

function buscar(found: RRSet[], name: string, type: string): RRSet {
  const r = found.find((x) => x.name === name && x.type === type);
  assert.ok(
    r,
    `faltó ${name} ${type} en el inventario: ${found.map((f) => `${f.name}/${f.type}`).join(", ") || "(vacío)"}`,
  );
  return r;
}

describe("inventario de DNS sin red", () => {
  let dns: typeof import("./dns-import.ts");

  before(async () => {
    const real = await import("node:dns/promises");
    // El doble va ANTES del import, y con el módulo real esparcido: sin `...real`, cualquier
    // otra cosa que importe de `node:dns/promises` se queda sin la suya.
    mock.module("node:dns/promises", { namedExports: { ...real, Resolver: FakeResolver } });
    dns = await import("./dns-import.ts");
  });

  beforeEach(() => {
    tabla.clear();
    resolvers.length = 0;
    colgado = false;
    // `snapshotDns` deja vivo un setTimeout de 45 s que nunca limpia: con timers de verdad
    // cada prueba mantendría el proceso abierto otros 45 s después de terminar.
    mock.timers.enable({ apis: ["setTimeout"] });
  });

  afterEach(() => {
    mock.timers.reset();
  });

  it("trae los nombres comunes que responden, con su tipo y sus valores", async () => {
    const dom = dominio();
    sembrar(dom, "A", ["203.0.113.10"], 1234);
    sembrar(dom, "MX", [{ priority: 10, exchange: "mx.proveedor.com" }]);
    sembrar(dom, "TXT", [["v=spf1 include:_spf.proveedor.com -all"]]);
    sembrar(`www.${dom}`, "A", ["203.0.113.11"]);
    sembrar(`mail.${dom}`, "A", ["203.0.113.12"]);

    const inv = await dns.snapshotDns(dom);

    assert.equal(buscar(inv.found, dom, "A").ttl, 1234, "el TTL del A no se respetó");
    assert.deepEqual(buscar(inv.found, dom, "A").values, ["203.0.113.10"]);
    assert.deepEqual(buscar(inv.found, dom, "MX").values, ["10 mx.proveedor.com"]);
    assert.deepEqual(buscar(inv.found, dom, "TXT").values, ['"v=spf1 include:_spf.proveedor.com -all"']);
    assert.deepEqual(buscar(inv.found, `www.${dom}`, "A").values, ["203.0.113.11"]);
    assert.deepEqual(buscar(inv.found, `mail.${dom}`, "A").values, ["203.0.113.12"]);
    assert.equal(inv.truncado, false);
  });

  it("un A sin TTL cae al default de 300", async () => {
    const dom = dominio();
    sembrar(dom, "A", ["203.0.113.13"], 0);

    const inv = await dns.snapshotDns(dom);

    assert.equal(buscar(inv.found, dom, "A").ttl, 300);
  });

  it("rejunta las cadenas de un TXT y lo vuelve a entrecomillar", async () => {
    const dom = dominio();
    // `resolveTxt` entrega cada respuesta partida en trozos, y sin comillas.
    sembrar(dom, "TXT", [["v=DKIM1; ", "p=abc"], ['google-site-verification="xy"']]);

    const inv = await dns.snapshotDns(dom);

    assert.deepEqual(buscar(inv.found, dom, "TXT").values, [
      '"v=DKIM1; p=abc"',
      '"google-site-verification=\\"xy\\""',
    ]);
  });

  it("un nombre que responde ENOTFOUND o ENODATA no aparece y no rompe el inventario", async () => {
    const dom = dominio();
    sembrar(dom, "A", ["203.0.113.20"]);
    sembrar(`www.${dom}`, "A", ["203.0.113.21"]);
    fallar(`blog.${dom}`, "A", "ENOTFOUND");
    fallar(`_dmarc.${dom}`, "TXT", "ENODATA");

    const inv = await dns.snapshotDns(dom);

    assert.ok(!inv.found.some((r) => r.name.startsWith("blog.")), "blog apareció pese al ENOTFOUND");
    assert.ok(!inv.found.some((r) => r.name.startsWith("_dmarc.")), "_dmarc apareció pese al ENODATA");
    assert.deepEqual(buscar(inv.found, dom, "A").values, ["203.0.113.20"]);
    assert.deepEqual(buscar(inv.found, `www.${dom}`, "A").values, ["203.0.113.21"]);
  });

  it("si un nombre es CNAME, se queda sólo el CNAME y no el eco A/TXT del destino", async () => {
    const dom = dominio();
    sembrar(`mail.${dom}`, "CNAME", ["mail.proveedor.com"]);
    // El resolver sigue el CNAME: preguntarle A o TXT devuelve los del destino, no los suyos.
    sembrar(`mail.${dom}`, "A", ["203.0.113.30"]);
    sembrar(`mail.${dom}`, "TXT", [["v=spf1 -all"]]);

    const inv = await dns.snapshotDns(dom);

    const deMail = inv.found.filter((r) => r.name === `mail.${dom}`);
    assert.deepEqual(deMail.map((r) => r.type), ["CNAME"]);
    assert.deepEqual(deMail[0].values, ["mail.proveedor.com"]);
  });

  it("le pregunta a los nameservers del dominio y no a los públicos", async () => {
    const dom = dominio();
    sembrar(dom, "NS", ["NS1.Viejo.com."]);
    sembrar("ns1.viejo.com", "A", ["203.0.113.5"]);
    sembrar(dom, "A", ["203.0.113.40"]);

    const inv = await dns.snapshotDns(dom);

    assert.deepEqual(resolverDeRegistros(dom).servidores, ["203.0.113.5"]);
    assert.deepEqual(inv.nameservers, ["ns1.viejo.com"]);
    assert.deepEqual(buscar(inv.found, dom, "A").values, ["203.0.113.40"]);
  });

  it("si los nameservers del dominio no resuelven a IP, cae a los públicos", async () => {
    const dom = dominio();
    sembrar(dom, "NS", ["ns-sin-ip.proveedor.com"]);
    sembrar(dom, "A", ["203.0.113.41"]);

    await dns.snapshotDns(dom);

    assert.deepEqual(resolverDeRegistros(dom).servidores, ["8.8.8.8", "1.1.1.1"]);
  });

  it("extraNames alcanza selectores que la heurística no puede adivinar", async () => {
    const dom = dominio();
    sembrar(`abc123._domainkey.${dom}`, "CNAME", ["abc123.dkim.amazonses.com"]);

    const sinExtra = await dns.snapshotDns(dom);
    assert.ok(!sinExtra.found.some((r) => r.name.startsWith("abc123.")), "apareció sin pedirlo");

    const conExtra = await dns.snapshotDns(dom, ["abc123._domainkey"]);
    assert.deepEqual(
      buscar(conExtra.found, `abc123._domainkey.${dom}`, "CNAME").values,
      ["abc123.dkim.amazonses.com"],
    );
  });

  it("un DNS que no contesta se corta solo y lo avisa", async () => {
    const dom = dominio();
    colgado = true;

    const pendiente = dns.snapshotDns(dom);
    // Deja que la consulta de NS (que sí contesta) termine y se arme el corte.
    await new Promise((listo) => setImmediate(listo));
    mock.timers.tick(45_000);
    const inv = await pendiente;

    assert.equal(inv.truncado, true);
    assert.match(inv.warning, /tardó demasiado/);
    assert.deepEqual(inv.found, []);
  });

  describe("getDelegationStatus", () => {
    it("basta uno de los nuestros, aunque venga en mayúsculas y con punto final", async () => {
      const dom = dominio();
      sembrar(dom, "NS", ["ns-1.awsdns-01.org.", "ns-viejo.proveedor.com"]);

      const st = await dns.getDelegationStatus(dom, ["NS-1.AWSDNS-01.ORG"]);

      assert.equal(st.delegated, true);
      assert.deepEqual(st.observed, ["ns-1.awsdns-01.org", "ns-viejo.proveedor.com"]);
      assert.deepEqual(st.expected, ["ns-1.awsdns-01.org"]);
    });

    it("con viejos y nuevos a la vez ya cuenta como delegado", async () => {
      const dom = dominio();
      sembrar(dom, "NS", ["ns-viejo.proveedor.com", "ns-2.awsdns-02.net"]);

      const st = await dns.getDelegationStatus(dom, ["ns-1.awsdns-01.org", "ns-2.awsdns-02.net"]);

      assert.equal(st.delegated, true);
    });

    it("si sólo se ven los viejos, todavía no", async () => {
      const dom = dominio();
      sembrar(dom, "NS", ["ns-viejo.proveedor.com"]);

      const st = await dns.getDelegationStatus(dom, ["ns-1.awsdns-01.org"]);

      assert.equal(st.delegated, false);
    });

    it("sin nameservers esperados nunca se declara delegado", async () => {
      const dom = dominio();
      sembrar(dom, "NS", ["ns-1.awsdns-01.org"]);

      const st = await dns.getDelegationStatus(dom, []);

      assert.equal(st.delegated, false);
      assert.deepEqual(st.expected, []);
    });

    it("si el dominio no responde, observed va vacío y no se declara delegado", async () => {
      const dom = dominio();

      const st = await dns.getDelegationStatus(dom, ["ns-1.awsdns-01.org"]);

      assert.equal(st.delegated, false);
      assert.deepEqual(st.observed, []);
    });
  });
});
