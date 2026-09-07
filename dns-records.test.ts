// Validación, convivencia y guardián de los registros DNS. Todo puro: sin AWS ni base.
//
// Es el test más barato de la función y el que más cubre: cada mensaje de error de aquí es
// lo que va a leer un agente de IA para autocorregirse, así que se fijan también los casos
// que un LLM intentaría — borrar el MX, sustituir el SPF, meter un CNAME en la raíz.

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  normalizarNombre, normalizarTxt, validarRRSet, conflictoDeConvivencia,
  registrosGestionados, anotarRegistros, aplicarGuardian, fusionarSpfValores,
  expandirPreset, ErrorDns, type RRSet,
} from "./dns-records.ts";

const D = "ejemplo.com";
const dominio = { domain: D, verificationToken: "tok", dkimTokens: ["a1", "b2", "c3"] };
const rr = (name: string, type: string, values: string[], ttl = 300) =>
  ({ name, type, ttl, values }) as RRSet;

describe("normalizarNombre", () => {
  it("resuelve las formas de la raíz", () => {
    for (const entrada of ["@", "", "ejemplo.com", "ejemplo.com.", "EJEMPLO.COM"]) {
      assert.equal(normalizarNombre(entrada, D), D);
    }
  });

  it("completa los relativos y respeta los absolutos", () => {
    assert.equal(normalizarNombre("www", D), "www.ejemplo.com");
    assert.equal(normalizarNombre("www.ejemplo.com", D), "www.ejemplo.com");
    assert.equal(normalizarNombre("a.b", D), "a.b.ejemplo.com");
  });

  it("acepta el comodín sólo al principio", () => {
    assert.equal(normalizarNombre("*", D), "*.ejemplo.com");
    assert.throws(() => normalizarNombre("a.*.b", D), /comodín/);
  });

  it("rechaza etiquetas inválidas y demasiado largas", () => {
    assert.throws(() => normalizarNombre("a..b", D), /punto de más/);
    assert.throws(() => normalizarNombre("x".repeat(64), D), /63/);
    assert.throws(() => normalizarNombre("con espacio", D), /no se permiten/);
  });
});

describe("validarRRSet", () => {
  it("acepta un CNAME normal y le quita el punto final", () => {
    const r = validarRRSet(rr("www", "cname", ["cname.vercel-dns.com."]), D);
    assert.deepEqual(r, { name: "www.ejemplo.com", type: "CNAME", ttl: 300, values: ["cname.vercel-dns.com"] });
  });

  it("rechaza un CNAME en la raíz y explica la salida", () => {
    assert.throws(() => validarRRSet(rr("@", "CNAME", ["algo.vercel.app"]), D), (e: ErrorDns) => {
      assert.match(e.message, /raíz del dominio/);
      assert.match(e.message, /'www'|www/);
      return true;
    });
  });

  it("rechaza un CNAME con más de un valor", () => {
    assert.throws(() => validarRRSet(rr("www", "CNAME", ["a.com", "b.com"]), D), /un valor/);
  });

  it("valida el TTL en ambos extremos", () => {
    assert.throws(() => validarRRSet(rr("www", "A", ["1.2.3.4"], 30), D), /entre 60 y 172800/);
    assert.throws(() => validarRRSet(rr("www", "A", ["1.2.3.4"], 999999), D), /entre 60 y 172800/);
    assert.equal(validarRRSet(rr("www", "A", ["1.2.3.4"], 60), D).ttl, 60);
  });

  it("valida direcciones", () => {
    assert.throws(() => validarRRSet(rr("www", "A", ["300.1.1.1"]), D), /IPv4/);
    assert.throws(() => validarRRSet(rr("www", "A", ["no-una-ip"]), D), /IPv4/);
    assert.equal(validarRRSet(rr("www", "AAAA", ["2606:4700::1111"]), D).values[0], "2606:4700::1111");
  });

  it("exige la prioridad en MX y la normaliza", () => {
    assert.throws(() => validarRRSet(rr("@", "MX", ["mail.ejemplo.com"]), D), (e: ErrorDns) => {
      assert.match(e.message, /prioridad/);
      // El mensaje trae el ejemplo completo: es lo que hace que un agente lo arregle solo.
      assert.match(e.message, /"10 mail\.ejemplo\.com"/);
      return true;
    });
    assert.deepEqual(validarRRSet(rr("@", "MX", ["010  mail.ejemplo.com."]), D).values, ["10 mail.ejemplo.com"]);
  });

  it("parte un TXT largo en cadenas de 255", () => {
    // Es donde se atora todo el mundo al pegar una clave DKIM de otro proveedor.
    const largo = "k".repeat(600);
    const v = validarRRSet(rr("dkim", "TXT", [largo]), D).values[0];
    const trozos = v.match(/"[^"]*"/g)!;
    assert.equal(trozos.length, 3);
    assert.ok(trozos.every((t) => t.length - 2 <= 255));
    assert.equal(trozos.map((t) => t.slice(1, -1)).join(""), largo);
  });

  it("no re-entrecomilla un TXT que ya venía con comillas", () => {
    assert.equal(validarRRSet(rr("@", "TXT", ['"hola"']), D).values[0], '"hola"');
  });

  it("rechaza los NS de la raíz", () => {
    assert.throws(() => validarRRSet(rr("@", "NS", ["ns1.otro.com"]), D), /registrador/);
    assert.equal(validarRRSet(rr("sub", "NS", ["ns1.otro.com"]), D).values[0], "ns1.otro.com");
  });

  it("valida CAA y SRV", () => {
    assert.equal(validarRRSet(rr("@", "CAA", ['0 issue "letsencrypt.org"']), D).values[0], '0 issue "letsencrypt.org"');
    assert.throws(() => validarRRSet(rr("@", "CAA", ["issue letsencrypt.org"]), D), /0 issue/);
    assert.equal(validarRRSet(rr("_sip._tcp", "SRV", ["10 5 5060 sip.ejemplo.com"]), D).values.length, 1);
    assert.throws(() => validarRRSet(rr("sip", "SRV", ["10 5 5060 sip.ejemplo.com"]), D), /_servicio\._protocolo/);
  });

  it("rechaza tipos desconocidos, listas vacías y duplicados", () => {
    assert.throws(() => validarRRSet(rr("www", "SPF", ["x"]), D), /no está soportado/);
    assert.throws(() => validarRRSet(rr("www", "A", []), D), /al menos un valor/);
    assert.throws(() => validarRRSet(rr("www", "A", ["1.2.3.4", "1.2.3.4"]), D), /repetidos/);
  });
});

describe("conflictoDeConvivencia", () => {
  const existentes = [rr("www.ejemplo.com", "A", ["1.2.3.4"]), rr("mail.ejemplo.com", "CNAME", ["x.com"])];

  it("no deja un CNAME donde ya hay otro tipo", () => {
    assert.match(conflictoDeConvivencia(rr("www.ejemplo.com", "CNAME", ["x.com"]), existentes)!, /Ya existe un registro A/);
  });

  it("no deja otro tipo donde ya hay un CNAME", () => {
    assert.match(conflictoDeConvivencia(rr("mail.ejemplo.com", "A", ["1.2.3.4"]), existentes)!, /Ya existe un CNAME/);
  });

  it("deja reemplazar el mismo tipo y usar otro nombre", () => {
    assert.equal(conflictoDeConvivencia(rr("www.ejemplo.com", "A", ["9.9.9.9"]), existentes), null);
    assert.equal(conflictoDeConvivencia(rr("otro.ejemplo.com", "CNAME", ["x.com"]), existentes), null);
  });
});

describe("guardián de los registros de MailMask", () => {
  it("marca los cinco registros gestionados", () => {
    const g = registrosGestionados(dominio);
    assert.equal(g.filter((x) => x.type === "CNAME").length, 3);
    assert.ok(g.some((x) => x.name === "ejemplo.com" && x.type === "MX" && x.modo === "total"));
    assert.ok(g.some((x) => x.name === "_amazonses.ejemplo.com" && x.modo === "total"));
    // El TXT de la raíz es parcial: ahí también van las verificaciones de otros servicios.
    assert.ok(g.some((x) => x.name === "ejemplo.com" && x.type === "TXT" && x.modo === "parcial"));
  });

  it("no deja borrar ni cambiar el MX", () => {
    const mx = rr("ejemplo.com", "MX", ["10 otro.com"]);
    for (const accion of ["upsert", "delete"] as const) {
      const e = aplicarGuardian(accion, mx, dominio);
      assert.ok(e, `debería rechazar ${accion}`);
      assert.match(e!.message, /dejas de recibir correo/);
      // Y le dice al agente cuál es la salida legítima, para que no busque un force.
      assert.match(e!.message, /elimina el dominio de MailMask/);
    }
  });

  it("no deja tocar el TXT de verificación ni los CNAME de DKIM", () => {
    assert.ok(aplicarGuardian("upsert", rr("_amazonses.ejemplo.com", "TXT", ['"otro"']), dominio));
    assert.ok(aplicarGuardian("delete", rr("a1._domainkey.ejemplo.com", "CNAME", ["x"]), dominio));
  });

  it("no deja borrar el SPF del apex, y sugiere el arreglo", () => {
    const e = aplicarGuardian("upsert", rr("ejemplo.com", "TXT", ['"google-site-verification=abc"']), dominio);
    assert.ok(e);
    assert.match(e!.message, /caer en spam/);
    // El 409 trae los valores ya fusionados para que el agente reintente sin razonar.
    assert.ok(e!.suggestedValues!.includes('"google-site-verification=abc"'));
    assert.ok(e!.suggestedValues!.some((v) => v.includes("include:amazonses.com")));
  });

  it("deja añadir un TXT a la raíz conservando el SPF", () => {
    const ok = rr("ejemplo.com", "TXT", ['"v=spf1 include:amazonses.com ~all"', '"stripe-verification=1"']);
    assert.equal(aplicarGuardian("upsert", ok, dominio), null);
  });

  it("no deja borrar el TXT del apex entero, aunque sea parcial", () => {
    assert.ok(aplicarGuardian("delete", rr("ejemplo.com", "TXT", ['"v=spf1 include:amazonses.com ~all"']), dominio));
  });

  it("deja en paz lo que no es nuestro, incluido el DKIM de otro proveedor", () => {
    assert.equal(aplicarGuardian("upsert", rr("www.ejemplo.com", "CNAME", ["x.com"]), dominio), null);
    assert.equal(aplicarGuardian("upsert", rr("google._domainkey.ejemplo.com", "TXT", ['"v=DKIM1"']), dominio), null);
  });

  it("protege los NS de la raíz, que son de Route 53", () => {
    assert.ok(aplicarGuardian("upsert", rr("ejemplo.com", "NS", ["ns1.otro.com"]), dominio));
  });
});

describe("anotarRegistros", () => {
  it("marca gestionados, editables y los valores protegidos", () => {
    const anotados = anotarRegistros([
      rr("ejemplo.com", "MX", ["10 inbound-smtp.us-east-1.amazonaws.com"]),
      rr("ejemplo.com", "TXT", ['"v=spf1 include:amazonses.com ~all"', '"otra=cosa"']),
      rr("www.ejemplo.com", "CNAME", ["x.com"]),
    ], dominio);

    assert.deepEqual(
      anotados.map((r) => [r.managed, r.editable]),
      [[true, false], [true, true], [false, true]],
    );
    assert.deepEqual(anotados[1].protectedValues, ['"v=spf1 include:amazonses.com ~all"']);
    assert.ok(anotados[0].managedReason);
  });
});

describe("fusionarSpfValores", () => {
  it("mete el include antes del all y deja un solo SPF", () => {
    const r = fusionarSpfValores(['"v=spf1 include:_spf.google.com ~all"', '"verif=1"']);
    assert.equal(r.filter((v) => v.includes("v=spf1")).length, 1);
    const spf = r.find((v) => v.includes("v=spf1"))!;
    assert.equal(spf, '"v=spf1 include:_spf.google.com include:amazonses.com ~all"');
    assert.ok(r.includes('"verif=1"'));
  });

  it("añade el all si el SPF previo no lo traía", () => {
    assert.equal(fusionarSpfValores(['"v=spf1 mx"'])[0], '"v=spf1 mx include:amazonses.com"');
  });

  it("es idempotente", () => {
    const una = fusionarSpfValores([]);
    assert.deepEqual(fusionarSpfValores(una), una);
  });
});

describe("presets", () => {
  it("Vercel: A en la raíz y CNAME en www", () => {
    const r = expandirPreset("vercel", D, "mi-proyecto.vercel.app");
    assert.deepEqual(r.map((x) => [x.name, x.type]), [["ejemplo.com", "A"], ["www.ejemplo.com", "CNAME"]]);
  });

  it("Vercel con subdominio: sólo el CNAME", () => {
    const r = expandirPreset("vercel", D, "mi-proyecto.vercel.app", "app");
    assert.deepEqual(r, [{ name: "app.ejemplo.com", type: "CNAME", ttl: 300, values: ["mi-proyecto.vercel.app"] }]);
  });

  it("GitHub Pages trae las cuatro IPs", () => {
    assert.equal(expandirPreset("github-pages", D, "usuario.github.io")[0].values.length, 4);
  });

  it("exige el destino y rechaza plantillas que no existen", () => {
    assert.throws(() => expandirPreset("vercel", D), /Falta el destino/);
    assert.throws(() => expandirPreset("no-existe" as any, D, "x"), /No conozco la plantilla/);
  });

  it("lo que sale de un preset pasa la validación", () => {
    for (const r of expandirPreset("dmarc", D, "yo@correo.com")) validarRRSet(r, D);
    for (const r of expandirPreset("netlify", D, "sitio.netlify.app")) validarRRSet(r, D);
  });
});

describe("normalizarTxt", () => {
  it("junta las cadenas ya partidas antes de volver a partir", () => {
    assert.equal(normalizarTxt('"abc" "def"'), '"abcdef"');
  });

  it("escapa las comillas internas", () => {
    assert.equal(normalizarTxt('di "hola"'), '"di \\"hola\\""');
  });
});

describe("enTandas (freno de consultas DNS)", () => {
  it("respeta el tope de simultáneas y conserva el orden", async () => {
    // Sin freno se disparaban ~150 consultas de golpe contra el servidor autoritativo del
    // cliente; empezaba a descartarlas y el inventario salía incompleto y distinto en cada
    // corrida. Con brendago.design eso era la diferencia entre 4 registros y 12.
    const { enTandas } = await import("./dns-import.ts");
    let vivas = 0;
    let pico = 0;

    const tareas = Array.from({ length: 25 }, (_, i) => async () => {
      vivas++;
      pico = Math.max(pico, vivas);
      await new Promise((r) => setTimeout(r, 5));
      vivas--;
      return i;
    });

    const salida = await enTandas(tareas, 6);
    assert.ok(pico <= 6, `se dispararon ${pico} a la vez`);
    assert.deepEqual(salida, [...Array(25).keys()], "se perdió el orden de los resultados");
  });

  it("no se atora si no hay tareas", async () => {
    const { enTandas } = await import("./dns-import.ts");
    assert.deepEqual(await enTandas([], 6), []);
  });
});
