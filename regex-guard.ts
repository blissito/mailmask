/**
 * Defensa contra ReDoS en las reglas de dominio.
 *
 * Las reglas con `match: "regex"` las escribe el usuario y se evalúan contra cada
 * correo que entra. Un patrón con cuantificadores anidados —`(a+)+`, `(a*)*`— tarda
 * tiempo exponencial contra un texto que *casi* coincide: medido en Node 22,
 * `/^(a+)+$/` contra 30 caracteres tarda 4.6 s y contra 32, dieciocho segundos. Como
 * Node corre en un solo hilo, eso no ralentiza una petición: congela el proceso
 * entero, deja de responder el health check y la plataforma acaba reiniciando.
 *
 * Antes había un "guard" que corría la regex contra un `setTimeout` de 50 ms. No
 * servía de nada: `RegExp.test()` es síncrono, así que mientras corre el event loop
 * está bloqueado y el temporizador no puede dispararse. Se comprobó midiendo — el
 * guard de 50 ms devolvió su resultado a los 20 segundos.
 *
 * Lo que sí funciona, y es lo que hay aquí, son dos cosas baratas:
 *
 *  1. `revisarPatron()` rechaza la forma peligrosa **al guardar la regla**, una sola
 *     vez, en vez de intentar defenderse en cada correo.
 *  2. `acotarTexto()` limita cuánto texto se evalúa. Aunque un patrón peligroso se
 *     colara, el peor caso queda acotado por construcción.
 *
 * No pretende ser un analizador completo: eso es RE2 (`node-re2`), que garantiza
 * tiempo lineal y sigue siendo la solución de fondo si algún día hace falta admitir
 * expresiones arbitrarias. Esto ataja las formas que aparecen en la práctica.
 */

/**
 * Cuánto texto se evalúa contra una regex de regla.
 *
 * Un asunto real no pasa de un par de cientos de caracteres; el límite existe para el
 * asunto de 40 KB que llega justamente para hacer daño.
 */
export const MAX_TEXTO_REGEX = 1000;

/** Recorta el texto antes de evaluarlo con una regex de usuario. */
export function acotarTexto(valor: string): string {
  return valor.length > MAX_TEXTO_REGEX ? valor.slice(0, MAX_TEXTO_REGEX) : valor;
}

/** Longitud máxima del patrón que el usuario puede guardar. */
export const MAX_PATRON = 200;

interface Grupo {
  /** Ya se vio dentro un cuantificador que puede repetir sin tope. */
  tieneCuantificadorAbierto: boolean;
  /** Ramas de la alternancia de este grupo, para detectar `(a|a)+`. */
  ramas: string[];
  /** Texto de la rama en curso. */
  ramaActual: string;
}

/**
 * ¿El cuantificador que empieza en `i` puede repetir muchas veces?
 *
 * `+` y `*` sí. De `{n,m}` solo cuenta el que no tiene tope o lo tiene alto: `(a{2})+`
 * es inofensivo porque el número de repartos no crece.
 */
function cuantificadorAbierto(patron: string, i: number): { abierto: boolean; fin: number } | null {
  const c = patron[i];
  if (c === "+" || c === "*") return { abierto: true, fin: i };
  if (c !== "{") return null;
  const cierre = patron.indexOf("}", i);
  if (cierre === -1) return null; // una llave suelta es un literal, no un cuantificador
  const cuerpo = patron.slice(i + 1, cierre);
  if (!/^\d+(,\d*)?$/.test(cuerpo)) return null;
  const [minStr, maxStr] = cuerpo.split(",");
  const min = parseInt(minStr, 10);
  // `{n,}` no tiene tope; `{n,m}` con m grande da lo mismo que no tenerlo.
  const abierto = cuerpo.includes(",") ? (maxStr === "" || parseInt(maxStr, 10) > 8) : min > 8;
  return { abierto, fin: cierre };
}

/**
 * Revisa un patrón escrito por el usuario. Devuelve el motivo del rechazo, o `null` si
 * se puede guardar.
 *
 * El mensaje va directo al usuario, así que explica qué cambiar.
 */
export function revisarPatron(patron: string): string | null {
  if (patron.length > MAX_PATRON) {
    return `Patrón regex demasiado largo (máx ${MAX_PATRON} caracteres)`;
  }

  try {
    new RegExp(patron);
  } catch {
    return "Patrón regex inválido";
  }

  const pila: Grupo[] = [];
  const raiz: Grupo = { tieneCuantificadorAbierto: false, ramas: [], ramaActual: "" };
  pila.push(raiz);

  const anotar = (txt: string) => {
    pila[pila.length - 1].ramaActual += txt;
  };

  for (let i = 0; i < patron.length; i++) {
    const c = patron[i];

    // Un caracter escapado no abre grupos ni cuantifica: `\(` es un paréntesis literal
    // y `\+` es un signo de más.
    if (c === "\\") {
      anotar(patron.slice(i, i + 2));
      i++;
      continue;
    }

    // Dentro de una clase `[...]` no hay grupos ni cuantificadores.
    if (c === "[") {
      let j = i + 1;
      if (patron[j] === "^") j++;
      if (patron[j] === "]") j++; // `[]]` — el primer ] es literal
      while (j < patron.length && patron[j] !== "]") {
        if (patron[j] === "\\") j++;
        j++;
      }
      anotar(patron.slice(i, j + 1));
      i = j;
      continue;
    }

    if (c === "(") {
      pila.push({ tieneCuantificadorAbierto: false, ramas: [], ramaActual: "" });
      continue;
    }

    if (c === "|") {
      const g = pila[pila.length - 1];
      g.ramas.push(g.ramaActual);
      g.ramaActual = "";
      continue;
    }

    if (c === ")") {
      if (pila.length === 1) continue; // paréntesis desbalanceado; RegExp ya lo habría rechazado
      const grupo = pila.pop()!;
      grupo.ramas.push(grupo.ramaActual);

      const cuant = cuantificadorAbierto(patron, i + 1);
      const grupoRepetido = cuant?.abierto === true;

      if (grupoRepetido) {
        if (grupo.tieneCuantificadorAbierto) {
          return "El patrón tiene un cuantificador dentro de otro (por ejemplo (a+)+). Esa forma puede tardar horas en evaluarse: reescríbela sin anidar + o *.";
        }
        // `(a|a)+`: dos ramas que aceptan lo mismo multiplican los caminos igual que
        // un anidamiento.
        const ramas = grupo.ramas.map((r) => r.trim()).filter(Boolean);
        if (ramas.length > 1 && new Set(ramas).size < ramas.length) {
          return "El patrón repite la misma opción dentro de una alternancia (por ejemplo (a|a)+). Esa forma puede tardar horas en evaluarse: deja una sola opción.";
        }
      }

      // Para el grupo de arriba, este cuenta como algo repetible si él mismo se repite
      // o si lleva dentro algo que se repite: en `((a+))+` el anidamiento sólo se ve si
      // el grupo intermedio, que no está cuantificado, hereda lo que traía dentro.
      if (grupoRepetido || grupo.tieneCuantificadorAbierto) {
        pila[pila.length - 1].tieneCuantificadorAbierto = true;
      }

      anotar(`(${grupo.ramas.join("|")})`);
      if (cuant) {
        anotar(patron.slice(i + 1, cuant.fin + 1));
        i = cuant.fin;
      }
      continue;
    }

    const cuant = cuantificadorAbierto(patron, i);
    if (cuant) {
      if (cuant.abierto) pila[pila.length - 1].tieneCuantificadorAbierto = true;
      anotar(patron.slice(i, cuant.fin + 1));
      i = cuant.fin;
      continue;
    }

    anotar(c);
  }

  return null;
}
