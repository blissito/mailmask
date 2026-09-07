// Tipo de cambio USD→MXN.
//
// Antes era una variable de entorno con `?? 21` de respaldo, y el real era 16.89: nadie
// actualiza un número así, y el precio de todos los dominios se calculaba sobre él. Ahora se
// consulta cada hora y se guarda con historia.
//
// **Se cotiza sobre el peor tipo de las últimas semanas, no sobre el de este segundo.** El
// monto de un PreApproval de MercadoPago no se puede cambiar después, así que un dominio
// cotizado en un mínimo pasajero queda cobrándose por debajo del costo durante años.
import { desc, eq, gt, and } from "drizzle-orm";
import { db } from "./pg.js";
import { fxRates } from "./schema.js";
import { log } from "./logger.js";

const PAR = "USD/MXN";

/**
 * Fuera de estos límites se descarta la lectura. Una API que responde `1` o `0` no es un
 * tipo de cambio, y usarlo vendería todos los dominios regalados.
 */
const MIN_PLAUSIBLE = 10;
const MAX_PLAUSIBLE = 40;

/** Ventana sobre la que se toma el máximo para cotizar. */
const DIAS_VENTANA = 30;

/** Último recurso si nunca se ha podido consultar nada: alto a propósito. */
const RESPALDO = Number(process.env.USD_MXN ?? 21);

export interface Lectura { rate: number; fetchedAt: string; source: string }

function guardar(rate: number, source: string): void {
  db.insert(fxRates).values({ pair: PAR, rate, source, fetchedAt: new Date().toISOString() }).run();
}

export function ultimaLectura(): Lectura | null {
  const r = db.select().from(fxRates)
    .where(eq(fxRates.pair, PAR))
    .orderBy(desc(fxRates.fetchedAt))
    .limit(1)
    .get();
  return r ? { rate: r.rate, fetchedAt: r.fetchedAt, source: r.source } : null;
}

/**
 * El tipo con el que se cotiza: el **máximo** de los últimos 30 días. Es deliberadamente
 * conservador — cotizar de menos se paga durante todos los años que dure la suscripción,
 * cotizar de más sólo hace el dominio un poco más caro.
 */
export function tipoDeCambio(): number {
  const desde = new Date(Date.now() - DIAS_VENTANA * 864e5).toISOString();
  const filas = db.select().from(fxRates)
    .where(and(eq(fxRates.pair, PAR), gt(fxRates.fetchedAt, desde)))
    .all();

  if (!filas.length) {
    const ultima = ultimaLectura();
    return ultima ? Math.max(ultima.rate, RESPALDO * 0.9) : RESPALDO;
  }
  return Math.max(...filas.map((f) => f.rate));
}

const FUENTES = [
  {
    nombre: "open.er-api.com",
    url: "https://open.er-api.com/v6/latest/USD",
    leer: (j: any) => Number(j?.rates?.MXN),
  },
  {
    nombre: "frankfurter.app",
    url: "https://api.frankfurter.app/latest?from=USD&to=MXN",
    leer: (j: any) => Number(j?.rates?.MXN),
  },
];

/** Consulta y guarda. Devuelve la lectura buena, o `null` si ninguna fuente sirvió. */
export async function actualizarTipoDeCambio(): Promise<Lectura | null> {
  for (const f of FUENTES) {
    try {
      const res = await fetch(f.url, { signal: AbortSignal.timeout(8000) });
      if (!res.ok) continue;
      const rate = f.leer(await res.json());

      // Una respuesta con forma correcta pero valor absurdo es peor que ninguna: se
      // descarta y se prueba la siguiente fuente.
      if (!Number.isFinite(rate) || rate < MIN_PLAUSIBLE || rate > MAX_PLAUSIBLE) {
        log("warn", "billing", "Tipo de cambio fuera de rango, descartado", { fuente: f.nombre, rate });
        continue;
      }

      guardar(rate, f.nombre);
      log("info", "billing", "Tipo de cambio actualizado", { rate, fuente: f.nombre, cotizacion: tipoDeCambio() });
      return { rate, fetchedAt: new Date().toISOString(), source: f.nombre };
    } catch (err) {
      log("warn", "billing", "Fuente de tipo de cambio falló", { fuente: f.nombre, error: String(err) });
    }
  }
  return null;
}

/** Si lleva demasiado sin actualizarse, el precio se está calculando sobre un dato viejo. */
export function lecturaRancia(horas = 26): boolean {
  const u = ultimaLectura();
  return !u || Date.now() - Date.parse(u.fetchedAt) > horas * 3600_000;
}
