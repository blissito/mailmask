// Precio de un TLD para transferencias.
//
// `TLD_PRICES` es una tabla curada de 12 extensiones: sirve para el buscador de dominios
// nuevos, donde queremos enseñar una parrilla corta y con precios pensados. Pero para una
// **transferencia** esa tabla es el criterio equivocado: el dominio ya existe y ya es del
// cliente, así que la pregunta no es "¿cuáles vendemos?" sino "¿cuáles puede mover AWS?".
// Son 413, e incluye los de clientes que ya tenemos (`.design`, `.app`, `.studio`).
// Rechazar un `.design` porque no está en nuestra parrilla es decirle que no a un cliente
// por un detalle de nuestra tabla interna.
import { log } from "./logger.js";
import { TLD_PRICES } from "./db.js";
import { tipoDeCambio } from "./fx.js";

/**
 * Un dominio es una commodity con precio público: el cliente compara en diez segundos, así
 * que el margen es delgado a propósito. El negocio está en los $99/mes de activación; esto
 * es la conveniencia de que quede configurado solo. El piso existe porque a 1.2× un TLD de
 * $3 USD dejaría menos que la comisión de MercadoPago.
 */
const MARGEN = 1.2;
const MARGEN_MINIMO_MXN = 60;

/** Los precios de AWS cambian poco; consultarlos en cada petición es tiempo regalado. */
const CACHE_MS = 24 * 3600_000;
const cache = new Map<string, { transferUsdCents: number; renewUsdCents: number; expira: number }>();

export interface PrecioTld {
  tld: string;
  /** Lo que le cobramos al cliente por la transferencia (incluye un año). */
  transferMxnCents: number;
  transferUsdCents: number;
  renewMxnCents: number;
  renewUsdCents: number;
  /** true si sale de la tabla curada; false si se calculó con el precio vivo de AWS. */
  curado: boolean;
}

function alPrecioDeVenta(usdCents: number): number {
  // El tipo de cambio se actualiza cada hora y se cotiza sobre el máximo de los últimos 30
  // días: el monto de un PreApproval de MercadoPago no se puede cambiar después, así que un
  // dominio cotizado en un mínimo pasajero se cobraría bajo costo durante años.
  const costoMxn = (usdCents / 100) * tipoDeCambio();
  const conMargen = Math.max(costoMxn * MARGEN, costoMxn + MARGEN_MINIMO_MXN);
  // Redondeo a decenas menos uno: $722 → $729. Hacia arriba, nunca hacia abajo, que es como
  // se acaba vendiendo por debajo del costo.
  return (Math.ceil(conMargen / 10) * 10 - 1) * 100;
}

/**
 * Precio de transferencia de cualquier TLD que AWS soporte. Devuelve `null` si AWS no lo
 * maneja o no da un precio en USD utilizable.
 */
export async function precioDeTransferencia(tld: string): Promise<PrecioTld | null> {
  const clave = tld.replace(/^\./, "").toLowerCase();

  // La tabla curada manda: sus precios están pensados a mano y no deben moverse solos.
  const curado = TLD_PRICES[`.${clave}`];
  if (curado) {
    return {
      tld: `.${clave}`,
      transferMxnCents: curado.transferMxnCents,
      transferUsdCents: curado.transferUsdCents,
      renewMxnCents: curado.renewMxnCents,
      renewUsdCents: curado.renewUsdCents,
      curado: true,
    };
  }

  const enCache = cache.get(clave);
  const vivo = enCache && enCache.expira > Date.now()
    ? enCache
    : await (async () => {
      try {
        const { listTldPrice } = await import("./route53.js");
        const p = await listTldPrice(clave);
        if (!p) return null;
        const fila = { ...p, expira: Date.now() + CACHE_MS };
        cache.set(clave, fila);
        return fila;
      } catch (err) {
        log("warn", "route53", "No se pudo consultar el precio del TLD", { tld: clave, error: String(err) });
        return null;
      }
    })();

  // Un precio de cero es "AWS no lo ofrece de verdad", no una ganga.
  if (!vivo || vivo.transferUsdCents <= 0) return null;

  return {
    tld: `.${clave}`,
    transferMxnCents: alPrecioDeVenta(vivo.transferUsdCents),
    transferUsdCents: vivo.transferUsdCents,
    renewMxnCents: alPrecioDeVenta(vivo.renewUsdCents || vivo.transferUsdCents),
    renewUsdCents: vivo.renewUsdCents || vivo.transferUsdCents,
    curado: false,
  };
}
