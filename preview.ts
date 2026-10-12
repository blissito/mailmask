/**
 * Modo preview: un proceso con `PREVIEW=1` sirve la app para mirarla, sin tocar AWS ni cobrar.
 *
 * Nace del incidente del 11-oct-2026: una preview arrancó con el `.env` real, reparó las
 * receipt rules de SES y tocó el tópico SNS de producción. Una preview es una copia de la
 * app, no un segundo entorno de producción: nada de lo que haga puede tener efectos afuera
 * (mandar correo, cobrar, comprar un dominio).
 *
 * La regla que lo mantiene vivo: **todo cliente de AWS o bloque de arranque nuevo con
 * efectos pasa por este archivo**. Un `if (esServidor)` suelto es exactamente lo que se
 * saltó la compuerta la primera vez. La ficha es `docs/agents/preview.md`.
 */

/** Lo que se lanza al intentar algo con efectos afuera estando en preview. */
export class PreviewDeshabilitado extends Error {
  readonly servicio: string;

  constructor(servicio: string) {
    super(`${servicio} está deshabilitado en preview`);
    this.name = "PreviewDeshabilitado";
    this.servicio = servicio;
  }
}

/**
 * Se lee en cada llamada y no al importar el módulo: el mismo proceso cambia de opinión
 * entre pruebas, y un valor congelado mentiría sobre lo que hace en ese momento.
 */
export function esPreview(): boolean {
  return process.env.PREVIEW === "1";
}

/** Corta el paso antes de que algo con efectos afuera (AWS, MercadoPago) se ejecute. */
export function assertNoPreview(servicio: string): void {
  if (esPreview()) throw new PreviewDeshabilitado(servicio);
}

/** ¿Este proceso programa crons? Sólo el servidor, y nunca una preview. */
export function debeProgramar(esServidor: boolean, esPreview: boolean): boolean {
  return esServidor && !esPreview;
}

/** ¿Corre este proceso los arranques con efectos (reparar SES/SNS, backfill, tipo de cambio)? */
export function debeArrancarEfectos(esServidor: boolean, esPreview: boolean): boolean {
  return esServidor && !esPreview;
}
