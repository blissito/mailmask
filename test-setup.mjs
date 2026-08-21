/**
 * Preparación del proceso de pruebas. Se carga con `--import` desde `npm test`.
 *
 * Es .mjs y no .ts porque `NODE_OPTIONS=--import` corre ANTES de que el loader de tsx
 * exista: un .ts aquí muere con ERR_UNKNOWN_FILE_EXTENSION.
 *
 * Elysia programa un `setTimeout` de 295 s al registrar hooks (el caché de sucrose,
 * `node_modules/elysia/dist/sucrose.mjs`). Ningún test puede cancelarlo ni alcanzarlo,
 * pero mantiene vivo el proceso casi cinco minutos después del último test — y ésa era
 * la razón de fondo de `--test-force-exit`, el flag que truncaba el reporte al azar.
 *
 * Aquí se hacen `unref` los timers de más de un minuto: ninguna prueba espera tanto, y
 * `unref` no cancela nada, sólo dice "no mantengas vivo el proceso por mi culpa".
 */
const real = global.setTimeout;
global.setTimeout = (fn, ms, ...args) => {
  const t = real(fn, ms, ...args);
  if (typeof ms === "number" && ms > 60_000) t.unref?.();
  return t;
};
