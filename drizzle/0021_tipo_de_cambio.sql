-- Tipo de cambio USD→MXN, con historia.
--
-- Vivía en una variable de entorno, y eso es una bomba de relojería: nadie la actualiza y
-- el precio de los dominios se calcula sobre un número de hace meses. Se puso 21 cuando el
-- real era 16.89.
--
-- Se guarda la historia y no sólo el último valor porque el precio de renovación se fija al
-- contratar y **el monto de un PreApproval de MercadoPago no se puede cambiar después**: hay
-- que cotizar sobre el peor tipo de cambio reciente, no sobre el de este segundo.
CREATE TABLE IF NOT EXISTS `fx_rates` (
  `id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
  `pair` text NOT NULL,
  `rate` real NOT NULL,
  `source` text NOT NULL,
  `fetched_at` text NOT NULL
);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_fx_pair_fetched` ON `fx_rates` (`pair`,`fetched_at`);
