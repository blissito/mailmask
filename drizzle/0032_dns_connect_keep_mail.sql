-- «Conectar sin mudarte»: plan de regreso de la delegación de nameservers.
-- `dns_previous_ns` = los NS que tenía el dominio antes (para volver si algo falla) y
-- `dns_pre_snapshot` = el inventario revisado al confirmar, contra el que compara el vigía
-- de 48 h (`dns-watch.ts`). `dns_delegated_at` ya existía.
ALTER TABLE `domains` ADD `dns_previous_ns` text;--> statement-breakpoint
ALTER TABLE `domains` ADD `dns_pre_snapshot` text;
