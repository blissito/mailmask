-- Bitácora de cada sitio de EasyBits publicado en un dominio, para poder deshacerlo:
-- `records` es lo que escribimos y `previous` lo que había antes en cada (nombre, tipo)
-- (null = no había nada). Al quitarlo se restaura `previous` sólo donde el registro sigue
-- siendo el nuestro: lo que el usuario cambió después no se toca. Una fila por dominio.
CREATE TABLE `easybits_publications` (
	`domain_id` text PRIMARY KEY NOT NULL,
	`owner_email` text NOT NULL,
	`eb_domain_id` text NOT NULL,
	`eb_domain_created` integer NOT NULL,
	`website_id` text NOT NULL,
	`placement` text NOT NULL,
	`url` text NOT NULL,
	`records` text NOT NULL,
	`previous` text NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL
);
