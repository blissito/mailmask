-- Zona DNS gestionada por MailMask.
--
-- Hasta ahora `hosted_zone_id` sólo vivía en `domain_registrations`, o sea únicamente para
-- los dominios comprados con nosotros. El editor de DNS también sirve a dominios de fuera
-- que deleguen sus nameservers sin transferir el registro, así que la zona es una propiedad
-- del dominio y no de la compra.
ALTER TABLE `domains` ADD `hosted_zone_id` text;--> statement-breakpoint
-- none | pending_delegation | active
ALTER TABLE `domains` ADD `dns_zone_status` text DEFAULT 'none' NOT NULL;--> statement-breakpoint
-- JSON con los 4 nameservers del delegation set, para no re-consultar AWS en cada render.
ALTER TABLE `domains` ADD `dns_nameservers` text;--> statement-breakpoint
ALTER TABLE `domains` ADD `dns_delegated_at` text;--> statement-breakpoint
ALTER TABLE `domains` ADD `dns_checked_at` text;--> statement-breakpoint

-- Retrocompatibilidad: los dominios registrados con nosotros ya tienen zona y ya están
-- delegados, porque el cron llama a updateNameservers al completar el registro.
UPDATE `domains` SET `hosted_zone_id` = (
  SELECT r.`hosted_zone_id` FROM `domain_registrations` r
  WHERE r.`domain_id` = `domains`.`id` AND r.`hosted_zone_id` IS NOT NULL
  ORDER BY r.`created_at` DESC LIMIT 1
) WHERE `hosted_zone_id` IS NULL;--> statement-breakpoint

UPDATE `domains` SET `dns_zone_status` = 'active', `dns_delegated_at` = `created_at`
WHERE `hosted_zone_id` IS NOT NULL;
