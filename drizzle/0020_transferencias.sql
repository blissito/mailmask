-- Transferencia de dominios: traer uno existente (transfer-in) y dejarlo ir (transfer-out).
--
-- El auth code EPP NO se guarda: entregarlo es entregar el dominio. Vive en memoria del
-- proceso con TTL y aquí sólo quedan sus últimos 4 caracteres, para que el cliente sepa
-- cuál mandó.
ALTER TABLE `domain_registrations` ADD `transfer_auth_code_hint` text;--> statement-breakpoint
ALTER TABLE `domain_registrations` ADD `transfer_requested_at` text;--> statement-breakpoint
ALTER TABLE `domain_registrations` ADD `transfer_approved_at` text;--> statement-breakpoint
ALTER TABLE `domain_registrations` ADD `previous_registrar` text;--> statement-breakpoint
-- Inventario del DNS del proveedor anterior (JSON). Sin aprobarlo no se tocan nameservers.
ALTER TABLE `domain_registrations` ADD `dns_snapshot` text;--> statement-breakpoint
ALTER TABLE `domain_registrations` ADD `dns_snapshot_at` text;--> statement-breakpoint
-- none | discovered | approved
ALTER TABLE `domain_registrations` ADD `dns_import_status` text DEFAULT 'none' NOT NULL;
