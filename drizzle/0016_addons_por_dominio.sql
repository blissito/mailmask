-- Los add-ons pasan a ser POR DOMINIO: "dominio activado", "+50 GB" y "+100 envíos"
-- se compran para un dominio concreto. Nullable porque las filas viejas (sends25,
-- mailbox, domain-como-cupo) no tenían dominio y se tratan como legado del usuario.
ALTER TABLE `addons` ADD `domain_id` text;--> statement-breakpoint
CREATE INDEX `idx_addons_domain_status` ON `addons` (`domain_id`,`status`);
