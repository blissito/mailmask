-- Renovación anual cobrada, y campos que faltaban para no inventar la fecha de expiración.
--
-- Hasta ahora `registerDomain` mandaba `AutoRenew: true` a AWS y nadie volvía a cobrarle al
-- cliente: el pago era una Preference de una sola vez. O sea, AWS renovaba el dominio y nos
-- lo cobraba a nosotros cada año, para siempre.
ALTER TABLE `domain_registrations` ADD `kind` text DEFAULT 'register' NOT NULL;--> statement-breakpoint
ALTER TABLE `domain_registrations` ADD `mp_preapproval_id` text;--> statement-breakpoint
-- none | active | past_due | cancelled
ALTER TABLE `domain_registrations` ADD `renewal_status` text DEFAULT 'none' NOT NULL;--> statement-breakpoint
ALTER TABLE `domain_registrations` ADD `renewal_price_cents` integer;--> statement-breakpoint
ALTER TABLE `domain_registrations` ADD `next_charge_at` text;--> statement-breakpoint
ALTER TABLE `domain_registrations` ADD `last_synced_at` text;--> statement-breakpoint
-- Espejo de lo que AWS reporta. `false` es el estado que pierde dominios: se alerta.
ALTER TABLE `domain_registrations` ADD `aws_auto_renew` integer DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE `domain_registrations` ADD `warned_at` text;--> statement-breakpoint
ALTER TABLE `domain_registrations` ADD `dunning_started_at` text;--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_domain_reg_expires` ON `domain_registrations` (`expires_at`);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_domain_reg_preapproval` ON `domain_registrations` (`mp_preapproval_id`);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_domain_reg_kind` ON `domain_registrations` (`kind`);
