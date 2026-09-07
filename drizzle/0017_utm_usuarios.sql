-- Campaña de origen del usuario (utm_* del primer toque). Nullable: los usuarios
-- anteriores y los que llegan sin utm no traen nada.
ALTER TABLE `users` ADD `utm_source` text;--> statement-breakpoint
ALTER TABLE `users` ADD `utm_medium` text;--> statement-breakpoint
ALTER TABLE `users` ADD `utm_campaign` text;
