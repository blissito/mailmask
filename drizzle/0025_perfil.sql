-- Perfil de la cuenta: nombre y foto que se ven en /app, la Bandeja y el dock de Mask.
-- La foto vive en S3 bajo `user-avatars/`; aquí sólo su llave (cambia en cada subida).
ALTER TABLE `users` ADD `display_name` text;--> statement-breakpoint
ALTER TABLE `users` ADD `avatar_key` text;--> statement-breakpoint
ALTER TABLE `users` ADD `profile_updated_at` text;
