-- Buzones IMAP: un alias puede GUARDAR su correo además de (o en vez de) reenviarlo.
--
-- Guardamos el accountId de Stalwart, nunca la contraseña: la entrega va con la
-- credencial de administrador, así que la del buzón se muestra una vez y se olvida.
-- `mailbox_used_bytes` es una CACHÉ de lo que reporta el servidor, jamás la verdad
-- para facturar: todo contador de cuota deriva.
ALTER TABLE `alias` ADD `mailbox_enabled` integer DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE `alias` ADD `mailbox_account_id` text;--> statement-breakpoint
ALTER TABLE `alias` ADD `mailbox_quota_bytes` integer;--> statement-breakpoint
ALTER TABLE `alias` ADD `mailbox_used_bytes` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `alias` ADD `mailbox_used_at` text;--> statement-breakpoint
ALTER TABLE `alias` ADD `mailbox_created_at` text;--> statement-breakpoint
-- Gracia tras la baja: el buzón queda de SOLO LECTURA hasta esta fecha y luego se
-- borra. Sin esto, cancelar destruye el único ejemplar del correo de alguien que ya
-- no reenvía a Gmail.
ALTER TABLE `alias` ADD `mailbox_grace_until` text;
