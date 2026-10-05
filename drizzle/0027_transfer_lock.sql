-- Candado de transferencia: espejo de `clientTransferProhibited` y cuándo se vuelve a poner solo.
ALTER TABLE `domain_registrations` ADD `transfer_lock` integer;--> statement-breakpoint
ALTER TABLE `domain_registrations` ADD `transfer_unlocked_until` text;
