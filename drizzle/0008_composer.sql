-- Firma por dominio y respuestas guardadas para el compositor de la Bandeja.
-- Escrita a mano: el snapshot de drizzle sigue desincronizado respecto a `api_keys`
-- y `drizzle-kit generate` querría emitir un ALTER que rompería producción.
ALTER TABLE `domains` ADD `signature` text;
--> statement-breakpoint
CREATE TABLE `canned_responses` (
	`id` text PRIMARY KEY NOT NULL,
	`domain_id` text NOT NULL,
	`title` text NOT NULL,
	`body` text NOT NULL,
	`created_at` text NOT NULL,
	FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_canned_domain` ON `canned_responses` (`domain_id`);
