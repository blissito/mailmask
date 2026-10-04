-- Servidor de autorización OAuth 2.1 para el MCP (`/oauth/*`, `oauth.ts`): un cliente MCP
-- (Ghosty, Claude, etc.) se registra solo (DCR), la persona da permiso con su sesión y el
-- cliente recibe un `mo_` (1 h) + un `mr_` (60 días, rota en cada uso). Todo se guarda con hash.
CREATE TABLE `oauth_clients` (
	`client_id` text PRIMARY KEY NOT NULL,
	`client_secret_hash` text,
	`client_name` text NOT NULL,
	`client_uri` text,
	`logo_uri` text,
	`redirect_uris` text NOT NULL,
	`token_endpoint_auth_method` text DEFAULT 'none' NOT NULL,
	`created_ip` text,
	`created_at` text NOT NULL
);--> statement-breakpoint
CREATE TABLE `oauth_codes` (
	`code_hash` text PRIMARY KEY NOT NULL,
	`client_id` text NOT NULL REFERENCES `oauth_clients`(`client_id`) ON DELETE CASCADE,
	`user_email` text NOT NULL REFERENCES `users`(`email`) ON DELETE CASCADE,
	`redirect_uri` text NOT NULL,
	`code_challenge` text NOT NULL,
	`scope` text NOT NULL,
	`resource` text NOT NULL,
	`expires_at` text NOT NULL,
	`used_at` text
);--> statement-breakpoint
-- `family_id` agrupa todo lo que nació de un mismo permiso: si un refresh ya rotado se vuelve
-- a presentar (reuso = robo probable), se revoca la familia entera.
CREATE TABLE `oauth_tokens` (
	`id` text PRIMARY KEY NOT NULL,
	`token_hash` text NOT NULL,
	`kind` text NOT NULL,
	`client_id` text NOT NULL REFERENCES `oauth_clients`(`client_id`) ON DELETE CASCADE,
	`user_email` text NOT NULL REFERENCES `users`(`email`) ON DELETE CASCADE,
	`scope` text NOT NULL,
	`resource` text NOT NULL,
	`family_id` text NOT NULL,
	`expires_at` text NOT NULL,
	`revoked_at` text,
	`created_at` text NOT NULL
);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_oauth_tokens_hash` ON `oauth_tokens` (`token_hash`);--> statement-breakpoint
CREATE INDEX `idx_oauth_tokens_family` ON `oauth_tokens` (`family_id`);--> statement-breakpoint
CREATE INDEX `idx_oauth_tokens_user` ON `oauth_tokens` (`user_email`);
