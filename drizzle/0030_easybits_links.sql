-- Conexión OAuth de una cuenta de MailMask con su cuenta de EasyBits (Sitios), para publicar
-- un sitio en el dominio sin copiar registros. Los tokens van cifrados (AES-256-GCM, llave
-- fuera de la base), igual que `transfer_auth_codes`.
CREATE TABLE `easybits_links` (
	`user_email` text PRIMARY KEY NOT NULL,
	`access_token` text NOT NULL,
	`refresh_token` text,
	`expires_at` integer NOT NULL,
	`updated_at` text NOT NULL
);
--> statement-breakpoint
-- Cliente OAuth de MailMask en EasyBits, registrado por DCR la primera vez (uno por redirect_uri).
CREATE TABLE `easybits_oauth_clients` (
	`redirect_uri` text PRIMARY KEY NOT NULL,
	`client_id` text NOT NULL,
	`client_secret` text,
	`created_at` text NOT NULL
);
