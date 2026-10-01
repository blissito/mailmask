-- Asistente de /app (agente en Ghosty Studio que opera MailMask por /mcp con un turn token).
--
-- `assistant_messages`: el hilo que ve el usuario en el dock. Ghosty guarda su propia
-- memoria por (tenant, groupId); esto es sólo lo que se pinta al recargar.
CREATE TABLE `assistant_messages` (
	`id` text PRIMARY KEY NOT NULL,
	`user_email` text NOT NULL REFERENCES `users`(`email`) ON DELETE CASCADE,
	`role` text NOT NULL,
	`content` text NOT NULL,
	`status` text DEFAULT 'ok' NOT NULL,
	`created_at` text NOT NULL
);--> statement-breakpoint
CREATE INDEX `idx_assistant_messages_user` ON `assistant_messages` (`user_email`, `created_at`);--> statement-breakpoint
-- Acciones destructivas que pidió el asistente y esperan que el usuario las apruebe con
-- su sesión. El resumen se arma desde la base, nunca con texto del modelo.
CREATE TABLE `pending_agent_actions` (
	`id` text PRIMARY KEY NOT NULL,
	`user_email` text NOT NULL REFERENCES `users`(`email`) ON DELETE CASCADE,
	`domain_id` text,
	`intent` text NOT NULL,
	`payload` text NOT NULL,
	`summary` text NOT NULL,
	`status` text DEFAULT 'pending' NOT NULL,
	`result` text,
	`created_at` text NOT NULL,
	`decided_at` text
);--> statement-breakpoint
CREATE INDEX `idx_pending_agent_actions_user` ON `pending_agent_actions` (`user_email`, `status`);--> statement-breakpoint
-- "Nueva conversación": un nonce nuevo cambia el groupId y Ghosty abre un hilo limpio.
ALTER TABLE `users` ADD `assistant_nonce` text;
