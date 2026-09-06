-- Búsqueda y paginación de la Bandeja.
-- Escrita a mano: el snapshot de drizzle sigue desincronizado respecto a `api_keys`.
--
-- La tabla virtual FTS5 NO va aquí: es un módulo de compilación de SQLite y un
-- CREATE VIRTUAL TABLE que falle dentro de una migración deja el journal a medias
-- y tumba el arranque completo. Se crea en pg.ts, con degradación a LIKE.
--
-- idx_conversations_domain_status no cubre last_message_at, así que hoy todo
-- ORDER BY hace un sort completo. El keyset de la paginación lo necesita.
CREATE INDEX IF NOT EXISTS `idx_conversations_domain_recent` ON `conversations` (`domain_id`,`deleted_at`,`last_message_at` DESC,`id` DESC);
--> statement-breakpoint
-- El filtro por alias pasa de cliente a servidor.
CREATE INDEX IF NOT EXISTS `idx_conversations_domain_to` ON `conversations` (`domain_id`,`to`);
--> statement-breakpoint
-- Progreso del backfill del índice. En tabla y no en memoria para que sea reanudable.
CREATE TABLE IF NOT EXISTS `search_index_state` (
	`message_id` text PRIMARY KEY NOT NULL,
	`indexed_at` text NOT NULL,
	`status` text NOT NULL,
	`error` text
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_search_state_status` ON `search_index_state` (`status`);
