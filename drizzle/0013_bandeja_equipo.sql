ALTER TABLE `conversations` ADD `snoozed_until` text;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_conversations_snoozed` ON `conversations` (`status`,`snoozed_until`);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `conversation_reads` (
	`domain_id` text NOT NULL,
	`conversation_id` text NOT NULL REFERENCES `conversations`(`id`) ON DELETE cascade,
	`agent_email` text NOT NULL,
	`last_read_at` text NOT NULL,
	PRIMARY KEY(`conversation_id`, `agent_email`)
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_reads_domain_agent` ON `conversation_reads` (`domain_id`,`agent_email`);
