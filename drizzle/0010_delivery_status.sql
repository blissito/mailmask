-- Estado de entrega (delivered/bounced/complained) cruzado por el id interno de SES.
-- Escrita a mano: el snapshot de drizzle sigue desincronizado respecto a `api_keys`.
ALTER TABLE `messages` ADD `ses_message_id` text;
--> statement-breakpoint
ALTER TABLE `messages` ADD `delivery_status` text;
--> statement-breakpoint
ALTER TABLE `messages` ADD `delivery_detail` text;
--> statement-breakpoint
ALTER TABLE `messages` ADD `delivered_at` text;
--> statement-breakpoint
CREATE INDEX `idx_messages_ses_id` ON `messages` (`ses_message_id`);
--> statement-breakpoint
ALTER TABLE `email_logs` ADD `ses_message_id` text;
--> statement-breakpoint
CREATE INDEX `idx_email_logs_ses_id` ON `email_logs` (`ses_message_id`);
