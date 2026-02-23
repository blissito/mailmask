CREATE TABLE `referral_credits` (
	`id` text PRIMARY KEY NOT NULL,
	`email` text NOT NULL,
	`referral_id` text NOT NULL,
	`discount_percent` integer DEFAULT 50 NOT NULL,
	`used` integer DEFAULT false NOT NULL,
	`created_at` text NOT NULL,
	`used_at` text,
	FOREIGN KEY (`email`) REFERENCES `users`(`email`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`referral_id`) REFERENCES `referrals`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `referrals` (
	`id` text PRIMARY KEY NOT NULL,
	`referrer_email` text NOT NULL,
	`referred_email` text NOT NULL,
	`status` text DEFAULT 'pending' NOT NULL,
	`created_at` text NOT NULL,
	`converted_at` text,
	`credited_at` text,
	FOREIGN KEY (`referrer_email`) REFERENCES `users`(`email`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`referred_email`) REFERENCES `users`(`email`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_referrals_referrer` ON `referrals` (`referrer_email`);--> statement-breakpoint
CREATE INDEX `idx_referrals_referred` ON `referrals` (`referred_email`);--> statement-breakpoint
ALTER TABLE `users` ADD `referral_slug` text;--> statement-breakpoint
ALTER TABLE `users` ADD `referred_by` text;--> statement-breakpoint
ALTER TABLE `users` ADD `payment_count` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX `users_referral_slug_unique` ON `users` (`referral_slug`);--> statement-breakpoint
CREATE INDEX `idx_conversations_domain_status` ON `conversations` (`domain_id`,`status`,`deleted_at`);--> statement-breakpoint
CREATE INDEX `idx_email_logs_domain_ts` ON `email_logs` (`domain_id`,`timestamp`);--> statement-breakpoint
CREATE INDEX `idx_forward_queue_retry` ON `forward_queue` (`next_retry_at`,`dead`);--> statement-breakpoint
CREATE INDEX `idx_messages_conversation` ON `messages` (`conversation_id`);--> statement-breakpoint
CREATE INDEX `idx_tokens_kind_expires` ON `tokens` (`kind`,`expires_at`);