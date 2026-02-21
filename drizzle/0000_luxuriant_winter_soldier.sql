CREATE TABLE `agents` (
	`id` text PRIMARY KEY NOT NULL,
	`domain_id` text NOT NULL,
	`email` text NOT NULL,
	`name` text NOT NULL,
	`role` text DEFAULT 'agent' NOT NULL,
	`created_at` text NOT NULL,
	FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `agents_domain_id_email_unique` ON `agents` (`domain_id`,`email`);--> statement-breakpoint
CREATE TABLE `alias` (
	`domain_id` text NOT NULL,
	`alias` text NOT NULL,
	`destinations` text DEFAULT '[]' NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`forward_count` integer DEFAULT 0 NOT NULL,
	`last_from` text,
	`last_at` text,
	`created_at` text NOT NULL,
	PRIMARY KEY(`domain_id`, `alias`),
	FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `bulk_jobs` (
	`id` text PRIMARY KEY NOT NULL,
	`domain_id` text NOT NULL,
	`recipients` text DEFAULT '[]' NOT NULL,
	`subject` text NOT NULL,
	`html` text NOT NULL,
	`from` text NOT NULL,
	`status` text DEFAULT 'queued' NOT NULL,
	`total_recipients` integer DEFAULT 0 NOT NULL,
	`sent` integer DEFAULT 0 NOT NULL,
	`failed` integer DEFAULT 0 NOT NULL,
	`skipped_suppressed` integer DEFAULT 0 NOT NULL,
	`last_error` text,
	`created_at` text NOT NULL,
	`completed_at` text,
	`expires_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `conversations` (
	`id` text PRIMARY KEY NOT NULL,
	`domain_id` text NOT NULL,
	`from` text NOT NULL,
	`to` text NOT NULL,
	`subject` text NOT NULL,
	`status` text DEFAULT 'open' NOT NULL,
	`assigned_to` text,
	`priority` text DEFAULT 'normal' NOT NULL,
	`last_message_at` text NOT NULL,
	`message_count` integer DEFAULT 0 NOT NULL,
	`tags` text DEFAULT '[]' NOT NULL,
	`thread_refs` text DEFAULT '[]' NOT NULL,
	`deleted_at` text,
	FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `coupons` (
	`code` text PRIMARY KEY NOT NULL,
	`plan` text NOT NULL,
	`fixed_price` integer NOT NULL,
	`description` text NOT NULL,
	`single_use` integer DEFAULT false NOT NULL,
	`used` integer DEFAULT false NOT NULL,
	`expires_at` text,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `domains` (
	`id` text PRIMARY KEY NOT NULL,
	`owner_email` text NOT NULL,
	`domain` text NOT NULL,
	`verified` integer DEFAULT false NOT NULL,
	`mx_configured` integer DEFAULT false NOT NULL,
	`dkim_tokens` text DEFAULT '[]' NOT NULL,
	`verification_token` text NOT NULL,
	`created_at` text NOT NULL,
	FOREIGN KEY (`owner_email`) REFERENCES `users`(`email`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `domains_domain_unique` ON `domains` (`domain`);--> statement-breakpoint
CREATE TABLE `email_logs` (
	`id` text PRIMARY KEY NOT NULL,
	`domain_id` text NOT NULL,
	`timestamp` text NOT NULL,
	`from` text NOT NULL,
	`to` text NOT NULL,
	`subject` text NOT NULL,
	`status` text NOT NULL,
	`forwarded_to` text NOT NULL,
	`size_bytes` integer DEFAULT 0 NOT NULL,
	`error` text,
	`expires_at` text NOT NULL,
	FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `forward_queue` (
	`id` text PRIMARY KEY NOT NULL,
	`raw_content` text NOT NULL,
	`from` text NOT NULL,
	`to` text NOT NULL,
	`domain_id` text NOT NULL,
	`domain_name` text NOT NULL,
	`original_to` text NOT NULL,
	`subject` text NOT NULL,
	`log_days` integer DEFAULT 30 NOT NULL,
	`attempt_count` integer DEFAULT 0 NOT NULL,
	`next_retry_at` text NOT NULL,
	`last_error` text,
	`s3_bucket` text,
	`s3_key` text,
	`dead` integer DEFAULT false NOT NULL,
	`created_at` text NOT NULL,
	`expires_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `messages` (
	`id` text PRIMARY KEY NOT NULL,
	`conversation_id` text NOT NULL,
	`from` text NOT NULL,
	`body` text,
	`html` text,
	`s3_bucket` text,
	`s3_key` text,
	`direction` text NOT NULL,
	`message_id` text,
	`created_at` text NOT NULL,
	FOREIGN KEY (`conversation_id`) REFERENCES `conversations`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `notes` (
	`id` text PRIMARY KEY NOT NULL,
	`conversation_id` text NOT NULL,
	`author` text NOT NULL,
	`body` text NOT NULL,
	`created_at` text NOT NULL,
	FOREIGN KEY (`conversation_id`) REFERENCES `conversations`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `rate_limits` (
	`key` text PRIMARY KEY NOT NULL,
	`count` integer DEFAULT 0 NOT NULL,
	`window_start` integer NOT NULL,
	`expires_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `rules` (
	`id` text PRIMARY KEY NOT NULL,
	`domain_id` text NOT NULL,
	`field` text NOT NULL,
	`match` text NOT NULL,
	`value` text NOT NULL,
	`action` text NOT NULL,
	`target` text NOT NULL,
	`priority` integer DEFAULT 0 NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`created_at` text NOT NULL,
	FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `send_counts` (
	`domain_id` text NOT NULL,
	`month` text NOT NULL,
	`count` integer DEFAULT 0 NOT NULL,
	`expires_at` text NOT NULL,
	PRIMARY KEY(`domain_id`, `month`)
);
--> statement-breakpoint
CREATE TABLE `suppressions` (
	`domain_id` text NOT NULL,
	`email` text NOT NULL,
	`reason` text NOT NULL,
	`created_at` text NOT NULL,
	PRIMARY KEY(`domain_id`, `email`),
	FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `tokens` (
	`token` text PRIMARY KEY NOT NULL,
	`kind` text NOT NULL,
	`value` text,
	`expires_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `users` (
	`email` text PRIMARY KEY NOT NULL,
	`password_hash` text NOT NULL,
	`email_verified` integer DEFAULT false NOT NULL,
	`created_at` text NOT NULL,
	`password_changed_at` text,
	`sub_plan` text,
	`sub_status` text,
	`sub_mp_id` text,
	`sub_period_end` text
);
