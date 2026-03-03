CREATE TABLE `domain_registrations` (
	`id` text PRIMARY KEY NOT NULL,
	`domain_id` text,
	`domain_name` text NOT NULL,
	`owner_email` text NOT NULL,
	`status` text DEFAULT 'pending_payment' NOT NULL,
	`route53_operation_id` text,
	`hosted_zone_id` text,
	`registered_at` text,
	`expires_at` text,
	`auto_renew` integer DEFAULT true NOT NULL,
	`tld` text NOT NULL,
	`price_cents` integer NOT NULL,
	`aws_cost_cents` integer NOT NULL,
	`mp_payment_id` text,
	`last_error` text,
	`created_at` text NOT NULL,
	FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`owner_email`) REFERENCES `users`(`email`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_domain_reg_owner` ON `domain_registrations` (`owner_email`);--> statement-breakpoint
CREATE INDEX `idx_domain_reg_status` ON `domain_registrations` (`status`);--> statement-breakpoint
ALTER TABLE `domains` ADD `registered_via_mailmask` integer DEFAULT false NOT NULL;