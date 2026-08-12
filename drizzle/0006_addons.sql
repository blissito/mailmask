CREATE TABLE `addons` (
	`id` text PRIMARY KEY NOT NULL,
	`user_email` text NOT NULL,
	`kind` text NOT NULL,
	`status` text DEFAULT 'pending' NOT NULL,
	`mp_preapproval_id` text,
	`price_cents` integer NOT NULL,
	`current_period_end` text,
	`created_at` text NOT NULL,
	`cancelled_at` text,
	FOREIGN KEY (`user_email`) REFERENCES `users`(`email`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `addons_mp_preapproval_id_unique` ON `addons` (`mp_preapproval_id`);--> statement-breakpoint
CREATE INDEX `idx_addons_user_status` ON `addons` (`user_email`,`status`);
