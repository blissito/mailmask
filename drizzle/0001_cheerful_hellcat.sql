CREATE TABLE `smtp_credentials` (
	`id` text PRIMARY KEY NOT NULL,
	`domain_id` text NOT NULL,
	`label` text NOT NULL,
	`iam_username` text NOT NULL,
	`access_key_id` text NOT NULL,
	`created_at` text NOT NULL,
	`revoked_at` text,
	FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `smtp_credentials_iam_username_unique` ON `smtp_credentials` (`iam_username`);
