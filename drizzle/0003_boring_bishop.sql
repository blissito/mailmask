CREATE TABLE `referral_clicks` (
	`id` text PRIMARY KEY NOT NULL,
	`referrer_email` text NOT NULL,
	`clicked_at` text NOT NULL,
	`ip` text NOT NULL,
	`user_agent` text,
	FOREIGN KEY (`referrer_email`) REFERENCES `users`(`email`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_referral_clicks_referrer` ON `referral_clicks` (`referrer_email`);--> statement-breakpoint
CREATE INDEX `idx_referral_clicks_referrer_time` ON `referral_clicks` (`referrer_email`,`clicked_at`);