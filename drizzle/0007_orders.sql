CREATE TABLE `orders` (
	`id` text PRIMARY KEY NOT NULL,
	`number` text NOT NULL,
	`user_email` text NOT NULL,
	`kind` text NOT NULL,
	`subject` text NOT NULL,
	`subject_id` text,
	`subject_key` text,
	`description` text NOT NULL,
	`amount_cents` integer DEFAULT 0 NOT NULL,
	`list_price_cents` integer,
	`currency` text DEFAULT 'MXN' NOT NULL,
	`period_start` text,
	`period_end` text,
	`mp_preapproval_id` text,
	`mp_authorized_payment_id` text,
	`mp_payment_id` text,
	`mp_status` text,
	`mp_status_detail` text,
	`event_key` text,
	`note` text,
	`granted_by` text,
	`raw` text,
	`occurred_at` text NOT NULL,
	`created_at` text NOT NULL,
	FOREIGN KEY (`user_email`) REFERENCES `users`(`email`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `orders_number_unique` ON `orders` (`number`);--> statement-breakpoint
CREATE UNIQUE INDEX `orders_event_key_unique` ON `orders` (`event_key`);--> statement-breakpoint
CREATE INDEX `idx_orders_user_created` ON `orders` (`user_email`,`created_at`);--> statement-breakpoint
CREATE INDEX `idx_orders_subject` ON `orders` (`subject`,`subject_id`);--> statement-breakpoint
CREATE INDEX `idx_orders_mp_preapproval` ON `orders` (`mp_preapproval_id`);--> statement-breakpoint
ALTER TABLE `addons` ADD `source` text DEFAULT 'purchase' NOT NULL;--> statement-breakpoint
ALTER TABLE `addons` ADD `courtesy_note` text;--> statement-breakpoint
UPDATE `addons`
  SET `source` = 'courtesy',
      `price_cents` = 0,
      `courtesy_note` = 'Cortesía de MailMask'
  WHERE `mp_preapproval_id` IS NULL
    AND `status` = 'active';--> statement-breakpoint
INSERT OR IGNORE INTO `orders`
  (`id`, `number`, `user_email`, `kind`, `subject`, `subject_id`, `subject_key`,
   `description`, `amount_cents`, `list_price_cents`, `currency`, `period_end`,
   `event_key`, `note`, `granted_by`, `occurred_at`, `created_at`)
SELECT
  lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' ||
    substr(lower(hex(randomblob(2))), 2) || '-a' ||
    substr(lower(hex(randomblob(2))), 2) || '-' || lower(hex(randomblob(6))),
  'MM-0000-' || upper(substr(lower(hex(randomblob(2))), 1, 4)),
  a.`user_email`,
  'courtesy',
  'addon',
  a.`id`,
  a.`kind`,
  CASE a.`kind`
    WHEN 'domain' THEN 'Dominio extra'
    WHEN 'sends25' THEN 'Envíos 25/día'
    WHEN 'sends100' THEN 'Envíos 100/día'
    ELSE a.`kind`
  END,
  0,
  CASE a.`kind`
    WHEN 'domain' THEN 9900
    WHEN 'sends25' THEN 4900
    WHEN 'sends100' THEN 9900
    ELSE NULL
  END,
  'MXN',
  a.`current_period_end`,
  'courtesy:' || a.`id`,
  'Cortesía de MailMask',
  'migration:0007',
  a.`created_at`,
  a.`created_at`
FROM `addons` a
WHERE a.`source` = 'courtesy';
