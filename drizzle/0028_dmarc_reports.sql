-- Reportes agregados de DMARC (rua) de nuestros propios dominios. Sólo uso interno.
CREATE TABLE `dmarc_reports` (
	`id` text PRIMARY KEY NOT NULL,
	`org_name` text NOT NULL,
	`report_id` text NOT NULL,
	`domain` text NOT NULL,
	`policy` text,
	`date_begin` text NOT NULL,
	`date_end` text NOT NULL,
	`received_at` text NOT NULL
);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_dmarc_reports_org_report` ON `dmarc_reports` (`org_name`,`report_id`);--> statement-breakpoint
CREATE INDEX `idx_dmarc_reports_date_end` ON `dmarc_reports` (`date_end`);--> statement-breakpoint
CREATE TABLE `dmarc_records` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`report_id` text NOT NULL REFERENCES `dmarc_reports`(`id`) ON DELETE cascade,
	`source_ip` text NOT NULL,
	`count` integer NOT NULL,
	`disposition` text,
	`dkim_pass` integer NOT NULL,
	`spf_pass` integer NOT NULL,
	`header_from` text,
	`dkim_domain` text,
	`spf_domain` text
);--> statement-breakpoint
CREATE INDEX `idx_dmarc_records_report` ON `dmarc_records` (`report_id`);
