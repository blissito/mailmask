-- Cuándo se midieron en vivo `verified` y `mx_configured`; la lista los da como «unknown» si pasa de 24 h.
ALTER TABLE `domains` ADD `health_checked_at` text;
