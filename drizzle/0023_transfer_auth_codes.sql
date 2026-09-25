-- Código EPP de un transfer-in, cifrado (AES-256-GCM, llave fuera de la base).
--
-- Vivía en un Map en memoria con una hora de vida: un deploy o un pago que tardara más
-- (el checkout de MP de kandey.com.mx se colgó el 24-sep-2026) dejaba la transferencia
-- pagada y sin poderse mandar. Tabla aparte y no columna de `domain_registrations` para
-- que ninguna proyección de esa fila pueda sacarlo a una respuesta.
CREATE TABLE `transfer_auth_codes` (
	`registration_id` text PRIMARY KEY NOT NULL,
	`ciphertext` text NOT NULL,
	`expires_at` integer NOT NULL
);
