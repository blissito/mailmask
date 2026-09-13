-- Contacto WHOIS del cliente para un transfer-in.
--
-- Hasta aquí, TODO dominio —registrado o transferido— quedaba a nombre de MailMask, porque
-- nadie le pasaba nunca un contacto a `whoisContact()`. En una transferencia eso es quitarle
-- al cliente la titularidad de algo que ya era suyo. Se guarda como JSON porque son datos
-- de un formulario, no un modelo que se consulte.
ALTER TABLE `domain_registrations` ADD `whois_contact` text;
