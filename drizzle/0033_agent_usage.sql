-- Consumo del agente (Mascarito) por dominio, para los topes de `agent-quota.ts`.
-- `agent_usage`: una fila por (dominio, semana ISO `YYYY-Www`; la semana corta el lunes 00:00
-- de CDMX). `agent_usage_hourly`: el costo por hora UTC (`YYYY-MM-DDTHH`), para la ventana
-- móvil de 5 h y el gasto del mes de los dominios de la casa; se purga a los 35 días.
-- Las dos se escriben con UPSERT que suma. Sin FK a `domains` a propósito: es historia de
-- gasto y debe sobrevivir al dominio para cuadrar contra el reporte de Ghosty.
CREATE TABLE `agent_usage` (
	`domain_id` text NOT NULL,
	`week` text NOT NULL,
	`threads` integer DEFAULT 0 NOT NULL,
	`mail_turns` integer DEFAULT 0 NOT NULL,
	`panel_turns` integer DEFAULT 0 NOT NULL,
	`tool_calls` integer DEFAULT 0 NOT NULL,
	`cost_micro_usd` integer DEFAULT 0 NOT NULL,
	`updated_at` text NOT NULL,
	PRIMARY KEY(`domain_id`, `week`)
);
--> statement-breakpoint
CREATE TABLE `agent_usage_hourly` (
	`domain_id` text NOT NULL,
	`hour` text NOT NULL,
	`cost_micro_usd` integer DEFAULT 0 NOT NULL,
	PRIMARY KEY(`domain_id`, `hour`)
);
