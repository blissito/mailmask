-- Consumo del agente (Mascarito) por dominio y mes, para los topes de `agent-quota.ts`.
-- Una fila por (dominio, mes YYYY-MM); se escribe con UPSERT que suma, así que dos turnos
-- simultáneos no se pisan. Sin FK a `domains` a propósito: es historia de gasto y debe
-- sobrevivir al dominio para cuadrar contra el reporte de Ghosty.
CREATE TABLE `agent_usage` (
	`domain_id` text NOT NULL,
	`month` text NOT NULL,
	`threads` integer DEFAULT 0 NOT NULL,
	`turns` integer DEFAULT 0 NOT NULL,
	`tool_calls` integer DEFAULT 0 NOT NULL,
	`cost_micro_usd` integer DEFAULT 0 NOT NULL,
	`updated_at` text NOT NULL,
	PRIMARY KEY(`domain_id`, `month`)
);
