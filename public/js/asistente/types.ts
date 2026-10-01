/**
 * Tipos compartidos del asistente (Nik) en el dashboard.
 *
 * Viven aparte de la ruta porque los consumen DOS superficies: la página
 * completa (`/dash/asistente`) y el dock global que aparece en todo el dash.
 *
 * Deuda conocida: el widget PÚBLICO de las landings
 * (`app/components/chatbot/ChatWidget.tsx`) tiene su propia copia de varias de
 * estas piezas. No se unifica a propósito — es otro scope y otro bundle (viaja
 * a páginas de visitantes finales), y arrastrarlo a este refactor lo haría por
 * una razón que no le sirve a él. Unificar cuando se toque ese archivo.
 */

/** Archivo ya subido a Tigris, listo para mandarse con el mensaje. */
export type Attachment = {
  url: string
  name?: string
  contentType?: string
  size?: number
  error?: boolean
}

/** Una tool MCP que corrió el agente durante el turno. */
export type ToolRun = { name: string; label: string; done: boolean }

export type Msg = {
  id: string
  role: "user" | "assistant"
  content: string
  status?: string | null
  createdAt: string
  /* Key de React estable. El mensaje optimista nace con id `tmp_*` y luego el
     server manda el real; si la key cambiara, React remonta el nodo y la
     animación de entrada se repite sobre un mensaje YA visible (el "flash").
     La key se fija al insertarlo y no se toca aunque el id cambie. */
  key?: string
  /* Adjuntos del turno (solo en el mensaje optimista: al recargar vienen ya
     embebidos como markdown dentro de `content`). */
  attachments?: Attachment[]
  /* La respuesta no se completó → se ofrece "Reintentar". */
  failed?: boolean
  /* Tools que corrió el agente en este turno, en orden. */
  tools?: ToolRun[]
}
