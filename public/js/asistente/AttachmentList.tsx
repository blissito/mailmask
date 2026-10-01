import { IoClose } from "react-icons/io5"
import { ClipIcon } from "./icons"
import type { Attachment } from "./types"

// Extraído de `app/routes/dash/dash.asistente.tsx` para que el dock global
// pueda reusarlo. Movimiento mecánico: sin cambios de comportamiento.

export /** Adjuntos ya enviados, dentro del hilo. */
function AttachmentList({ items }: { items: Attachment[] }) {
  return (
    <div className="flex flex-wrap gap-2 justify-end">
      {items.map((a, i) =>
        a.contentType?.startsWith("image/") ? (
          <a key={i} href={a.url} target="_blank" rel="noreferrer">
            <img
              src={a.url}
              alt={a.name || "Imagen adjunta"}
              className="max-h-40 rounded-2xl border border-line object-cover"
            />
          </a>
        ) : (
          <a
            key={i}
            href={a.url}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2 text-sm font-medium text-fg bg-bg-elev border border-line rounded-2xl px-3 py-2 hover:border-accent transition"
          >
            <ClipIcon />
            <span className="truncate max-w-[180px]">
              {a.name || "Archivo"}
            </span>
          </a>
        ),
      )}
    </div>
  )
}

export /** Adjunto pendiente de enviar, en el composer. */
function AttachmentChip({
  item,
  onRemove,
}: {
  item: Attachment
  onRemove: () => void
}) {
  const isImage = item.contentType?.startsWith("image/") && item.url
  return (
    <span
      className={`group/chip relative flex items-center gap-2 rounded-xl border pr-7 pl-2 py-1.5 text-xs font-medium ${
        item.error
          ? "border-red-200 bg-red-50 text-red-600"
          : "border-line bg-bg-inset/60 text-fg"
      }`}
    >
      {isImage ? (
        <img
          src={item.url}
          alt=""
          className="w-7 h-7 rounded-lg object-cover shrink-0"
        />
      ) : (
        <ClipIcon />
      )}
      <span className="truncate max-w-[140px]">{item.name || "Archivo"}</span>
      {item.error && <span>· falló</span>}
      <button
        type="button"
        onClick={onRemove}
        aria-label="Quitar adjunto"
        className="absolute right-1.5 top-1/2 -translate-y-1/2 w-4 h-4 rounded-full text-fg-muted hover:text-fg flex items-center justify-center"
      >
        <IoClose />
      </button>
    </span>
  )
}
