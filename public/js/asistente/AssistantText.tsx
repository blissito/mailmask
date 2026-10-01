import { useEffect, useRef } from "react"
import { Streamdown } from "streamdown"
import { hasNavMarker, parseNavParts } from "./navMarker"

// Extraído de `app/routes/dash/dash.asistente.tsx` para que el dock global
// pueda reusarlo. Movimiento mecánico: sin cambios de comportamiento.

/**
 * Convierte las URLs de captura que manda Nik en imágenes de markdown.
 *
 * `screenshot_url` devuelve la URL PELADA dentro del texto, así que se pintaba
 * como un link azul que hay que abrir en otra pestaña — justo cuando lo único
 * que quieres es MIRAR lo que vio el agente.
 *
 * La detección va por HOST, no por extensión: los archivos del bucket de la
 * caja no tienen ninguna (`…/AAN0XaQkExyz`), así que un `/\.(png|jpe?g)$/` no
 * habría cazado ni una. El `(?<!\]\()` deja en paz las que YA vienen como
 * imagen o como link con texto, para no anidar markdown dentro de markdown.
 */
export function renderScreenshots(text: string): string {
  return text.replace(
    /(?<!\]\()https:\/\/easybits-public\.t3\.storage\.dev\/\S+/g,
    (url) => `\n\n![captura](${url})\n\n`,
  )
}

export /**
 * Cuerpo de un mensaje del asistente. Mismo criterio que el ChatWidget público:
 * markdown vía streamdown para que negritas, listas y links se rendericen en vez
 * de mostrarse literales.
 */
function AssistantText({
  text,
  streaming,
  onNavigate,
  onSurface = "light",
  allowNav = true,
}: {
  text: string
  /** Mientras es true, cada bloque nuevo entra animado y se muestra el cursor. */
  streaming?: boolean
  /** Se llama al tocar un botón de navegación (el dock mobile se cierra). */
  onNavigate?: () => void
  /**
   * Sobre qué fondo se pinta. El dock y `/dash/asistente` son claros; el panel
   * del editor de landing es oscuro, y ahí el `text-fg` de siempre deja
   * la respuesta NEGRA SOBRE NEGRO — invisible, con la traza de tools y los
   * botones sí visibles, que es el peor síntoma posible porque parece que el
   * agente contestó vacío.
   *
   * El resto de `.asis-md` funciona en ambos: los links van en morado (#5158f6) y
   * los marcadores de lista en gris medio.
   */
  onSurface?: "light" | "dark"
  /**
   * Si es `false`, los `[[ir:]]` no se pintan como botón (su texto se borra
   * igual, no se enseña el marcador crudo).
   *
   * Lo usa el panel del editor de landing: ahí un botón de navegación SACA al
   * usuario del editor a media tarea, con cambios posiblemente sin guardar. El
   * system prompt ya le pide a Nik que no los mande, pero un prompt es una
   * petición y no una garantía — y el costo de que se la salte es perder
   * trabajo.
   */
  allowNav?: boolean
}) {
  const ref = useRef<HTMLDivElement>(null)

  /* Botón "copiar" en cada bloque de código. Se inyecta sobre el DOM ya
     renderizado en vez de pasar componentes a Streamdown: el markdown llega en
     streaming y re-renderiza en cada token, así que un componente custom se
     remontaría constantemente. Aquí basta con marcar los `pre` nuevos. */
  useEffect(() => {
    const root = ref.current
    if (!root) return
    root.querySelectorAll("pre").forEach((pre) => {
      if (pre.dataset.copyReady) return
      pre.dataset.copyReady = "1"
      pre.classList.add("relative", "group/code")
      const btn = document.createElement("button")
      btn.type = "button"
      btn.textContent = "Copiar"
      btn.className =
        "absolute top-2 right-2 text-[11px] font-medium px-2 py-1 rounded-md bg-white/10 text-white/80 hover:bg-white/20 opacity-0 group-hover/code:opacity-100 transition-opacity"
      btn.onclick = () => {
        navigator.clipboard.writeText(pre.innerText.replace(/\nCopiar$/, ""))
        btn.textContent = "¡Copiado!"
        window.setTimeout(() => (btn.textContent = "Copiar"), 1500)
      }
      pre.appendChild(btn)
    })
  }, [text])

  const parts =
    allowNav && hasNavMarker(text) ? parseNavParts(text, streaming) : null
  // Sin navegación permitida los marcadores se borran del texto en vez de
  // enseñarse crudos.
  const plain = allowNav
    ? text
    : text.replace(/\[\[ir:[^\]\s]+\]\]/g, "").trim()

  // Las capturas de `screenshot_url` llegan como URL PELADA en el texto, así que
  // se veían como un link azul que hay que abrir en otra pestaña — justo cuando
  // lo único que quieres es MIRAR lo que vio el agente. Se convierten a imagen
  // de markdown para que Streamdown las pinte en el hilo.
  //
  // La detección va por HOST y no por extensión: los archivos del bucket de la
  // caja no tienen ninguna (`…/AAN0XaQkExyz`), así que un `/\.(png|jpe?g)$/`
  // no habría cazado ni una sola.
  const withImages = renderScreenshots(plain)

  return (
    <div
      ref={ref}
      className={`${streaming ? "asis-stream " : ""}asis-md max-w-none break-words ${onSurface === "dark" ? "text-white/90" : "text-fg"} text-base leading-relaxed`}
    >
      {parts ? (
        parts.map((p, i) =>
          p.type === "text" ? (
            <Streamdown key={i} linkSafety={{ enabled: false }}>
              {renderScreenshots(p.value)}
            </Streamdown>
          ) : (
            <NavButton
              key={i}
              to={p.to}
              label={p.label}
              onNavigate={onNavigate}
            />
          ),
        )
      ) : (
        <Streamdown linkSafety={{ enabled: false }}>{withImages}</Streamdown>
      )}
    </div>
  )
}

/**
 * El botón que Nik pone para llevarte a una pantalla.
 *
 * En MailMask `/app` no tiene router: el botón llama a `window.mailmaskNav`
 * (expuesto por `app.js`, que usa `selectDomain`/`switchTab`), así que el dock
 * **no se desmonta** y la conversación sigue ahí cuando llegas. Con una recarga
 * perderías el hilo justo en el momento en que lo estabas usando.
 *
 * `onNavigate` lo usa la versión mobile del dock para cerrarse: ahí el panel
 * tapa la pantalla completa y quedarse abierto sobre el destino no tendría
 * sentido. En desktop no se pasa.
 */
function NavButton({
  to,
  label,
  onNavigate,
}: {
  to: string
  label: string
  onNavigate?: () => void
}) {
  return (
    <button
      type="button"
      onClick={() => {
        window.mailmaskNav?.(to)
        onNavigate?.()
      }}
      className="not-prose inline-flex items-center gap-1.5 my-1 px-3 py-1.5 rounded-full border border-line bg-bg-elev text-sm font-medium text-fg hover:border-accent hover:text-accent-text transition-colors"
    >
      {label}
      <svg
        width="14"
        height="14"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.2"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M5 12h14M13 6l6 6-6 6" />
      </svg>
    </button>
  )
}
