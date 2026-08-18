// Compositor de la Bandeja: sustituye los <textarea> por un editor con formato.
//
// Tiptap en su forma vanilla, no React: `bandeja.js` y `app.js` son JS a secas, y
// el único bundle de React del repo (docs-chat.js) pesa 10.7 MB. Este pesa una
// fracción.
//
// El formato que viaja al servidor es MARKDOWN, no HTML. Dos razones: la parte
// text/plain del correo sale gratis (el markdown ya es legible), y el HTML de
// correo lo genera el servidor con `email-html.ts`, que es el único lugar que
// sabe de las limitaciones de Outlook.
//
// La barra de formato arranca colapsada: el compositor debe verse como el
// textarea de siempre. Es un botón, no un menú flotante sobre la selección: si no
// seleccionas texto, nunca descubrirías que hay formato.

import { Editor } from "@tiptap/core";
import StarterKit from "@tiptap/starter-kit";
import Placeholder from "@tiptap/extension-placeholder";
import Image from "@tiptap/extension-image";
import { Markdown } from "tiptap-markdown";
import { Table, TableRow, TableHeader, TableCell } from "@tiptap/extension-table";
import { Node, mergeAttributes } from "@tiptap/core";
import githubAlerts from "markdown-it-github-alerts";

const CALLOUT_KINDS = ["note", "tip", "important", "warning", "caution"] as const;
type CalloutKind = (typeof CALLOUT_KINDS)[number];

const CALLOUT_LABELS: Record<CalloutKind, string> = {
  note: "Nota",
  tip: "Consejo",
  important: "Importante",
  warning: "Advertencia",
  caution: "Precaución",
};

/**
 * Caja de aviso. Es un nodo propio y no una cita con texto, porque al viajar como
 * texto el serializador escapaba los corchetes ("\\[!WARNING\\]") y el servidor ya no
 * la reconocía.
 *
 * En markdown se escribe con la sintaxis de GitHub —"> [!NOTE]"—, que también usan
 * Obsidian y VitePress: así el texto plano del correo se sigue leyendo como cita.
 */
const Callout = Node.create({
  name: "callout",
  group: "block",
  content: "block+",
  defining: true,

  addAttributes() {
    return {
      kind: {
        default: "note" as CalloutKind,
        parseHTML: (element) => element.getAttribute("data-callout") ?? "note",
        renderHTML: (attributes) => ({ "data-callout": attributes.kind }),
      },
    };
  },

  parseHTML() {
    return [{ tag: "div[data-callout]" }];
  },

  renderHTML({ HTMLAttributes, node }) {
    const kind = (node.attrs.kind ?? "note") as CalloutKind;
    return [
      "div",
      mergeAttributes(HTMLAttributes, { class: `mm-callout mm-callout-${kind}` }),
      ["div", { class: "mm-callout-label", contenteditable: "false" }, CALLOUT_LABELS[kind] ?? kind],
      ["div", { class: "mm-callout-body" }, 0],
    ];
  },

  addStorage() {
    return {
      markdown: {
        // deno-lint-ignore no-explicit-any
        serialize(state: any, node: any) {
          const kind = String(node.attrs.kind ?? "note").toUpperCase();
          state.wrapBlock("> ", null, node, () => {
            // write() no escapa: es lo que mantiene los corchetes intactos.
            state.write(`[!${kind}]`);
            state.ensureNewLine();
            state.renderContent(node);
          });
        },
        parse: {
          // deno-lint-ignore no-explicit-any
          setup(md: any) {
            md.use(githubAlerts);
            // El plugin emite <div class="markdown-alert">; aquí se necesita el
            // atributo que parseHTML busca.
            md.renderer.rules.alert_open = (tokens: any[], idx: number) =>
              `<div data-callout="${tokens[idx].meta.type}">`;
            md.renderer.rules.alert_close = () => "</div>";
          },
        },
      },
    };
  },
});

const FORMAT_PREF_KEY = "mailmask:composer:format-visible";

/** Archivo ya subido y listo para viajar dentro del correo. */
export interface AttachmentRef {
  key: string;
  filename: string;
  size: number;
}

export interface CannedResponse {
  id: string;
  title: string;
  body: string;
}

interface ComposerOptions {
  /** El <textarea> que se reemplaza. Se conserva oculto para no romper el CSS ni los tests. */
  textarea: HTMLTextAreaElement;
  placeholder?: string;
  /** Se llama con Ctrl/Cmd+Enter. */
  onSubmit?: () => void;
  /** Sube una imagen y devuelve su URL pública. Sin esto, no se ofrece insertar imágenes. */
  uploadImage?: (file: File) => Promise<string>;
  /** Sube un archivo adjunto. Sin esto no se ofrece adjuntar. */
  uploadFile?: (file: File) => Promise<AttachmentRef>;
  /** Devuelve las respuestas guardadas del dominio. Sin esto no se ofrece el menú. */
  loadCanned?: () => Promise<CannedResponse[]>;
}

export interface Composer {
  /** El markdown actual. Es lo que se manda al servidor. */
  getMarkdown(): string;
  setMarkdown(value: string): void;
  /** Los adjuntos ya subidos, para mandarlos junto al cuerpo. */
  getAttachments(): AttachmentRef[];
  clear(): void;
  focus(): void;
  destroy(): void;
}

// Íconos de Lucide, que es lo que usa el resto del repo (24x24, stroke 2) y lo que
// referencian los componentes oficiales de Tiptap (i-lucide-bold, i-lucide-italic).
// Antes eran trazos dibujados a ojo y el de la caja no se entendía.
function icon(paths: string): string {
  return `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${paths}</svg>`;
}

const ICONS: Record<string, string> = {
  bold: icon('<path d="M6 12h9a4 4 0 0 1 0 8H7a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h7a4 4 0 0 1 0 8"/>'),
  italic: icon('<line x1="19" x2="10" y1="4" y2="4"/><line x1="14" x2="5" y1="20" y2="20"/><line x1="15" x2="9" y1="4" y2="20"/>'),
  link: icon('<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>'),
  // "info": un rectángulo pelón no decía nada; esto sí se lee como aviso.
  attach: icon('<path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.57a2 2 0 0 1-2.83-2.83l8.49-8.48"/>'),
  canned: icon('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M9 15h6"/><path d="M9 11h2"/>'),
  callout: icon('<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>'),
  table: icon('<path d="M12 3v18"/><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M3 9h18"/><path d="M3 15h18"/>'),
  image: icon('<rect width="18" height="18" x="3" y="3" rx="2"/><circle cx="9" cy="9" r="2"/><path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21"/>'),
};

export function createComposer(options: ComposerOptions): Composer {
  const { textarea, onSubmit, uploadImage, uploadFile, loadCanned } = options;
  const placeholder = options.placeholder ?? textarea.placeholder ?? "";

  // El textarea sigue en el DOM pero oculto: el CSS existente lo referencia por id
  // y algunas rutas de bandeja.js todavía leen su value.
  textarea.classList.add("mm-composer-hidden-input");
  textarea.setAttribute("aria-hidden", "true");
  textarea.tabIndex = -1;

  const root = document.createElement("div");
  root.className = "mm-composer";

  const toolbar = document.createElement("div");
  toolbar.className = "mm-composer-toolbar";
  toolbar.hidden = localStorage.getItem(FORMAT_PREF_KEY) !== "1";

  const surface = document.createElement("div");
  surface.className = "mm-composer-surface";

  // Franja propia para el botón de formato. Flotarlo sobre el texto lo hacía
  // encimarse con el contenido y quedar cortado contra la barra de scroll.
  const bar = document.createElement("div");
  bar.className = "mm-composer-bar";

  // Fila de adjuntos. Vive fuera del editor: un adjunto no es parte del texto, y
  // meterlo en el documento haría que se borrara con un backspace distraído.
  const attachRow = document.createElement("div");
  attachRow.className = "mm-composer-files";
  attachRow.hidden = true;

  root.appendChild(toolbar);
  root.appendChild(surface);
  root.appendChild(attachRow);
  root.appendChild(bar);
  textarea.parentNode?.insertBefore(root, textarea);

  const editor = new Editor({
    element: surface,
    extensions: [
      StarterKit.configure({
        // Sin autolink: al teclear una URL el caret queda atrapado dentro del <a> y
        // no se puede seguir escribiendo. La URL viaja como texto y el servidor la
        // enlaza al renderizar (markdown-it con linkify).
        link: { openOnClick: false, autolink: false },
        // Se aceptan los tres niveles. Limitarlo a "##" con el argumento de que el h1
        // es el asunto era un purismo: "# " es lo primero que alguien teclea, y al no
        // hacer nada parecía que el markdown no servía.
        heading: { levels: [1, 2, 3] },
      }),
      Placeholder.configure({ placeholder }),
      Image.configure({ inline: false, allowBase64: false }),
      // Sin el nodo de tabla, una tabla de markdown se deshacía al entrar al editor:
      // los pipes desaparecían y las celdas quedaban pegadas en un párrafo.
      Table.configure({ resizable: false }),
      TableRow,
      TableHeader,
      TableCell,
      Callout,
      Markdown.configure({
        // Ningún HTML entra al documento. Al pegar desde Word, Canva o Gmail sólo
        // sobrevive lo que estas extensiones saben representar; el resto cae a
        // texto plano. La lista blanca es estructural, no un filtro que mantener.
        html: false,
        bulletListMarker: "-",
        linkify: false,
        breaks: false,
        transformPastedText: true,
      }),
    ],
    editorProps: {
      attributes: { class: "mm-composer-content" },
      handleKeyDown: (_view, event) => {
        // Ctrl/Cmd+Enter envía: es lo que ya anuncia la pista del compositor.
        if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
          event.preventDefault();
          onSubmit?.();
          return true;
        }
        return false;
      },
      handlePaste: (_view, event) => handleFiles(event, Array.from(event.clipboardData?.files ?? [])),
      handleDrop: (_view, event) =>
        handleFiles(event, Array.from((event as DragEvent).dataTransfer?.files ?? [])),
    },
    onUpdate: ({ editor }) => {
      // Espejo al textarea oculto: bandeja.js lo lee en varios sitios y así no hay
      // que tocarlos todos a la vez.
      textarea.value = editor.storage.markdown.getMarkdown();
    },
  });

  const attachments: AttachmentRef[] = [];

  function formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  function renderAttachments() {
    attachRow.hidden = attachments.length === 0;
    attachRow.textContent = "";
    attachments.forEach((file, i) => {
      const chip = document.createElement("span");
      chip.className = "mm-file-chip";

      const name = document.createElement("span");
      name.className = "mm-file-name";
      name.textContent = file.filename;
      name.title = file.filename;

      const size = document.createElement("span");
      size.className = "mm-file-size";
      size.textContent = formatSize(file.size);

      const quitar = document.createElement("button");
      quitar.type = "button";
      quitar.className = "mm-file-remove";
      quitar.title = `Quitar ${file.filename}`;
      quitar.setAttribute("aria-label", quitar.title);
      quitar.textContent = "×";
      quitar.addEventListener("click", () => {
        attachments.splice(i, 1);
        renderAttachments();
      });

      chip.append(name, size, quitar);
      attachRow.appendChild(chip);
    });
  }

  async function addFiles(files: File[]) {
    if (!uploadFile) return;
    for (const file of files) {
      // Marcador mientras sube: sin él, en una conexión lenta parece que no pasó nada.
      const pendiente: AttachmentRef = { key: "", filename: file.name, size: file.size };
      attachments.push(pendiente);
      renderAttachments();
      try {
        const subido = await uploadFile(file);
        Object.assign(pendiente, subido);
      } catch (err) {
        const i = attachments.indexOf(pendiente);
        if (i >= 0) attachments.splice(i, 1);
        aviso(err instanceof Error ? err.message : `No se pudo subir ${file.name}`);
      }
      renderAttachments();
    }
  }

  /**
   * Archivos que llegan pegados o soltados encima del editor.
   *
   * Se interceptan TODOS, no sólo las imágenes: al dejar pasar un PDF, el navegador
   * hacía lo suyo —abrirlo— y con eso se llevaba la pestaña y el borrador sin
   * guardar. Perder lo escrito por soltar un archivo de más es inaceptable.
   */
  function handleFiles(event: Event, files: File[]): boolean {
    if (!files.length) return false;
    event.preventDefault();

    // Una imagen se INSERTA en el cuerpo; cualquier otra cosa se ADJUNTA. Es lo que
    // hace Gmail y lo que la gente espera al arrastrar una foto frente a un PDF.
    const images = files.filter((f) => f.type.startsWith("image/"));
    const otros = files.filter((f) => !f.type.startsWith("image/"));

    if (images.length) {
      if (uploadImage) void insertImages(images);
      else if (uploadFile) void addFiles(images);
      else aviso("No se pueden subir imágenes en este compositor");
    }
    if (otros.length) {
      if (uploadFile) void addFiles(otros);
      else aviso("No se pueden adjuntar archivos en este compositor");
    }
    return true;
  }

  function aviso(mensaje: string) {
    window.dispatchEvent(new CustomEvent("mm:toast", { detail: mensaje }));
  }

  async function insertImages(files: File[]) {
    if (!uploadImage) return;
    for (const file of files) {
      try {
        const url = await uploadImage(file);
        // El alt sale del nombre del archivo: Outlook bloquea imágenes por defecto
        // y el alt es lo único que se lee hasta que el destinatario las habilita.
        const alt = file.name.replace(/\.[^.]+$/, "") || "imagen";
        editor.chain().focus().setImage({ src: url, alt }).run();
      } catch (err) {
        console.error("[composer] no se pudo subir la imagen", err);
        aviso(err instanceof Error ? err.message : "No se pudo subir la imagen");
      }
    }
  }

  // --- Barra de formato ---

  interface Tool {
    key: string;
    title: string;
    run: () => void;
    active?: () => boolean;
  }

  // Sólo lo que no se puede teclear. StarterKit trae las reglas de entrada de
  // markdown: "- " hace la lista, "## " el título, "> " la cita, "1. " la numerada.
  // Un botón para cada una duplicaría algo que ya ocurre solo y llenaría la barra.
  const tools: Tool[] = [
    { key: "bold", title: "Negrita (Ctrl+B)", run: () => editor.chain().focus().toggleBold().run(), active: () => editor.isActive("bold") },
    { key: "italic", title: "Cursiva (Ctrl+I)", run: () => editor.chain().focus().toggleItalic().run(), active: () => editor.isActive("italic") },
    { key: "link", title: "Enlace", run: promptLink, active: () => editor.isActive("link") },
    // Estos dos sí llevan botón: su sintaxis no es adivinable, a diferencia de "- "
    // o "## ". Insertan el esqueleto y el usuario rellena.
    { key: "callout", title: "Caja de aviso", run: insertCallout },
    { key: "table", title: "Tabla", run: insertTable },
  ];

  if (uploadImage) {
    tools.push({ key: "image", title: "Insertar imagen", run: pickImage });
  }
  if (uploadFile) {
    tools.push({ key: "attach", title: "Adjuntar archivo", run: pickAttachment });
  }
  if (loadCanned) {
    tools.push({ key: "canned", title: "Respuestas guardadas", run: openCanned });
  }

  const buttons = tools.map((tool) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "mm-composer-tool";
    btn.title = tool.title;
    btn.innerHTML = ICONS[tool.key] ?? tool.key;
    // mousedown en vez de click, y preventDefault: si no, el editor pierde el foco
    // y el formato se aplica sobre una selección que ya no existe.
    btn.addEventListener("mousedown", (e) => e.preventDefault());
    btn.addEventListener("click", () => {
      tool.run();
      refreshToolbar();
    });
    toolbar.appendChild(btn);
    return { tool, btn };
  });

  function refreshToolbar() {
    for (const { tool, btn } of buttons) {
      btn.classList.toggle("is-active", tool.active?.() ?? false);
    }
  }
  editor.on("selectionUpdate", refreshToolbar);
  editor.on("transaction", refreshToolbar);

  function promptLink() {
    const previous = editor.getAttributes("link").href as string | undefined;
    const url = window.prompt("URL del enlace", previous ?? "https://");
    if (url === null) return;
    if (!url.trim()) {
      editor.chain().focus().extendMarkRange("link").unsetLink().run();
      return;
    }
    // Sólo http, https y mailto. El servidor lo vuelve a validar, pero avisar aquí
    // evita que el usuario crea que quedó puesto.
    if (!/^(https?:\/\/|mailto:)/i.test(url.trim())) {
      aviso("El enlace debe empezar con https:// o mailto:");
      return;
    }
    editor.chain().focus().extendMarkRange("link").setLink({ href: url.trim() }).run();
  }

  // La caja se ve como caja ya en el editor; el servidor la pinta con su color.
  function insertCallout() {
    editor.chain().focus().insertContent({
      type: "callout",
      attrs: { kind: "note" },
      content: [{ type: "paragraph", content: [{ type: "text", text: "Escribe aquí el aviso." }] }],
    }).run();
  }

  // Tabla real: se edita celda por celda y se serializa a pipes de markdown.
  function insertTable() {
    editor.chain().focus().insertTable({ rows: 3, cols: 2, withHeaderRow: true }).run();
  }

  function pickAttachment() {
    const input = document.createElement("input");
    input.type = "file";
    input.multiple = true;
    input.addEventListener("change", () => {
      const files = Array.from(input.files ?? []);
      if (files.length) void addFiles(files);
    });
    input.click();
  }

  // Menú de respuestas guardadas. Se pide la lista al abrirlo y no al montar: la
  // mayoría de las veces nadie lo abre, y así no se paga la petición por gusto.
  let cannedMenu: HTMLElement | null = null;
  async function openCanned() {
    if (!loadCanned) return;
    if (cannedMenu) { cerrarCanned(); return; }

    const menu = document.createElement("div");
    menu.className = "mm-canned-menu";
    menu.textContent = "Cargando…";
    root.appendChild(menu);
    cannedMenu = menu;

    let items: CannedResponse[] = [];
    try {
      items = await loadCanned();
    } catch {
      menu.textContent = "No se pudieron cargar";
      return;
    }
    menu.textContent = "";
    if (!items.length) {
      const vacio = document.createElement("div");
      vacio.className = "mm-canned-empty";
      vacio.textContent = "No hay respuestas guardadas todavía";
      menu.appendChild(vacio);
      return;
    }
    for (const item of items) {
      const opcion = document.createElement("button");
      opcion.type = "button";
      opcion.className = "mm-canned-item";
      const t = document.createElement("span");
      t.className = "mm-canned-title";
      t.textContent = item.title;
      const p = document.createElement("span");
      p.className = "mm-canned-preview";
      p.textContent = item.body.replace(/\s+/g, " ").slice(0, 70);
      opcion.append(t, p);
      opcion.addEventListener("click", () => {
        // Se pasa el markdown crudo: tiptap-markdown ya intercepta insertContent y lo
        // parsea. Convertirlo a HTML antes lo insertaba escapado, porque el editor
        // corre con html:false y trata cualquier etiqueta como texto.
        //
        // Se inserta en el cursor y no reemplaza: casi siempre se saluda antes y se
        // despide después de la plantilla.
        editor.chain().focus().insertContent(item.body).run();
        cerrarCanned();
      });
      menu.appendChild(opcion);
    }
  }

  function cerrarCanned() {
    cannedMenu?.remove();
    cannedMenu = null;
  }

  function pickImage() {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = "image/png,image/jpeg,image/gif,image/webp";
    input.multiple = true;
    input.addEventListener("change", () => {
      const files = Array.from(input.files ?? []);
      if (files.length) void insertImages(files);
    });
    input.click();
  }

  // Botón que muestra u oculta la barra. Vive fuera del editor para que el
  // compositor se vea como un textarea hasta que alguien lo pida.
  const toggle = document.createElement("button");
  toggle.type = "button";
  toggle.className = "mm-composer-toggle";
  toggle.title = "Mostrar u ocultar formato";
  toggle.textContent = "Aa";
  toggle.setAttribute("aria-expanded", String(!toolbar.hidden));
  toggle.addEventListener("click", () => {
    toolbar.hidden = !toolbar.hidden;
    toggle.setAttribute("aria-expanded", String(!toolbar.hidden));
    toggle.classList.toggle("is-active", !toolbar.hidden);
    localStorage.setItem(FORMAT_PREF_KEY, toolbar.hidden ? "0" : "1");
    editor.commands.focus();
  });
  toggle.classList.toggle("is-active", !toolbar.hidden);
  bar.appendChild(toggle);

  // Expandir. El compositor por omisión es bajo para no comerse la conversación,
  // pero escribir un correo largo ahí es incómodo: esto le da altura sin sacar al
  // usuario de la pantalla.
  const EXPAND_PREF_KEY = "mailmask:composer:expanded";
  const expand = document.createElement("button");
  expand.type = "button";
  expand.className = "mm-composer-toggle mm-composer-expand";
  // Fondo del modo pantalla completa. Se crea una sola vez y vive en <body> para que
  // ningún `overflow` de un contenedor lo recorte.
  const backdrop = document.createElement("div");
  backdrop.className = "mm-composer-backdrop";
  backdrop.hidden = true;

  // Qué crece al expandir. Se busca el contenedor y no sólo el editor: si no, los
  // botones (Responder / Nota interna / Enviar, o Cancelar / Enviar) se quedaban
  // fuera y no había forma de mandar el correo sin cerrar.
  //
  // Si el compositor ya vive dentro de un modal —el de "Redactar"—, se agranda ESE.
  // Crear un segundo modal encima no funcionaba: `.mesa-modal-overlay` tiene
  // z-index 100 y con ello su propio contexto de apilamiento, así que el editor
  // quedaba atrapado debajo de nuestro fondo y sólo se veía la capa oscura.
  const hostModal = root.closest(".mesa-modal") as HTMLElement | null;
  const expandTarget = hostModal ?? (root.closest(".mesa-composer") as HTMLElement | null) ?? root;

  const applyExpanded = (on: boolean) => {
    // Nada se reparenta: se posiciona con CSS fijo. Mover el editor de nodo padre
    // destruiría la vista de ProseMirror y con ella el borrador sin guardar.
    expandTarget.classList.toggle("is-expanded", on);
    root.classList.toggle("is-expanded", on);
    // Dentro de un modal ya hay capa oscura y el scroll ya está bloqueado: poner
    // otra lo taparía todo.
    if (!hostModal) {
      document.body.classList.toggle("mm-composer-locked", on);
      backdrop.hidden = !on;
      if (on && !backdrop.isConnected) document.body.appendChild(backdrop);
    }
    expand.classList.toggle("is-active", on);
    expand.title = on ? "Reducir el editor" : "Expandir el editor";
    expand.setAttribute("aria-label", expand.title);
    // lucide "shrink" y "expand".
    expand.innerHTML = on
      ? icon('<path d="m15 15 6 6"/><path d="m15 9 6-6"/><path d="M21 16v5h-5"/><path d="M21 8V3h-5"/><path d="M3 16v5h5"/><path d="m3 21 6-6"/><path d="M3 8V3h5"/><path d="M9 9 3 3"/>')
      : icon('<path d="m21 21-6-6m6 6v-4.8m0 4.8h-4.8"/><path d="M3 16.2V21m0 0h4.8M3 21l6-6"/><path d="M21 7.8V3m0 0h-4.8M21 3l-6 6"/><path d="M3 7.8V3m0 0h4.8M3 3l6 6"/>');
  };
  // Siempre colapsado al montar: recordar "pantalla completa" haría que la Bandeja
  // abriera tapada, que no es lo que nadie espera.
  applyExpanded(false);
  const setExpanded = (on: boolean) => {
    applyExpanded(on);
    localStorage.setItem(EXPAND_PREF_KEY, on ? "1" : "0");
    editor.commands.focus();
  };
  expand.addEventListener("click", () => setExpanded(!expandTarget.classList.contains("is-expanded")));
  backdrop.addEventListener("click", () => setExpanded(false));
  // Escape cierra, que es lo que cualquiera intenta primero en un modal.
  const onEscape = (e: KeyboardEvent) => {
    if (e.key === "Escape" && expandTarget.classList.contains("is-expanded")) {
      e.preventDefault();
      setExpanded(false);
    }
  };
  document.addEventListener("keydown", onEscape);
  bar.appendChild(expand);

  const hint = document.createElement("span");
  hint.className = "mm-composer-hint-md";
  hint.textContent = "Teclea  -  lista   #  título   >  cita";
  bar.appendChild(hint);

  return {
    getMarkdown: () => editor.storage.markdown.getMarkdown(),
    setMarkdown: (value: string) => {
      editor.commands.setContent(value ?? "");
      textarea.value = value ?? "";
    },
    getAttachments: () => attachments.filter((a) => a.key),
    clear: () => {
      editor.commands.clearContent(true);
      textarea.value = "";
      attachments.length = 0;
      renderAttachments();
      cerrarCanned();
    },
    focus: () => editor.commands.focus("end"),
    destroy: () => {
      document.removeEventListener("keydown", onEscape);
      document.body.classList.remove("mm-composer-locked");
      expandTarget.classList.remove("is-expanded");
      backdrop.remove();
      editor.destroy();
      root.remove();
      textarea.classList.remove("mm-composer-hidden-input");
      textarea.removeAttribute("aria-hidden");
    },
  };
}

// bandeja.js es un script clásico, no un módulo: se expone en window.
declare global {
  interface Window {
    MailMaskComposer?: { create: typeof createComposer };
  }
}
window.MailMaskComposer = { create: createComposer };
