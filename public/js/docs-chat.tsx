import React, { useState, useRef, useEffect } from "react";
import { createRoot } from "react-dom/client";
import { createPortal } from "react-dom";
import {
  FormmyProvider,
  useFormmyChat,
  getMessageText,
} from "@formmy.app/chat/react";
import { Streamdown } from "streamdown";
import { createCodePlugin } from "@streamdown/code";

const codePlugin = createCodePlugin({
  themes: ["github-dark", "github-dark"],
});

const PK = "formmy_pk_live_pw-wnkzJQh3Q02m2hEqVFebjHo39T7lg";
const AGENT_ID = "6962a45fbe5361f571b8369e";

// Web Audio beep on assistant message
function playBeep() {
  try {
    const ctx = new AudioContext();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.type = "sine";
    osc.frequency.value = 880;
    gain.gain.value = 0.08;
    osc.start();
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.15);
    osc.stop(ctx.currentTime + 0.15);
  } catch {}
}

// Iconos de trazo para las tarjetas de "Para empezar"
const iconProps = {
  width: 18,
  height: 18,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 2,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
};

const ICONS: Record<string, React.ReactNode> = {
  globe: (
    <svg {...iconProps}>
      <circle cx="12" cy="12" r="10" />
      <path d="M2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20" />
    </svg>
  ),
  mask: (
    <svg {...iconProps}>
      <circle cx="12" cy="12" r="4" />
      <path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-4 8" />
    </svg>
  ),
  send: (
    <svg {...iconProps}>
      <path d="M22 2 11 13M22 2l-7 20-4-9-9-4 20-7z" />
    </svg>
  ),
  plug: (
    <svg {...iconProps}>
      <path d="M9 2v6M15 2v6M6 8h12v4a6 6 0 0 1-12 0V8zM12 18v4" />
    </svg>
  ),
  code: (
    <svg {...iconProps}>
      <rect x="2" y="4" width="20" height="16" rx="2" />
      <path d="m9 10-2 2 2 2M15 10l2 2-2 2" />
    </svg>
  ),
};

const SUGGESTIONS = [
  { icon: "globe", q: "\u00bfC\u00f3mo conecto mi primer dominio?" },
  { icon: "mask", q: "\u00bfC\u00f3mo creo una m\u00e1scara que reenv\u00ede a mi Gmail?" },
  { icon: "send", q: "\u00bfC\u00f3mo env\u00edo correo desde mi dominio con la API?" },
  { icon: "plug", q: "\u00bfC\u00f3mo conecto MailMask a mi agente por MCP?" },
  { icon: "code", q: "\u00bfC\u00f3mo empiezo con el SDK de Node.js?" },
];

function Sparkle({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="rgb(var(--accent))" strokeWidth="2" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <path d="M12 6c.5 3 2 4.5 5 6-3 .5-4.5 2-5 5-.5-3-2-4.5-5-5 3-1.5 4.5-3 5-6z" fill="rgb(var(--accent))" />
    </svg>
  );
}

type Mode = "docked" | "floating" | "closed";

type ChatProps = {
  mode: Mode | "mobile" | "solo";
  onToggleDock?: () => void;
  onClose?: () => void;
};

function IconButton({ title, onClick, children }: { title: string; onClick: () => void; children: React.ReactNode }) {
  return (
    <button className="docs-chat-iconbtn" title={title} aria-label={title} onClick={onClick}>
      {children}
    </button>
  );
}

function Chat({ mode, onToggleDock, onClose }: ChatProps) {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const [input, setInput] = useState("");
  const bottomRef = useRef<HTMLDivElement>(null);
  const messagesRef = useRef<HTMLDivElement>(null);
  const prevCountRef = useRef(0);


  const { messages, sendMessage, status, reset, error } = useFormmyChat({
    agentId: AGENT_ID,
    onFinish: () => {
      playBeep();
    },
    onError: (err: any) => {
      console.error("[docs-chat] onError callback:", err);
    },
  });

  const isLoading = status === "streaming" || status === "submitted";

  useEffect(() => {
    if (!menuOpen) return;
    const close = (e: MouseEvent) => {
      if (!menuRef.current?.contains(e.target as Node)) setMenuOpen(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [menuOpen]);

  // Auto-scroll
  useEffect(() => {
    if (messages.length > 0) {
      if (messagesRef.current) {
        messagesRef.current.scrollTop = messagesRef.current.scrollHeight;
      }
    }
  }, [messages, status]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isLoading) return;
    const msg = input.trim();
    setInput("");
    try {
      await sendMessage(msg);
    } catch (err) {
      console.error("[docs-chat] sendMessage threw:", err);
    }
  };

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        background: "rgb(var(--bg-elev))",
        overflow: "hidden",
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: "12px 12px 12px 20px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexShrink: 0,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontWeight: 600, fontSize: 16, color: "rgb(var(--fg))" }}>
            Asistente IA
          </span>
          <Sparkle />
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 2 }}>
          {onToggleDock && (
            <IconButton
              title={mode === "floating" ? "Acoplar al costado" : "Desacoplar"}
              onClick={onToggleDock}
            >
              {mode === "floating" ? (
                <svg {...iconProps}>
                  <rect x="3" y="3" width="18" height="18" rx="2" />
                  <path d="M15 3v18" />
                </svg>
              ) : (
                <svg {...iconProps}>
                  <rect x="3" y="8" width="13" height="13" rx="2" />
                  <path d="M8 8V5a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-3" />
                </svg>
              )}
            </IconButton>
          )}
          <div ref={menuRef} style={{ position: "relative" }}>
            <IconButton title="M\u00e1s opciones" onClick={() => setMenuOpen((v) => !v)}>
              <svg {...iconProps}>
                <circle cx="12" cy="5" r="1" />
                <circle cx="12" cy="12" r="1" />
                <circle cx="12" cy="19" r="1" />
              </svg>
            </IconButton>
            {menuOpen && (
              <div className="docs-chat-menu" role="menu">
                <button
                  role="menuitem"
                  className="danger"
                  onClick={() => {
                    reset();
                    setMenuOpen(false);
                  }}
                >
                  <svg {...iconProps} width={16} height={16}>
                    <path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14M10 11v6M14 11v6" />
                  </svg>
                  Limpiar conversaci&oacute;n
                </button>
                {mode !== "solo" && (
                  <button
                    role="menuitem"
                    onClick={() => {
                      window.open("/docs?chat=solo", "_blank", "noopener");
                      setMenuOpen(false);
                    }}
                  >
                    <svg {...iconProps} width={16} height={16}>
                      <path d="M14 3h7v7M21 3l-9 9M19 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h5" />
                    </svg>
                    Abrir en pesta&ntilde;a nueva
                  </button>
                )}
              </div>
            )}
          </div>
          {onClose && (
            <IconButton title="Cerrar" onClick={onClose}>
              <svg {...iconProps}>
                <path d="M18 6 6 18M6 6l12 12" />
              </svg>
            </IconButton>
          )}
        </div>
      </div>

      {/* Messages */}
      <div
        ref={messagesRef}
        style={{
          flex: 1,
          overflowY: "auto",
          overflowX: "hidden",
          padding: 16,
          display: "flex",
          flexDirection: "column",
          gap: 12,
        }}
      >
        {messages.length === 0 && !isLoading && (
          <div style={{ padding: "28px 8px 0" }}>
            <h2
              style={{
                fontFamily: '"Bricolage Grotesque", Inter, system-ui, sans-serif',
                fontWeight: 800,
                fontSize: 28,
                lineHeight: 1.15,
                letterSpacing: "-0.02em",
                color: "rgb(var(--fg))",
                margin: 0,
              }}
            >
              &#128075; Soy el{" "}
              <span style={{ color: "rgb(var(--accent-text))" }}>Asistente IA</span>{" "}
              de MailMask.
            </h2>
            <p style={{ fontSize: 17, lineHeight: 1.5, color: "rgb(var(--fg-muted))", margin: "10px 0 0" }}>
              Te ayudo a encontrar respuestas en la documentaci&oacute;n. &iquest;Qu&eacute; buscas?
            </p>
            <p style={{ fontSize: 15, color: "rgb(var(--fg-subtle))", margin: "36px 0 10px" }}>
              Para empezar
            </p>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {SUGGESTIONS.map(({ icon, q }) => (
                <button
                  key={q}
                  className="docs-chat-suggestion"
                  onClick={() => sendMessage(q)}
                >
                  <span className="docs-chat-suggestion-icon">{ICONS[icon]}</span>
                  <span>{q}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg) => {
          const text = getMessageText(msg);
          const isUser = msg.role === "user";
          return (
            <div
              key={msg.id}
              style={{
                display: "flex",
                justifyContent: isUser ? "flex-end" : "flex-start",
              }}
            >
              <div
                style={{
                  maxWidth: "100%",
                  padding: isUser ? "8px 14px" : "0",
                  borderRadius: 12,
                  fontSize: 15,
                  lineHeight: 1.6,
                  ...(isUser
                    ? {
                        background:
                          "linear-gradient(135deg, rgb(var(--accent-text)), rgb(var(--accent)))",
                        color: "#fff",
                      }
                    : { color: "rgb(var(--fg-muted))" }),
                }}
              >
                {isUser ? (
                  text
                ) : (
                  <div className="streamdown-wrap">
                    <Streamdown
                      plugins={{ code: codePlugin }}
                      isAnimating={status === "streaming"}
                    >
                      {text}
                    </Streamdown>
                  </div>
                )}
              </div>
            </div>
          );
        })}

        {isLoading && messages[messages.length - 1]?.role === "user" && (
          <div style={{ display: "flex", gap: 4, padding: "4px 0" }}>
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                style={{
                  width: 6,
                  height: 6,
                  borderRadius: "50%",
                  background: "rgb(var(--fg-subtle))",
                  animation: `pulse 1s ease-in-out ${i * 0.15}s infinite`,
                }}
              />
            ))}
          </div>
        )}

        {error && (
          <div
            style={{
              color: "#ef4444",
              fontSize: 12,
              padding: "8px 12px",
              background: "rgb(var(--accent) / 0.08)",
              borderRadius: 8,
            }}
          >
            Error: {error.message}
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <form onSubmit={handleSubmit} style={{ padding: "12px 16px 10px", flexShrink: 0 }}>
        <div className="docs-chat-box">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              // Enter envía, Shift+Enter hace salto de línea
              if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
                e.preventDefault();
                handleSubmit(e as unknown as React.FormEvent);
              }
            }}
            placeholder="&iquest;En qu&eacute; te ayudo?"
            disabled={isLoading}
            rows={3}
          />
          <button
            type="submit"
            disabled={isLoading || !input.trim()}
            title="Enviar"
            aria-label="Enviar"
          >
            <svg {...iconProps} width={20} height={20}>
              <path d="M4 4l16 8-16 8 3-8-3-8zM7 12h13" />
            </svg>
          </button>
        </div>
        <p
          style={{
            fontSize: 12,
            lineHeight: 1.5,
            color: "rgb(var(--fg-subtle))",
            textAlign: "center",
            margin: "8px 4px 0",
          }}
        >
          Funciona con{" "}
          <a href="https://www.formmy.app" target="_blank" rel="noopener" style={{ color: "inherit", textDecoration: "underline" }}>
            Formmy
          </a>
          . Las respuestas generadas por IA pueden equivocarse; verif&iacute;calas antes de usarlas. No compartas informaci&oacute;n sensible.
        </p>
      </form>

      <style>{`
        .docs-chat-iconbtn {
          background: none;
          border: none;
          border-radius: 6px;
          padding: 6px;
          display: flex;
          color: rgb(var(--fg-muted));
          cursor: pointer;
        }
        .docs-chat-iconbtn:hover { background: rgb(var(--bg-inset)); color: rgb(var(--fg)); }
        .docs-chat-menu {
          position: absolute;
          right: 0;
          top: calc(100% + 6px);
          z-index: 20;
          min-width: 240px;
          padding: 6px;
          background: rgb(var(--bg-elev));
          border: 1px solid rgb(var(--line));
          border-radius: 8px;
          box-shadow: 0 10px 30px rgba(0,0,0,0.25);
        }
        .docs-chat-menu button {
          display: flex;
          align-items: center;
          gap: 10px;
          width: 100%;
          background: none;
          border: none;
          border-radius: 6px;
          padding: 10px 12px;
          color: rgb(var(--fg));
          font-size: 15px;
          text-align: left;
          cursor: pointer;
        }
        .docs-chat-menu button:hover { background: rgb(var(--bg-inset)); }
        .docs-chat-menu button.danger { color: rgb(var(--accent-text)); }
        .docs-chat-suggestion {
          display: flex;
          align-items: center;
          gap: 12px;
          width: 100%;
          text-align: left;
          background: rgb(var(--bg));
          border: 1px solid rgb(var(--line));
          border-radius: 6px;
          padding: 12px 14px;
          color: rgb(var(--fg));
          font-size: 15px;
          line-height: 1.45;
          cursor: pointer;
          transition: border-color 120ms, background 120ms;
        }
        .docs-chat-suggestion:hover {
          border-color: rgb(var(--accent));
          background: rgb(var(--bg-inset));
        }
        .docs-chat-suggestion-icon {
          flex-shrink: 0;
          width: 30px;
          height: 30px;
          border-radius: 6px;
          display: flex;
          align-items: center;
          justify-content: center;
          background: rgb(var(--bg-inset));
          color: rgb(var(--fg-muted));
        }
        .docs-chat-box {
          position: relative;
          background: rgb(var(--bg-inset));
          border: 1px solid rgb(var(--line));
          border-radius: 6px;
          transition: border-color 120ms;
        }
        .docs-chat-box:focus-within { border-color: rgb(var(--accent)); }
        .docs-chat-box textarea {
          display: block;
          width: 100%;
          resize: none;
          background: transparent;
          border: none;
          outline: none;
          padding: 12px 44px 12px 12px;
          color: rgb(var(--fg));
          font: inherit;
          font-size: 16px;
          line-height: 1.5;
        }
        .docs-chat-box textarea::placeholder { color: rgb(var(--fg-subtle)); }
        .docs-chat-box button {
          position: absolute;
          right: 8px;
          bottom: 8px;
          background: none;
          border: none;
          padding: 6px;
          display: flex;
          color: rgb(var(--accent));
          cursor: pointer;
        }
        .docs-chat-box button:disabled { color: rgb(var(--fg-subtle)); cursor: not-allowed; }
        @keyframes pulse {
          0%, 100% { opacity: 0.3; transform: scale(0.8); }
          50% { opacity: 1; transform: scale(1); }
        }
        /* Streamdown Tailwind JIT class replacements */
        .streamdown-wrap .text-\[var\(--sdm-c\,inherit\)\] {
          color: var(--sdm-c, inherit);
        }
        .streamdown-wrap .bg-\[var\(--sdm-tbg\)\] {
          background-color: var(--sdm-tbg);
        }
        .streamdown-wrap .bg-\[var\(--sdm-bg\,inherit\)\] {
          background-color: var(--sdm-bg, inherit);
        }
        .streamdown-wrap .bg-background { background-color: rgb(var(--bg-elev)); }
        .streamdown-wrap .text-muted-foreground { color: rgb(var(--fg-subtle)); }
        .streamdown-wrap .text-foreground { color: rgb(var(--fg)); }
        .streamdown-wrap .border-border { border-color: rgb(var(--line)); }
        .streamdown-wrap .text-sm { font-size: 0.875rem; }
        .streamdown-wrap .text-xs { font-size: 0.75rem; }
        .streamdown-wrap .font-mono { font-family: ui-monospace, SFMono-Regular, monospace; }
        .streamdown-wrap .lowercase { text-transform: lowercase; }
        .streamdown-wrap .rounded-md { border-radius: 6px; }
        .streamdown-wrap .rounded-xl { border-radius: 12px; }
        .streamdown-wrap .overflow-hidden { overflow: hidden; }
        .streamdown-wrap .border { border-width: 1px; border-style: solid; }
        .streamdown-wrap .p-4 { padding: 1rem; }
        .streamdown-wrap .my-4 { margin-top: 1rem; margin-bottom: 1rem; }
        .streamdown-wrap .flex { display: flex; }
        .streamdown-wrap .w-full { width: 100%; }
        .streamdown-wrap .flex-col { flex-direction: column; }
        .streamdown-wrap .gap-2 { gap: 0.5rem; }
        .streamdown-wrap .items-center { align-items: center; }
        .streamdown-wrap .justify-end { justify-content: flex-end; }
        .streamdown-wrap .h-8 { height: 2rem; }
        .streamdown-wrap .shrink-0 { flex-shrink: 0; }
        .streamdown-wrap .pointer-events-none { pointer-events: none; }
        .streamdown-wrap .pointer-events-auto { pointer-events: auto; }
        .streamdown-wrap .sticky { position: sticky; }
        .streamdown-wrap .top-2 { top: 0.5rem; }
        .streamdown-wrap .z-10 { z-index: 10; }
        .streamdown-wrap .-mt-10 { margin-top: -2.5rem; }
        .streamdown-wrap .ml-1 { margin-left: 0.25rem; }
        .streamdown-wrap .p-1 { padding: 0.25rem; }
        .streamdown-wrap .cursor-pointer { cursor: pointer; }
        .streamdown-wrap .transition-all { transition: all 150ms; }
        .streamdown-wrap .divide-y > * + * { border-top: 1px solid rgb(var(--line)); }
        .streamdown-wrap {
          min-width: 0;
          overflow: hidden;
        }
        .streamdown-wrap [data-streamdown="code-block"] {
          background: rgb(var(--bg-inset));
          border: 1px solid rgb(var(--line));
          border-radius: 12px;
          overflow: hidden;
          margin: 8px 0;
          max-width: 100%;
          min-width: 0;
        }
        .streamdown-wrap [data-streamdown="code-block-body"] {
          overflow-x: auto;
        }
        .streamdown-wrap [data-streamdown="code-block"] pre {
          background: transparent !important;
          border: none;
          border-radius: 0;
          margin: 0;
        }
        .streamdown-wrap [data-streamdown="code-block-header"] {
          background: rgb(var(--bg-inset));
          border-bottom: 1px solid rgb(var(--line));
          padding: 0 12px;
        }
        .streamdown-wrap pre {
          background: rgb(var(--bg-inset)) !important;
          border: 1px solid rgb(var(--line));
          border-radius: 8px;
          overflow-x: auto;
          font-size: 13px;
          margin: 8px 0;
          padding: 10px 12px;
          max-width: 100%;
        }
        .streamdown-wrap code {
          font-size: 13px;
        }
        .streamdown-wrap ::-webkit-scrollbar {
          width: 4px;
          height: 4px;
        }
        .streamdown-wrap ::-webkit-scrollbar-track {
          background: transparent;
        }
        .streamdown-wrap ::-webkit-scrollbar-thumb {
          background: rgb(var(--line));
          border-radius: 4px;
        }
        .streamdown-wrap p { margin: 6px 0; }
        .streamdown-wrap ul, .streamdown-wrap ol { margin: 6px 0; padding-left: 20px; }
        .streamdown-wrap a { color: rgb(var(--accent-text)); text-decoration: underline; }
        .streamdown-wrap h1, .streamdown-wrap h2, .streamdown-wrap h3 {
          color: rgb(var(--fg));
          margin: 12px 0 6px;
          font-weight: 600;
        }
        .streamdown-wrap code:not(pre code) {
          background: rgb(var(--line));
          padding: 2px 6px;
          border-radius: 4px;
          font-size: 13px;
          color: rgb(var(--accent-text));
        }
      `}</style>
    </div>
  );
}

// El chat vive en un solo nodo que se mueve entre el costado, el panel flotante y
// la pantalla completa: así cambiar de modo no desmonta el hook ni pierde la conversación.
const chatHost = document.createElement("div");
chatHost.style.height = "100%";

const MODE_KEY = "docs-chat-mode";

function readMode(): Mode {
  try {
    const v = localStorage.getItem(MODE_KEY);
    if (v === "docked" || v === "floating" || v === "closed") return v;
  } catch {}
  return "docked";
}

function saveMode(m: Mode) {
  try {
    localStorage.setItem(MODE_KEY, m);
  } catch {}
}

type Size = "phone" | "tablet" | "desktop";

// phone < 768 (pantalla completa), tablet 768–1279 (panel flotante), desktop ≥ 1280 (acoplable)
function readSize(): Size {
  const w = window.innerWidth;
  return w < 768 ? "phone" : w < 1280 ? "tablet" : "desktop";
}

function App({ aside }: { aside: HTMLElement }) {
  const solo = new URLSearchParams(location.search).get("chat") === "solo";
  const [size, setSize] = useState<Size>(readSize);
  const [mode, setModeState] = useState<Mode>(readMode);
  const [overlayOpen, setOverlayOpen] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  const desktop = size === "desktop";

  const setMode = (m: Mode) => {
    setModeState(m);
    saveMode(m);
  };

  useEffect(() => {
    const check = () => setSize(readSize());
    window.addEventListener("resize", check);
    return () => window.removeEventListener("resize", check);
  }, []);

  const docked = !solo && desktop && mode === "docked";
  const panelVisible = solo || (desktop ? mode === "floating" : overlayOpen);

  // Sin chat acoplado, la rejilla de docs.html suelta la tercera columna
  useEffect(() => {
    document.documentElement.classList.toggle("docs-chat-undocked", !docked);
  }, [docked]);

  // Mover el nodo del chat a donde toque
  useEffect(() => {
    const target = docked ? aside : panelVisible ? panelRef.current : null;
    if (target && chatHost.parentNode !== target) target.appendChild(chatHost);
    if (!target && chatHost.parentNode) chatHost.parentNode.removeChild(chatHost);
  });

  const chatOpen = docked || panelVisible;

  // Trigger de la barra superior: abre el chat o lo cierra
  const toggleRef = useRef<() => void>(() => {});
  toggleRef.current = () => {
    if (!desktop) setOverlayOpen((v) => !v);
    else setMode(chatOpen ? "closed" : "docked");
  };
  useEffect(() => {
    const btn = document.getElementById("docs-chat-trigger");
    if (!btn) return;
    const onClick = () => toggleRef.current();
    btn.addEventListener("click", onClick);
    return () => btn.removeEventListener("click", onClick);
  }, []);
  useEffect(() => {
    document.getElementById("docs-chat-trigger")?.setAttribute("aria-pressed", String(chatOpen));
  }, [chatOpen]);

  const chatMode: ChatProps["mode"] = solo
    ? "solo"
    : size === "phone"
      ? "mobile"
      : desktop
        ? mode
        : "floating";
  const chat = createPortal(
    <Chat
      mode={chatMode}
      onToggleDock={
        solo || !desktop ? undefined : () => setMode(mode === "floating" ? "docked" : "floating")
      }
      onClose={solo ? undefined : () => (desktop ? setMode("closed") : setOverlayOpen(false))}
    />,
    chatHost,
  );

  const panelClass = solo || size === "phone" ? "docs-chat-fullscreen" : "docs-chat-floating";

  return (
    <>
      {chat}
      {createPortal(
        <>
          {panelVisible && <div ref={panelRef} className={panelClass} />}
          <style>{`
            .docs-chat-undocked #docs-chat { display: none !important; }
            @media (min-width: 1280px) {
              .docs-chat-undocked .docs-layout { grid-template-columns: 240px minmax(0, 1fr); }
            }
            .docs-chat-floating {
              position: fixed;
              top: 72px;
              right: 24px;
              width: min(440px, calc(100vw - 32px));
              height: min(760px, calc(100vh - 96px));
              z-index: 1001;
              border: 1px solid rgb(var(--line));
              border-radius: 10px;
              overflow: hidden;
              box-shadow: 0 20px 50px rgba(0,0,0,0.35);
            }
            .docs-chat-fullscreen {
              position: fixed;
              inset: 0;
              z-index: 1001;
            }
          `}</style>
        </>,
        document.body,
      )}
    </>
  );
}

function Root({ aside }: { aside: HTMLElement }) {
  return (
    // www es el host principal de Formmy; el apex formmy.app no presenta certificado TLS
    // (handshake sin peer cert), asi que todo fetch del SDK moria con "Failed to fetch".
    <FormmyProvider publishableKey={PK} baseUrl="https://www.formmy.app">
      <App aside={aside} />
    </FormmyProvider>
  );
}

const el = document.getElementById("docs-chat");
if (el) {
  // La raíz va en un nodo propio: el aside sólo recibe el chat cuando está acoplado
  const rootEl = document.createElement("div");
  document.body.appendChild(rootEl);
  createRoot(rootEl).render(<Root aside={el} />);
}
