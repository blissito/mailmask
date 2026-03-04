import React, { useState, useRef, useEffect } from "react";
import { createRoot, createPortal } from "react-dom/client";
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

function Chat() {
  const [input, setInput] = useState("");
  const bottomRef = useRef<HTMLDivElement>(null);
  const prevCountRef = useRef(0);

  console.log("[docs-chat] Chat component mounting, AGENT_ID:", AGENT_ID, "PK:", PK.slice(0, 20) + "...");

  const { messages, sendMessage, status, reset, error } = useFormmyChat({
    agentId: AGENT_ID,
    onFinish: () => {
      console.log("[docs-chat] onFinish called — message complete");
      playBeep();
    },
    onError: (err: any) => {
      console.error("[docs-chat] onError callback:", err);
    },
  });

  const isLoading = status === "streaming" || status === "submitted";

  // Log status and error changes
  useEffect(() => {
    console.log("[docs-chat] status:", status, "| messages:", messages.length, "| error:", error);
  }, [status, messages.length, error]);

  // Auto-scroll
  useEffect(() => {
    if (messages.length > 0) {
      bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages, status]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isLoading) return;
    const msg = input.trim();
    setInput("");
    console.log("[docs-chat] Sending message:", msg);
    try {
      await sendMessage(msg);
      console.log("[docs-chat] sendMessage resolved");
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
        background: "#09090b",
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: "12px 16px",
          borderBottom: "1px solid #27272a",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexShrink: 0,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div
            style={{
              width: 8,
              height: 8,
              borderRadius: "50%",
              background: "#22c55e",
            }}
          />
          <span style={{ fontWeight: 600, fontSize: 16, color: "#fafafa" }}>
            Asistente MailMask
          </span>
        </div>
        <button
          onClick={reset}
          style={{
            background: "none",
            border: "none",
            color: "#71717a",
            cursor: "pointer",
            fontSize: 12,
            padding: "4px 8px",
          }}
          title="Nueva conversaci&oacute;n"
        >
          Limpiar
        </button>
      </div>

      {/* Messages */}
      <div
        style={{
          flex: 1,
          overflowY: "auto",
          padding: 16,
          display: "flex",
          flexDirection: "column",
          gap: 12,
        }}
      >
        {messages.length === 0 && !isLoading && (
          <div
            style={{
              textAlign: "center",
              color: "#52525b",
              fontSize: 15,
              marginTop: 40,
            }}
          >
            <p style={{ fontSize: 24, marginBottom: 8 }}>
              {/* mask emoji */}
              &#129409;
            </p>
            <p>Pregunta sobre la API, SDK o configuraci&oacute;n de MailMask</p>
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                gap: 6,
                justifyContent: "center",
                marginTop: 16,
              }}
            >
              {[
                "C\u00f3mo creo un alias?",
                "Ejemplo con Node.js",
                "Configurar SMTP",
              ].map((q) => (
                <button
                  key={q}
                  onClick={() => {
                    console.log("[docs-chat] Suggestion clicked:", q);
                    sendMessage(q);
                  }}
                  style={{
                    background: "#18181b",
                    border: "1px solid #27272a",
                    borderRadius: 8,
                    padding: "6px 12px",
                    color: "#a1a1aa",
                    fontSize: 14,
                    cursor: "pointer",
                  }}
                >
                  {q}
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
                  maxWidth: "90%",
                  padding: isUser ? "8px 14px" : "0",
                  borderRadius: 12,
                  fontSize: 15,
                  lineHeight: 1.6,
                  ...(isUser
                    ? {
                        background:
                          "linear-gradient(135deg, rgb(var(--mask-600)), rgb(var(--mask-500)))",
                        color: "#fff",
                      }
                    : { color: "#d4d4d8" }),
                }}
              >
                {isUser ? (
                  text
                ) : (
                  <div className="streamdown-wrap">
                    <Streamdown
                      plugins={{ "code-highlighter": codePlugin }}
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
                  background: "#52525b",
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
              background: "#1c1917",
              borderRadius: 8,
            }}
          >
            Error: {error.message}
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <form
        onSubmit={handleSubmit}
        style={{
          padding: 12,
          borderTop: "1px solid #27272a",
          display: "flex",
          gap: 8,
          flexShrink: 0,
        }}
      >
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Escribe tu pregunta..."
          disabled={isLoading}
          style={{
            flex: 1,
            background: "#18181b",
            border: "1px solid #27272a",
            borderRadius: 10,
            padding: "10px 14px",
            color: "#fafafa",
            fontSize: 15,
            outline: "none",
          }}
          onFocus={(e) =>
            (e.currentTarget.style.borderColor = "rgb(var(--mask-500))")
          }
          onBlur={(e) => (e.currentTarget.style.borderColor = "#27272a")}
        />
        <button
          type="submit"
          disabled={isLoading || !input.trim()}
          style={{
            background: "rgb(var(--mask-500))",
            border: "none",
            borderRadius: 10,
            padding: "0 16px",
            color: "#fff",
            fontSize: 15,
            fontWeight: 600,
            cursor: isLoading || !input.trim() ? "not-allowed" : "pointer",
            opacity: isLoading || !input.trim() ? 0.5 : 1,
          }}
        >
          Enviar
        </button>
      </form>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 0.3; transform: scale(0.8); }
          50% { opacity: 1; transform: scale(1); }
        }
        .streamdown-wrap pre {
          background: #18181b !important;
          border: 1px solid #27272a;
          border-radius: 8px;
          overflow-x: auto;
          font-size: 13px;
          margin: 8px 0;
          padding: 14px 16px;
        }
        .streamdown-wrap code {
          font-size: 13px;
        }
        .streamdown-wrap p { margin: 6px 0; }
        .streamdown-wrap ul, .streamdown-wrap ol { margin: 6px 0; padding-left: 20px; }
        .streamdown-wrap a { color: rgb(var(--mask-400)); text-decoration: underline; }
        .streamdown-wrap h1, .streamdown-wrap h2, .streamdown-wrap h3 {
          color: #fafafa;
          margin: 12px 0 6px;
          font-weight: 600;
        }
        .streamdown-wrap code:not(pre code) {
          background: #27272a;
          padding: 2px 6px;
          border-radius: 4px;
          font-size: 13px;
          color: rgb(var(--mask-400));
        }
      `}</style>
    </div>
  );
}

// Mobile floating button + fullscreen panel
function MobileChat() {
  const [open, setOpen] = useState(false);

  return (
    <>
      {!open && (
        <button
          onClick={() => setOpen(true)}
          style={{
            position: "fixed",
            bottom: 20,
            right: 20,
            width: 52,
            height: 52,
            borderRadius: "50%",
            background: "rgb(var(--mask-500))",
            border: "none",
            color: "#fff",
            fontSize: 22,
            cursor: "pointer",
            boxShadow: "0 4px 20px rgba(0,0,0,0.4)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
          }}
          title="Abrir asistente"
        >
          <svg
            width="22"
            height="22"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
          </svg>
        </button>
      )}

      {open && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 1001,
            background: "#09090b",
            display: "flex",
            flexDirection: "column",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "flex-end",
              padding: "8px 12px 0",
              flexShrink: 0,
            }}
          >
            <button
              onClick={() => setOpen(false)}
              style={{
                background: "none",
                border: "none",
                color: "#71717a",
                fontSize: 22,
                cursor: "pointer",
                padding: 4,
              }}
            >
              &times;
            </button>
          </div>
          <div style={{ flex: 1, minHeight: 0 }}>
            <Chat />
          </div>
        </div>
      )}
    </>
  );
}

function App() {
  const [isMobile, setIsMobile] = useState(false);

  useEffect(() => {
    const check = () => setIsMobile(window.innerWidth < 1024);
    check();
    window.addEventListener("resize", check);
    return () => window.removeEventListener("resize", check);
  }, []);

  // Desktop: render in the grid panel; Mobile: portal to body for floating button
  if (!isMobile) {
    return <Chat />;
  }
  return createPortal(<MobileChat />, document.body);
}

function Root() {
  return (
    <FormmyProvider publishableKey={PK} baseUrl="https://formmy.app">
      <App />
    </FormmyProvider>
  );
}

const el = document.getElementById("docs-chat");
console.log("[docs-chat] Init — container element:", el ? "found" : "NOT FOUND");
if (el) {
  console.log("[docs-chat] Mounting React app...");
  createRoot(el).render(<Root />);
} else {
  console.warn("[docs-chat] #docs-chat element not found in DOM — chat will not render");
}
