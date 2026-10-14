// Ficha de una dirección: la de las cajas de Ghosty (`@ghostystudio/boxes`), con el robot
// del tema de MailMask al centro. `app.js` es JS a secas, así que esto se carga con
// `import("/js/direccion.js")` la primera vez que se abre una dirección y sólo recibe datos
// ya armados: aquí no se hace ningún fetch.
import { createRoot, type Root } from "react-dom/client";
import { BoxDetail, lookFor, type BoxDetailData, type BoxTone } from "@ghostystudio/boxes/react";

export interface AddressLog {
  key: string;
  outbound: boolean;
  who: string;
  subject: string;
  status: string;
  time: string;
}

export interface AddressAction {
  label: string;
  href?: string;
  onClick?: () => void;
}

export interface AddressData {
  address: string;
  domain: string;
  enabled: boolean;
  catchAll: boolean;
  destinations: string[];
  mailbox: boolean;
  mailboxReadOnly: boolean;
  forwardCount: number;
  lastFrom?: string;
  lastAgo?: string;
  logs: AddressLog[] | null; // null = cargando
  logsNote?: string;
  actions: AddressAction[];
}

let root: Root | null = null;
let host: HTMLDivElement | null = null;

export function closeAddress() {
  root?.unmount();
  host?.remove();
  root = null;
  host = null;
}

/** Abre la ficha o, si ya está abierta, la repinta con los datos nuevos (p. ej. al llegar el historial). */
export function openAddress(d: AddressData) {
  if (!host) {
    host = document.createElement("div");
    document.body.appendChild(host);
    root = createRoot(host);
  }
  const state: { label: string; tone: BoxTone } = !d.enabled
    ? { label: "inactiva", tone: "sleep" }
    : d.logs?.length
      ? { label: "recibiendo", tone: "work" }
      : { label: "activa", tone: "calm" };

  const data: BoxDetailData = {
    name: d.address,
    subtitle: d.domain,
    head: {
      // Del look sólo la forma y la semilla: el color lo pone el tema (lo explícito le gana).
      shape: lookFor(d.address).shape,
      seed: lookFor(d.address).seed,
      theme: "mailmaskGreen",
      state: d.enabled ? (d.logs?.length ? "happy" : "idle") : "sleeping",
    },
    title: d.address,
    chips: [d.catchAll ? "Comodín" : "Dirección", ...(d.mailbox ? [d.mailboxReadOnly ? "Buzón · sólo lectura" : "Buzón"] : [])],
    state,
    hint: d.catchAll
      ? "Recibe todo lo que no coincide con otra dirección del dominio."
      : d.enabled
        ? undefined
        : "Inactiva: el correo que llega aquí se descarta.",
    rows: [
      { label: "Reenvía a", value: d.destinations.length ? d.destinations.join(", ") : "—" },
      { label: "Reenviados", value: `${d.forwardCount.toLocaleString("es-MX")} en total` },
      ...(d.lastFrom ? [{ label: "Último correo", value: `${d.lastFrom}${d.lastAgo ? ` · ${d.lastAgo}` : ""}` }] : []),
    ],
    chatsTitle: d.logs === null ? "Cargando correos…" : d.logs.length ? "Últimos correos" : d.logsNote ?? "Todavía no hay correos registrados.",
    chats: (d.logs ?? []).map((l) => ({
      key: l.key,
      heading: (
        <>
          {l.outbound ? "↑ " : "↓ "}
          <b>{l.who}</b>
        </>
      ),
      details: `${l.subject || "(sin asunto)"} · ${l.status}`,
      time: l.time,
    })),
  };

  root!.render(
    <BoxDetail data={data} light onClose={closeAddress} closeLabel="Cerrar">
      {d.actions.length > 0 && (
        <div className="card-repair">
          <div className="repair-actions">
            {d.actions.map((a) => (
              <button key={a.label} type="button" onClick={a.onClick ?? (() => { if (a.href) location.href = a.href; })}>
                {a.label}
              </button>
            ))}
          </div>
        </div>
      )}
    </BoxDetail>,
  );
}
