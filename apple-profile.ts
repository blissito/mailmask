// Perfil .mobileconfig para configurar Apple Mail de un clic.
//
// Apple Mail **no soporta** los dos estándares abiertos de autodescubrimiento —ni
// SRV (RFC 6186) ni el autoconfig de Mozilla— así que un perfil no es el premio de
// consolación: es el único camino automático que existe para macOS e iOS.
//
// Y tiene una ventaja que los otros no: **no necesita ningún DNS del cliente**. El
// archivo lo servimos nosotros, así que funciona con el dominio de cualquiera sin
// pedirle que agregue registros a su zona.

/** Host público del servidor IMAP. Se configura para poder moverlo sin tocar código. */
export const IMAP_HOST = process.env.IMAP_PUBLIC_HOST ?? "imap.mailmask.studio";

export interface DatosPerfil {
  /** Dirección completa del buzón, que es también el usuario. */
  direccion: string;
  /** Nombre que verá el destinatario. */
  nombre?: string;
  /** Dominio, para nombrar el perfil. */
  dominio: string;
  /**
   * Servidor de salida. Se pasa aparte porque hoy no es el mismo host: el 465 de
   * nuestro servidor no está enrutado, así que un perfil que lo anuncie dejaría al
   * usuario sin poder responder. Sin este dato el perfil sale sólo de lectura.
   */
  salida?: { host: string; puerto: number; usuario?: string };
}

/** Escapa para XML. Un apóstrofo en un nombre rompería el plist entero. */
function esc(s: string): string {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

/**
 * UUID estable derivado de la dirección: si el usuario descarga el perfil dos
 * veces, macOS lo reconoce como el MISMO y lo reemplaza en vez de crear una
 * segunda cuenta duplicada.
 */
function uuidEstable(semilla: string): string {
  let h1 = 0x811c9dc5, h2 = 0x01000193;
  for (let i = 0; i < semilla.length; i++) {
    h1 = Math.imul(h1 ^ semilla.charCodeAt(i), 16777619) >>> 0;
    h2 = Math.imul(h2 + semilla.charCodeAt(i), 2246822519) >>> 0;
  }
  const hex = (n: number) => n.toString(16).padStart(8, "0");
  const s = (hex(h1) + hex(h2) + hex(h1 ^ h2) + hex((h1 + h2) >>> 0)).slice(0, 32);
  return `${s.slice(0,8)}-${s.slice(8,12)}-${s.slice(12,16)}-${s.slice(16,20)}-${s.slice(20,32)}`.toUpperCase();
}

export function generarPerfilApple(d: DatosPerfil): string {
  const uuidPerfil = uuidEstable(`perfil:${d.direccion}`);
  const uuidCuenta = uuidEstable(`cuenta:${d.direccion}`);
  const nombre = d.nombre?.trim() || d.direccion.split("@")[0];

  // Apple exige host y puerto de salida aunque la cuenta sea de sólo lectura. Si no
  // tenemos servidor de salida se repite el de entrada: el perfil se instala igual
  // y Mail avisa al intentar enviar, en vez de fallar la instalación completa.
  const salidaHost = d.salida?.host ?? IMAP_HOST;
  const salidaPuerto = d.salida?.puerto ?? 465;
  const salidaUsuario = d.salida?.usuario ?? d.direccion;

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadDisplayName</key><string>Correo ${esc(d.dominio)}</string>
  <key>PayloadDescription</key><string>Configura ${esc(d.direccion)} en Mail</string>
  <key>PayloadOrganization</key><string>MailMask</string>
  <key>PayloadIdentifier</key><string>studio.mailmask.mail.${esc(d.direccion)}</string>
  <key>PayloadUUID</key><string>${uuidPerfil}</string>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.mail.managed</string>
      <key>PayloadIdentifier</key><string>studio.mailmask.mail.${esc(d.direccion)}.cuenta</string>
      <key>PayloadUUID</key><string>${uuidCuenta}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadDisplayName</key><string>${esc(d.direccion)}</string>

      <key>EmailAccountType</key><string>EmailTypeIMAP</string>
      <key>EmailAccountName</key><string>${esc(nombre)}</string>
      <key>EmailAccountDescription</key><string>${esc(d.direccion)}</string>
      <key>EmailAddress</key><string>${esc(d.direccion)}</string>

      <key>IncomingMailServerHostName</key><string>${esc(IMAP_HOST)}</string>
      <key>IncomingMailServerPortNumber</key><integer>993</integer>
      <key>IncomingMailServerUseSSL</key><true/>
      <key>IncomingMailServerAuthentication</key><string>EmailAuthPassword</string>
      <key>IncomingMailServerUsername</key><string>${esc(d.direccion)}</string>

      <key>OutgoingMailServerHostName</key><string>${esc(salidaHost)}</string>
      <key>OutgoingMailServerPortNumber</key><integer>${salidaPuerto}</integer>
      <key>OutgoingMailServerUseSSL</key><true/>
      <key>OutgoingMailServerAuthentication</key><string>EmailAuthPassword</string>
      <key>OutgoingMailServerUsername</key><string>${esc(salidaUsuario)}</string>
      <key>OutgoingPasswordSameAsIncoming</key><${d.salida?.usuario ? "false" : "true"}/>

      <key>PreventMove</key><false/>
      <key>PreventAppSheet</key><false/>
      <key>SMIMEEnabled</key><false/>
    </dict>
  </array>
</dict>
</plist>
`;
}

/** Nombre del archivo que verá el usuario al descargarlo. */
export function nombreArchivoPerfil(direccion: string): string {
  return `${direccion.replace(/[^a-zA-Z0-9._-]/g, "_")}.mobileconfig`;
}
