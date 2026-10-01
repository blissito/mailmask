#!/bin/sh
# Instala (o actualiza) el relay de salida en la caja de Stalwart. Idempotente: se puede
# correr las veces que haga falta; sólo reinicia el servicio si algo cambió.
#
#   sudo OUTBOUND_RELAY_SECRET=<el de Fly> ./install.sh
#
# Sin OUTBOUND_RELAY_SECRET conserva el que ya esté en /etc/mailmask-relay.env.
# La caja no tiene bootstrap reproducible (CLAUDE.md, "La caja no se sabe reconstruir"):
# por eso todo lo del relay vive en el repo y este script lo deja funcionando desde cero,
# incluido Node si la caja no lo trae.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
DEST=/opt/mailmask-relay
ENVF=/etc/mailmask-relay.env
UNIT=/etc/systemd/system/mailmask-outbound-relay.service
SVC_USER=mailmask-relay
NODE_VERSION=${NODE_VERSION:-v20.18.1}

[ "$(id -u)" = 0 ] || { echo "Corre como root" >&2; exit 1; }

# --- Node >= 18 ---
NODE=$(command -v node || true)
if [ -n "$NODE" ] && [ "$("$NODE" -e 'console.log(process.versions.node.split(".")[0] >= 18 ? 1 : 0)')" = 1 ]; then
  echo "Node existente: $NODE ($("$NODE" -v))"
else
  case "$(uname -m)" in
    x86_64) ARCH=x64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo "Arquitectura no soportada: $(uname -m)" >&2; exit 1 ;;
  esac
  if [ -f /etc/alpine-release ]; then
    # Los binarios oficiales son glibc; en Alpine se usa el paquete.
    apk add --no-cache nodejs npm
    NODE=$(command -v node)
  else
    NODE_DIR=/opt/node-$NODE_VERSION
    if [ ! -x "$NODE_DIR/bin/node" ]; then
      TMP=$(mktemp -d)
      curl -fsSL "https://nodejs.org/dist/$NODE_VERSION/node-$NODE_VERSION-linux-$ARCH.tar.xz" -o "$TMP/node.tar.xz"
      mkdir -p "$NODE_DIR"
      tar -xJf "$TMP/node.tar.xz" -C "$NODE_DIR" --strip-components=1
      rm -rf "$TMP"
    fi
    NODE=$NODE_DIR/bin/node
  fi
  echo "Node instalado: $NODE ($("$NODE" -v))"
fi
NPM="$(dirname "$NODE")/npm"
[ -x "$NPM" ] || NPM=$(command -v npm)

# --- Usuario sin privilegios ---
if ! id "$SVC_USER" >/dev/null 2>&1; then
  if command -v useradd >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
  else
    adduser -S -D -H -s /sbin/nologin "$SVC_USER"
  fi
fi

# --- Código y dependencias (sólo si cambiaron) ---
mkdir -p "$DEST"
CHANGED=0
for f in relay.mjs package.json package-lock.json; do
  if ! cmp -s "$HERE/$f" "$DEST/$f"; then cp "$HERE/$f" "$DEST/$f"; CHANGED=1; fi
done
if [ "$CHANGED" = 1 ] || [ ! -d "$DEST/node_modules/smtp-server" ]; then
  (cd "$DEST" && PATH="$(dirname "$NODE"):$PATH" "$NPM" ci --omit=dev --no-audit --no-fund)
  CHANGED=1
fi
chown -R root:root "$DEST"
chmod -R a+rX "$DEST"

# --- Secreto ---
if [ ! -f "$ENVF" ]; then
  umask 027
  cat > "$ENVF" <<EOF
OUTBOUND_RELAY_SECRET=
RELAY_AUTH_USER=stalwart
RELAY_REQUIRE_AUTH=true
RELAY_LISTEN_HOST=127.0.0.1
RELAY_PORT=2525
RELAY_APP_URL=https://www.mailmask.studio/api/internal/outbound
RELAY_TIMEOUT_MS=30000
EOF
  CHANGED=1
fi
if [ -n "${OUTBOUND_RELAY_SECRET:-}" ] && ! grep -qx "OUTBOUND_RELAY_SECRET=$OUTBOUND_RELAY_SECRET" "$ENVF"; then
  TMPF=$(mktemp)
  grep -v '^OUTBOUND_RELAY_SECRET=' "$ENVF" > "$TMPF" || true
  echo "OUTBOUND_RELAY_SECRET=$OUTBOUND_RELAY_SECRET" >> "$TMPF"
  cat "$TMPF" > "$ENVF"
  rm -f "$TMPF"
  CHANGED=1
fi
chown root:"$SVC_USER" "$ENVF"
chmod 640 "$ENVF"
grep -q '^OUTBOUND_RELAY_SECRET=.\+' "$ENVF" || { echo "Falta OUTBOUND_RELAY_SECRET en $ENVF" >&2; exit 1; }

# --- Unidad systemd ---
TMPU=$(mktemp)
sed "s#@NODE@#$NODE#" "$HERE/mailmask-outbound-relay.service" > "$TMPU"
if ! cmp -s "$TMPU" "$UNIT"; then cp "$TMPU" "$UNIT"; CHANGED=1; fi
rm -f "$TMPU"
systemctl daemon-reload
systemctl enable mailmask-outbound-relay >/dev/null
if [ "$CHANGED" = 1 ] || ! systemctl is-active --quiet mailmask-outbound-relay; then
  systemctl restart mailmask-outbound-relay
fi

# --- Comprobación ---
i=0
PROBE="require('net').connect(2525,'127.0.0.1').on('connect',()=>process.exit(0)).on('error',()=>process.exit(1))"
until "$NODE" -e "$PROBE" 2>/dev/null; do
  i=$((i+1)); [ $i -ge 10 ] && { echo "El relay no escucha en 127.0.0.1:2525" >&2; exit 1; }; sleep 1
done
systemctl --no-pager --lines=5 status mailmask-outbound-relay || true
echo "Listo. Prueba: printf 'LHLO x\\r\\nQUIT\\r\\n' | nc 127.0.0.1 2525"
