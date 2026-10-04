#!/usr/bin/env bash
# Opera la caja de Stalwart (EasyBits, host `ovh`) a través de la API de sandbox-host.
#   scripts/caja.sh exec '<comando>'          corre el comando como root dentro de la caja
#   scripts/caja.sh put <local> <remoto>      sube un archivo (base64, conserva bytes)
#
# Mismo patrón que ~/ghosty-studio/scripts/en_la_caja.sh: necesita el alias `ovh` en
# ~/.ssh/config; el token vive en /etc/sandbox-host/.env del host y nunca sale de ahí.
# La caja no tiene SSH propio: todo pasa por `files/write` y `exec`.
set -euo pipefail
SID=${CAJA_SID:-sb_4c48dee1-819c-4481-99b0-d08b4f387e83}
RUN="caja-$$"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

api() { # api <ruta> <archivo-json>
  scp -q "$2" "ovh:/tmp/$RUN.json"
  ssh ovh "T=\$(grep -oP '^SANDBOX_HOST_TOKEN=\K.*' /etc/sandbox-host/.env); curl -s -m 600 -H \"Authorization: Bearer \$T\" -H 'Content-Type: application/json' -X POST http://127.0.0.1:8080/v1/sandbox/$SID/$1 --data-binary @/tmp/$RUN.json; rm -f /tmp/$RUN.json"
}

case "${1:-}" in
  exec)
    python3 -c 'import json,sys;print(json.dumps({"command":sys.argv[1]}))' "$2" > "$TMP/cmd.json"
    api exec "$TMP/cmd.json" | python3 -c '
import sys, json
d = json.load(sys.stdin)
sys.stdout.write(d.get("stdout", "")); sys.stderr.write(d.get("stderr", ""))
sys.exit(d.get("exitCode", d.get("code", 0)) or 0)'
    ;;
  put)
    python3 -c 'import base64,json,sys;print(json.dumps({"path":sys.argv[2],"content":base64.b64encode(open(sys.argv[1],"rb").read()).decode(),"encoding":"base64"}))' "$2" "$3" > "$TMP/put.json"
    api files/write "$TMP/put.json" >/dev/null
    ;;
  *) echo "uso: $0 exec '<cmd>' | put <local> <remoto>" >&2; exit 2 ;;
esac
