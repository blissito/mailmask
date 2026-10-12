#!/usr/bin/env bash
# Paso previo de la suite del paquete raíz. Lo declara .ghosty/factory.md (setup.script).
#
# `data/` está en .gitignore y better-sqlite3 NO crea el directorio: en un checkout limpio
# no existe y `npm test` falla al abrir ./data/test.db. Es el mismo `mkdir -p data` que hace
# el job `verify` de ci.yml antes de `npm test`.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data
