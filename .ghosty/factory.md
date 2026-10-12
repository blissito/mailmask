---
setup:
  services: []
  env: {}
  script: .ghosty/prepare.sh
---

# Entorno de pruebas (paquete raíz)

Lo que la fábrica necesita para dejar una caja limpia lista para la suite del root.
Este `setup:` cubre SÓLO el paquete raíz (el job `verify` de `ci.yml`); `cli/` y `sdk/`
son paquetes aparte, con su propio `npm ci`, y no los prepara este archivo.

## El bloque `setup:`

- **`services: []`** — sin servicios externos: la suite corre sobre SQLite en archivo
  (`better-sqlite3`). No hay Postgres ni Redis que arrancar.
- **`env: {}`** — a propósito vacío. Las variables de PRUEBA las inyecta el propio script
  `test` de `package.json` (`DATABASE_PATH=./data/test.db`, `JWT_SECRET=test-secret-key`,
  `MP_ACCESS_TOKEN`/`MP_WEBHOOK_SECRET`=`test`, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`=`test`,
  `AWS_ENDPOINT_URL=http://localhost:1`). No se repiten aquí para que no se desfasen en
  silencio el día que cambie `package.json`: el script manda. Sólo si alguna prueba pide una
  variable que `npm test` NO define, ése es el caso para ponerla en este `env:`.
- **`script: .ghosty/prepare.sh`** — paso previo. `data/` está en `.gitignore` y
  `better-sqlite3` no crea el directorio, así que en un checkout limpio no existe y la suite
  truena al abrir `./data/test.db`. El script hace `mkdir -p data`: es exactamente el
  `mkdir -p data` del job `verify` de `ci.yml`.

## Cómo se reproduce una corrida limpia

En una caja de trabajo, tras el checkout y `npm ci`:

```sh
set -a; . .env.test; set +a   # el .env.test sale de este setup: (vacío: lo llena `npm test`)
bash .ghosty/prepare.sh       # deja `data/`
rm -f data/test.db && npm test
```

Entorno: **Node 22**, el mismo de CI y de prod (`node:22-alpine`). `@types/node` va en `^26`
y describe APIs que NO existen en 22, así que typecheck verde no garantiza que algo corra aquí.

Fuente: script `test` de `package.json` y job `verify` de `.github/workflows/ci.yml`
(ficha: `docs/agents/dependencias-ci.md`).
