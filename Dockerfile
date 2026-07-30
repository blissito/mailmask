# syntax=docker/dockerfile:1
FROM node:20-alpine

WORKDIR /app

ENV NODE_ENV=production \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false

# Dependencies first: this layer is reused on every deploy that does not touch
# package-lock.json, which is the common case. The BuildKit cache mount keeps npm's
# download cache between builds, so even a lock change resolves from local disk.
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --omit=dev --no-audit --no-fund

# Application source last — it changes on every deploy, so nothing cacheable follows.
COPY . .

# Mount point for the SQLite volume, created in the image so the first boot after a
# fresh volume attach does not have to mkdir it.
RUN mkdir -p data

EXPOSE 8000

CMD ["node_modules/.bin/tsx", "main.ts"]
