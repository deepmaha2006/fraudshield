# syntax=docker/dockerfile:1
# FraudShield SOC — production image.
# Pin the base image by digest before release:
#   docker pull node:24.16.0-bookworm-slim && docker inspect --format '{{index .RepoDigests 0}}' node:24.16.0-bookworm-slim
# then replace both FROM lines with node:24.16.0-bookworm-slim@sha256:<digest>.

# ---- build: compile the native sqlite3 module, install production deps only
FROM node:24.16.0-bookworm-slim AS build
WORKDIR /app
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ \
 && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
# No dependency lifecycle scripts except the one explicitly reviewed (sqlite3 native build).
RUN npm ci --omit=dev --ignore-scripts && npm rebuild sqlite3 && npm cache clean --force
COPY . .
RUN rm -rf tests eslint.config.js .env .env.* data backups public/uploads

# ---- runtime: no compilers, no npm cache, non-root, read-only code
FROM node:24.16.0-bookworm-slim
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    DB_FILE=/data/fraudshield.db \
    UPLOAD_DIR=/data/uploads
WORKDIR /app
# Apply Debian security updates (the base image lags behind fixes), then remove the
# package managers: the running service never needs npm/npx/corepack, and their
# bundled dependencies (tar, undici, sigstore, …) are pure attack surface.
RUN apt-get update \
 && apt-get -y upgrade --no-install-recommends \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
           /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack
COPY --from=build --chown=root:root /app /app
RUN mkdir -p /data/uploads && chown -R node:node /data && chmod 700 /data
USER node
VOLUME ["/data"]
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.js"]
