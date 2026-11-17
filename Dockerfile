# syntax=docker/dockerfile:1

# ---- Build: install everything, build the web client, then drop dev dependencies ----
FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build && npm prune --omit=dev

# ---- Runtime ----
FROM node:24-alpine
RUN apk add --no-cache su-exec
WORKDIR /app
ENV NODE_ENV=production \
    PORT=8790 \
    DATABASE_PATH=/app/data/wled-presets.sqlite \
    NODE_NO_WARNINGS=1

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY shared ./shared
COPY server/src ./server/src
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

VOLUME /app/data
EXPOSE 8790
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${PORT}/api/health" >/dev/null || exit 1

ENTRYPOINT ["entrypoint.sh"]
CMD ["node", "server/src/index.ts"]
