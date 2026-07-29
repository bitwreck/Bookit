# ── Build stage (install prod deps only) ───────────────────
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

# ── Runtime stage ───────────────────────────────────────────
FROM node:20-alpine
WORKDIR /app

# Non-root user for security
RUN addgroup -S booking && adduser -S booking -G booking

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Remove dev/docker files we don't need at runtime
RUN rm -f Dockerfile docker-compose.yml .dockerignore

RUN chown -R booking:booking /app
USER booking

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/resources || exit 1

CMD ["node", "server.js"]
