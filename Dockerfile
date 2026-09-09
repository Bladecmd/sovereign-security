# Sovereign Security — Production Multi-Stage Containerfile
# Stage 1: Build & Compile
FROM node:22-alpine AS builder

WORKDIR /build

# Install dependencies (reproducible with clean npm install)
COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts

# Copy source code and build configurations
COPY tsconfig.json ./
COPY src/ ./src/

# Compile TypeScript into dist/
RUN npm run build

# Remove development dependencies for lean production artifact
RUN npm prune --production

# Stage 2: Hardened Minimal Runtime
FROM node:22-alpine AS runner

# Install dumb-init for proper PID 1 signal forwarding and graceful shutdown
RUN apk add --no-cache dumb-init

ENV NODE_ENV=production
ENV PORT=4000
ENV DATA_DIR=/data

# Create dedicated non-root group and user with restricted UID/GID
RUN addgroup -g 10001 sovereign && \
    adduser -u 10001 -G sovereign -s /sbin/nologin -D -H sovereign

WORKDIR /app

# Copy production dependencies and compiled artifacts
COPY --chown=sovereign:sovereign package.json ./
COPY --from=builder --chown=sovereign:sovereign /build/node_modules ./node_modules
COPY --from=builder --chown=sovereign:sovereign /build/dist ./dist

# Create persistent data directory for append-only audit ledger with non-root ownership
RUN mkdir -p /data && chown -R sovereign:sovereign /data && chmod 700 /data

# Drop privileges to non-root sovereign user
USER sovereign:sovereign

EXPOSE 4000

# Native health check against /health endpoint
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 4000) + '/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "dist/server/server.js"]
