# StubForge Mobile - Configurable stub server with built-in OAuth2 for mobile development
FROM node:18-alpine
# Note: Alpine base supports linux/amd64 & linux/arm64 official variants enabling multi-platform builds via buildx.

WORKDIR /app

# Install openssl for RSA key generation
RUN apk add --no-cache openssl

# Copy package metadata and install production deps first (better layer caching across arch builds)
COPY package*.json ./
RUN npm install --production

# Copy source code (excluding stubs and keys directories)
COPY server.js ./
COPY config/ ./config/
COPY scripts/ ./scripts/
COPY docs/ ./docs/
COPY postman/ ./postman/
COPY *.md ./
COPY *.json ./
COPY start.sh ./

# Copy built-in stubs and keys as defaults (kept separate so they can be overlaid by volumes)
COPY stubs/ ./stubs-default/
COPY keys/ ./keys-default/

# Create directories for external volumes (ensures existence when empty volumes are mounted)
RUN mkdir -p /app/stubs /app/keys

# Entrypoint script creates keys if missing then starts server
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Define volumes for external stubs and keys
# Declare mount points used for customization
VOLUME ["/app/stubs", "/app/keys"]

EXPOSE 3000
ENV PORT=3000

CMD ["docker-entrypoint.sh"]
