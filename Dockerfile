# StubForge Mobile - Configurable stub server with built-in OAuth2 for mobile development
FROM node:18-alpine

WORKDIR /app

# Install openssl for RSA key generation
RUN apk add --no-cache openssl

# Copy package metadata and install production deps
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

# Copy built-in stubs and keys as defaults
COPY stubs/ ./stubs-default/
COPY keys/ ./keys-default/

# Create directories for external volumes
RUN mkdir -p /app/stubs /app/keys

# Entrypoint script creates keys if missing then starts server
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Define volumes for external stubs and keys
VOLUME ["/app/stubs", "/app/keys"]

EXPOSE 3000
ENV PORT=3000

CMD ["docker-entrypoint.sh"]
