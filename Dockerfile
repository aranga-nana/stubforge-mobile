# Minimal Docker image for oauth2-stubkit-mobile
FROM node:18-alpine

WORKDIR /app

# Install openssl for RSA key generation
RUN apk add --no-cache openssl

# Copy package metadata and install production deps
COPY package*.json ./
RUN npm install --production

# Copy rest of source
COPY . .

# Entrypoint script creates keys if missing then starts server
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 3000
ENV PORT=3000

CMD ["docker-entrypoint.sh"]
