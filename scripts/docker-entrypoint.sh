#!/bin/sh
set -e

# Copy default stubs if the stubs directory is empty
if [ ! "$(ls -A /app/stubs 2>/dev/null)" ]; then
  echo "[entrypoint] No custom stubs found, copying built-in samples..."
  cp -r /app/stubs-default/* /app/stubs/
fi

# Copy default keys if missing, or generate new ones if keys directory is empty
if [ ! "$(ls -A /app/keys 2>/dev/null)" ]; then
  echo "[entrypoint] No custom keys found..."
  if [ -f /app/keys-default/private.pem ] && [ -f /app/keys-default/public.pem ]; then
    echo "[entrypoint] Copying built-in development keys..."
    cp /app/keys-default/* /app/keys/
  else
    echo "[entrypoint] Generating new RSA key pair (development only)..."
    openssl genrsa -out /app/keys/private.pem 2048 >/dev/null 2>&1
    openssl rsa -in /app/keys/private.pem -pubout -out /app/keys/public.pem >/dev/null 2>&1
  fi
elif [ ! -f /app/keys/private.pem ] || [ ! -f /app/keys/public.pem ]; then
  echo "[entrypoint] Incomplete key pair found, generating new RSA key pair..."
  openssl genrsa -out /app/keys/private.pem 2048 >/dev/null 2>&1
  openssl rsa -in /app/keys/private.pem -pubout -out /app/keys/public.pem >/dev/null 2>&1
fi

echo "[entrypoint] Starting StubForge Mobile server..."
exec node server.js
