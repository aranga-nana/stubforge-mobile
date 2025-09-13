#!/bin/sh
set -e

if [ ! -f keys/private.pem ] || [ ! -f keys/public.pem ]; then
  echo "[entrypoint] Generating RSA key pair (development only)"
  mkdir -p keys
  openssl genrsa -out keys/private.pem 2048 >/dev/null 2>&1
  openssl rsa -in keys/private.pem -pubout -out keys/public.pem >/dev/null 2>&1
fi

exec node server.js
