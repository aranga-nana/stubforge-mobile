#!/usr/bin/env bash
set -euo pipefail

IMAGE_BASE="aranga/stubforge-mobile"
VERSION="${1:-}" # allow passing version, otherwise derive from package.json

if [[ -z "$VERSION" ]]; then
  if command -v jq >/dev/null 2>&1; then
    VERSION=$(jq -r '.version' package.json)
  else
    VERSION=$(grep '"version"' package.json | head -1 | sed -E 's/.*"version" *: *"([^"]+)".*/\1/')
  fi
fi

if [[ -z "$VERSION" ]]; then
  echo "Could not determine version" >&2
  exit 1
fi

echo "Building multi-platform image for version: $VERSION"

# Ensure a builder exists
if ! docker buildx inspect sf-builder >/dev/null 2>&1; then
  docker buildx create --name sf-builder --use
else
  docker buildx use sf-builder
fi

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ${IMAGE_BASE}:$VERSION \
  -t ${IMAGE_BASE}:latest \
  --push .

echo "Pushed: ${IMAGE_BASE}:$VERSION and :latest"
