#!/usr/bin/env bash
# Simple launcher for the stub server.
# Usage:
#   ./start.sh                # install (if needed) then start
#   ./start.sh --watch         # enable rule hot reload (WATCH_RULES=1)
#   ./start.sh --dev           # use nodemon (auto-restart on code change)
#   PORT=4000 ./start.sh --watch
#
# Options can be combined: ./start.sh --dev --watch
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

WATCH=0
DEV=0
for arg in "$@"; do
  case "$arg" in
    --watch) WATCH=1 ;;
    --dev) DEV=1 ;;
    *) echo "Unknown option: $arg" >&2; exit 1 ;;
  esac
done

if [ ! -d node_modules ]; then
  echo "[start.sh] node_modules missing -> running npm install"
  npm install
fi

if [ "$WATCH" = 1 ]; then
  export WATCH_RULES=1
  echo "[start.sh] WATCH_RULES=1 enabled"
fi

CMD=("node" "server.js")
if [ "$DEV" = 1 ]; then
  if npx --yes nodemon -v >/dev/null 2>&1; then
    CMD=("npx" "nodemon" "server.js")
    echo "[start.sh] Using nodemon for auto-restart"
  else
    echo "[start.sh] nodemon not installed; falling back to node"
  fi
fi

echo "[start.sh] Starting server (PORT=${PORT:-3000})"
exec "${CMD[@]}"
