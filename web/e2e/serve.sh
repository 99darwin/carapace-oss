#!/usr/bin/env bash
# Serve web/dist from a freshly migrated and seeded server on a throwaway
# SQLite database. Playwright starts this; run `npm run build` first.
set -euo pipefail

port="${E2E_PORT:-8765}"
web_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_dir="$(cd "$web_dir/.." && pwd)"
tmp_dir="$(mktemp -d)"
server_pid=""

cleanup() {
  if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || true; fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

export CARAPACE_MODE=dev
export CARAPACE_DATABASE_URL="sqlite+aiosqlite:///$tmp_dir/e2e.db"
export CARAPACE_PUBLIC_URL="http://127.0.0.1:$port"
export CARAPACE_WEB_DIR="$web_dir/dist"

cd "$repo_dir"
uv run --package carapace-server alembic -c server/alembic.ini upgrade head
uv run --package carapace-server python web/e2e/seed.py "$CARAPACE_DATABASE_URL"
uv run --package carapace-server uvicorn carapace_server.app:create_app \
  --factory --host 127.0.0.1 --port "$port" &
server_pid=$!
wait "$server_pid"
