#!/usr/bin/env bash
# Tessera MVP launcher.
#   ./run.sh            install deps (first run), seed if no DB, start backend :8000 + frontend :5173
#   ./run.sh --reseed   wipe and re-seed the demo database first
#   ./run.sh test       run the backend test suite
#   ./run.sh build      type-check and build the frontend
#   ./run.sh seed       (re)seed the database only
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"
VENV="$BACKEND/.venv"
API_PORT="${API_PORT:-8000}"
UI_PORT="${UI_PORT:-5173}"

pick_python() {
  for p in python3.13 python3.12 python3.11 python3; do
    if command -v "$p" >/dev/null 2>&1; then echo "$p"; return; fi
  done
  echo "Python 3.11+ is required" >&2; exit 1
}

setup_backend() {
  if [ ! -x "$VENV/bin/python" ]; then
    echo "==> creating virtualenv"
    "$(pick_python)" -m venv "$VENV"
  fi
  if [ ! -f "$VENV/.deps-installed" ] || [ "$BACKEND/requirements.txt" -nt "$VENV/.deps-installed" ]; then
    echo "==> installing backend dependencies"
    "$VENV/bin/pip" install -q --upgrade pip
    "$VENV/bin/pip" install -q -r "$BACKEND/requirements.txt"
    touch "$VENV/.deps-installed"
  fi
}

setup_frontend() {
  if [ ! -d "$FRONTEND/node_modules" ]; then
    echo "==> installing frontend dependencies"
    (cd "$FRONTEND" && npm install --no-fund --no-audit)
  fi
}

seed() {
  echo "==> seeding demo data (fictional company: Larkspur Labs)"
  (cd "$BACKEND" && "$VENV/bin/python" -m tessera.seed)
}

case "${1:-}" in
  test)
    setup_backend
    cd "$BACKEND" && exec "$VENV/bin/pytest" -q
    ;;
  build)
    setup_frontend
    cd "$FRONTEND" && exec npm run build
    ;;
  seed)
    setup_backend
    seed
    exit 0
    ;;
esac

setup_backend
setup_frontend
if [ "${1:-}" = "--reseed" ] || [ ! -f "$BACKEND/tessera.db" ]; then
  seed
fi

echo "==> starting API on http://127.0.0.1:$API_PORT"
(cd "$BACKEND" && exec "$VENV/bin/uvicorn" tessera.api.app:app --host 127.0.0.1 --port "$API_PORT") &
API_PID=$!
trap 'echo; echo "==> stopping"; kill $API_PID 2>/dev/null || true' EXIT INT TERM

for _ in $(seq 1 40); do
  curl -sf "http://127.0.0.1:$API_PORT/api/health" >/dev/null 2>&1 && break
  sleep 0.25
done

echo "==> starting UI on http://localhost:$UI_PORT  (Ctrl+C to stop both)"
cd "$FRONTEND"
TESSERA_API="http://127.0.0.1:$API_PORT" npx vite --port "$UI_PORT" --strictPort
