#!/usr/bin/env bash
# Tessera MVP launcher.
#   ./run.sh            build the Go server, install UI deps (first run), seed if no DB, start API :8000 + UI :5173
#   ./run.sh --reseed   wipe and re-seed the demo database first
#   ./run.sh test       go vet + the Go test suite (includes the API parity replay)
#   ./run.sh build      build the Go server and type-check/build the frontend
#   ./run.sh seed       (re)seed the database only
#   ./run.sh bench      Go benchmarks + end-to-end latency/startup/memory of the server
#                       (set PYTHON=… PY_BACKEND=… to also measure a Python backend checkout)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
SERVER="$ROOT/server"
FRONTEND="$ROOT/frontend"
BIN="$SERVER/bin/tessera"
DB="${TESSERA_DB:-$SERVER/tessera.db}"
API_PORT="${API_PORT:-8000}"
UI_PORT="${UI_PORT:-5173}"
export UI_PORT
# read policies from disk so edits apply on the next request (the binary also embeds copies)
export TESSERA_POLICY_DIR="${TESSERA_POLICY_DIR:-$SERVER/policies}"

pick_go() {
  if command -v go >/dev/null 2>&1; then command -v go; return; fi
  for p in /opt/homebrew/bin/go /usr/local/go/bin/go; do
    if [ -x "$p" ]; then echo "$p"; return; fi
  done
  echo "Go is required (see the go directive in server/go.mod)" >&2; exit 1
}
GO="$(pick_go)"

build_server() {
  # rebuild when any Go source, embedded file or go.mod/go.sum is newer than the binary
  if [ ! -x "$BIN" ] || [ -n "$(find "$SERVER" -newer "$BIN" \( -name '*.go' -o -name '*.yaml' -o -name '*.json' -o -name '*.html' -o -name 'go.mod' -o -name 'go.sum' \) -not -path '*/testdata/*' -print -quit)" ]; then
    echo "==> building Go server"
    (cd "$SERVER" && "$GO" build -trimpath -o "$BIN" ./cmd/tessera)
  fi
}

setup_frontend() {
  if [ ! -d "$FRONTEND/node_modules" ]; then
    echo "==> installing frontend dependencies"
    (cd "$FRONTEND" && npm install --no-fund --no-audit)
  fi
}

seed() {
  "$BIN" seed -db "$DB"
}

case "${1:-}" in
  test)
    cd "$SERVER"
    "$GO" vet ./...
    exec "$GO" test ./...
    ;;
  build)
    build_server
    setup_frontend
    cd "$FRONTEND" && exec npm run build
    ;;
  seed)
    build_server
    seed
    exit 0
    ;;
  bench)
    build_server
    cd "$SERVER"
    echo "==> Go benchmarks (graph and effective permissions)"
    "$GO" test -run '^$' -bench . -benchmem ./internal/graph/
    echo "==> end-to-end server measurements"
    args=(-go-bin "$BIN" -port "${BENCH_PORT:-8100}" -n "${BENCH_N:-100}")
    if [ -n "${PYTHON:-}" ] && [ -n "${PY_BACKEND:-}" ]; then
      args+=(-python "$PYTHON" -py-backend "$PY_BACKEND")
    fi
    exec "$GO" run ./tools/benchcmp "${args[@]}"
    ;;
esac

build_server
setup_frontend
if [ "${1:-}" = "--reseed" ] || [ ! -f "$DB" ]; then
  seed
fi

echo "==> starting API on http://127.0.0.1:$API_PORT"
"$BIN" serve -addr "127.0.0.1:$API_PORT" -db "$DB" &
API_PID=$!
trap 'echo; echo "==> stopping"; kill $API_PID 2>/dev/null || true; wait $API_PID 2>/dev/null || true' EXIT INT TERM

for _ in $(seq 1 40); do
  curl -sf "http://127.0.0.1:$API_PORT/api/health" >/dev/null 2>&1 && break
  sleep 0.25
done

echo "==> starting UI on http://localhost:$UI_PORT  (Ctrl+C to stop both)"
cd "$FRONTEND"
TESSERA_API="http://127.0.0.1:$API_PORT" npx vite --port "$UI_PORT" --strictPort
