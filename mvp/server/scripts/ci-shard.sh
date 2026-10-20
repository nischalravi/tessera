#!/usr/bin/env bash
# Prints the Go packages (one per line) that CI test shard $1 runs. Run from mvp/server.
# Explicit shards are listed below; "rest" is every package from `go list` that no explicit
# shard names, so a new package is picked up automatically and never skipped.
set -euo pipefail

declare -A SHARDS=(
  [api]="internal/api"
  [store]="internal/store internal/store/storetest"
  [cmd]="cmd/tessera internal/auth internal/backup"
  [core]="internal/admin internal/audit internal/aws/query"
)

shard=${1:?usage: ci-shard.sh api|store|cmd|core|rest}
mod=$(go list -m)

if [ "$shard" != rest ]; then
  [ -n "${SHARDS[$shard]:-}" ] || { echo "unknown shard: $shard" >&2; exit 2; }
  for p in ${SHARDS[$shard]}; do echo "$mod/$p"; done
  exit 0
fi

explicit=$(for s in "${!SHARDS[@]}"; do for p in ${SHARDS[$s]}; do echo "$mod/$p"; done; done | sort)
comm -23 <(go list ./... | sort) <(echo "$explicit")
