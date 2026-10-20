#!/usr/bin/env bash
# Prints the `go test` arguments (one per line) for CI test shard $1. Run from mvp/server.
#
# Package shards are listed in SHARDS. "rest" is every package from `go list` that no other
# shard names, so a new package is picked up automatically and never skipped.
#
# internal/api is too slow for one runner under -race (it passed 45 minutes on hosted
# runners), so its tests are split by name across api-1..api-$API_SPLIT: the sorted test list
# is dealt round-robin, which covers every test exactly once. Set RACE=-race when the run uses
# -race so the `-list` build is the one `go test` then reuses from the build cache.
set -euo pipefail

API_SPLIT=3

declare -A SHARDS=(
  [store]="internal/store internal/store/storetest"
  [cmd]="cmd/tessera internal/auth internal/backup"
  [core]="internal/admin internal/audit internal/aws/query"
  # The slowest single packages outside api (10-15 minutes each under -race).
  [slow]="internal/oauth internal/reviews internal/readiness internal/rotation internal/seed"
)

shard=${1:?usage: ci-shard.sh api-1..api-$API_SPLIT|store|cmd|core|slow|groups|rest}
mod=$(go list -m)

case "$shard" in
  api-*)
    n=${shard#api-}
    [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le "$API_SPLIT" ] ||
      { echo "unknown shard: $shard" >&2; exit 2; }
    # shellcheck disable=SC2086 # RACE is empty or one flag
    tests=$(go test ${RACE:-} -list '^(Test|Fuzz|Example)' ./internal/api |
      grep -E '^(Test|Fuzz|Example)' | sort |
      awk -v n="$n" -v k="$API_SPLIT" '(NR - 1) % k == n - 1' | paste -sd'|' -)
    [ -n "$tests" ] || { echo "no tests listed for $shard" >&2; exit 1; }
    echo "-run"
    echo "^($tests)\$"
    echo "$mod/internal/api"
    ;;
  groups)
    go list ./internal/groups/...
    ;;
  rest)
    explicit=$(
      echo "$mod/internal/api"
      go list ./internal/groups/...
      for s in "${!SHARDS[@]}"; do for p in ${SHARDS[$s]}; do echo "$mod/$p"; done; done
    )
    comm -23 <(go list ./... | sort) <(echo "$explicit" | sort)
    ;;
  *)
    [ -n "${SHARDS[$shard]:-}" ] || { echo "unknown shard: $shard" >&2; exit 2; }
    for p in ${SHARDS[$shard]}; do echo "$mod/$p"; done
    ;;
esac
