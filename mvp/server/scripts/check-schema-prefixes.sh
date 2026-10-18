#!/usr/bin/env bash
# Fails if two schema files share a numeric prefix (two PRs picked the same number).
# The legacy map holds prefixes that already collided on dev before this check existed
# (prefix -> file count); they are tolerated, but nothing new may join them.
set -euo pipefail
dir="$(cd "$(dirname "$0")/.." && pwd)/internal/store/schema"
declare -A legacy=([0204]=2 [0205]=3 [0206]=3)
declare -A count
for f in "$dir"/*.sql; do
  p="$(basename "$f")"; p="${p%%_*}"
  count[$p]=$(( ${count[$p]:-0} + 1 ))
done
fail=0
for p in "${!count[@]}"; do
  max=${legacy[$p]:-1}
  if [ "${count[$p]}" -gt "$max" ]; then
    echo "schema prefix $p is used by ${count[$p]} files:" >&2
    ls "$dir" | grep "^${p}_" >&2
    fail=1
  fi
done
[ "$fail" = 0 ] || { echo "Renumber your schema file to the next free number." >&2; exit 1; }
echo "schema prefixes ok"
