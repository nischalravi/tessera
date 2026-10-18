#!/usr/bin/env bash
# ci-diagnostics.sh: collect logs to validate a change and troubleshoot CI.
#
# Runs the same gates as .github/workflows/ci.yml and security-scan.yml
# locally, one log per step, and (when the GitHub CLI is signed in) pulls
# what GitHub recorded for a PR's runs: jobs, runners, steps, annotations
# and job logs. Annotations are where GitHub explains jobs that never start
# (for example a billing or spending-limit lock), which leave no job log.
#
# Usage (from anywhere in the repo):
#   mvp/scripts/ci-diagnostics.sh                  # all local gates
#   mvp/scripts/ci-diagnostics.sh --quick          # skip the slow -race suite
#   mvp/scripts/ci-diagnostics.sh --pr 182         # also collect GitHub's view of PR 182
#   mvp/scripts/ci-diagnostics.sh --only github --pr 182
#   --only takes a comma list of: env,go,security,frontend,github
#
# Output: mvp/logs/ci-<UTC timestamp>/ with SUMMARY.md, one <step>.log per
# step and github/*.json. mvp/logs/ is git-ignored. Nothing is uploaded.
set -uo pipefail

ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
MVP="$ROOT/mvp"
QUICK=0 PR="" ONLY="env,go,security,frontend,github"
while [ $# -gt 0 ]; do
  case "$1" in
    --quick) QUICK=1 ;;
    --pr) PR="${2:?--pr needs a number}"; shift ;;
    --only) ONLY="${2:?--only needs a list}"; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
want() { case ",$ONLY," in *",$1,"*) return 0 ;; esac; return 1; }

OUT="$MVP/logs/ci-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT/github"
SUMMARY="$OUT/SUMMARY.md"
FAILED=0
{
  echo "# CI diagnostics"
  echo
  echo "- Commit: \`$(git -C "$ROOT" rev-parse HEAD)\` on \`$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)\`"
  echo "- Collected: $(date -u +%Y-%m-%dT%H:%M:%SZ)${PR:+ · PR #$PR}"
  echo
  echo "| Step | Result | Seconds | Log |"
  echo "|---|---|---|---|"
} > "$SUMMARY"

# step <name> <dir> <command...>: runs a command, logs it, records the result.
step() {
  local name="$1" dir="$2"; shift 2
  local log="$OUT/$name.log" start end rc
  printf '==> %-22s' "$name"
  start=$(date +%s)
  { echo "\$ (cd ${dir#"$ROOT"/} && $*)"; echo; } > "$log"
  (cd "$dir" && "$@") >> "$log" 2>&1
  rc=$?
  end=$(date +%s)
  echo "exit $rc" >> "$log"
  if [ $rc -eq 0 ]; then echo "ok ($((end - start))s)"; res="ok"
  else echo "FAILED (exit $rc, see $log)"; res="**failed ($rc)**"; FAILED=$((FAILED + 1)); fi
  echo "| $name | $res | $((end - start)) | \`$name.log\` |" >> "$SUMMARY"
}
skip() { echo "==> $(printf '%-22s' "$1")skipped: $2"; echo "| $1 | skipped: $2 | | |" >> "$SUMMARY"; }
have() { command -v "$1" >/dev/null 2>&1; }
gofmt_check() { local f; f="$(gofmt -l .)"; [ -z "$f" ] || { echo "not gofmt-ed:"; echo "$f"; return 1; }; }

S="$MVP/server" F="$MVP/frontend"
GOBIN_DIR="$(go env GOPATH 2>/dev/null)/bin"

if want env; then
  {
    echo "## Toolchain"
    echo "go:       $(go version 2>&1)"
    echo "go.mod:   $(grep -E '^(go|toolchain) ' "$S/go.mod" | tr '\n' ' ')"
    echo "node:     $(node --version 2>&1)   (CI uses node 24)"
    echo "npm:      $(npm --version 2>&1)"
    echo "gosec:    $("$GOBIN_DIR/gosec" -version 2>&1 | head -1)"
    echo "govulncheck: $("$GOBIN_DIR/govulncheck" -version 2>&1 | grep -i govulncheck | head -1)"
    echo "os:       $(uname -srm)"
    echo
    echo "## Git"
    git -C "$ROOT" status -sb | head -20
    git -C "$ROOT" log --oneline -5
    echo
    echo "## Actions pinned by the workflows (does each version exist upstream?)"
    grep -ho 'uses: *[^ #]*' "$ROOT"/.github/workflows/*.yml | sed 's/uses: *//' | sort -u | while read -r ref; do
      repo="${ref%@*}" ver="${ref##*@}"
      case "$repo" in ./*) echo "$ref  local"; continue ;; esac
      # owner/repo[/path]@ref: the ref lives in owner/repo
      if git ls-remote --exit-code "https://github.com/$(echo "$repo" | cut -d/ -f1-2)" "refs/tags/$ver" "refs/heads/$ver" >/dev/null 2>&1; then
        echo "$ref  resolves"
      else
        echo "$ref  DOES NOT RESOLVE (a job using it fails at 'Set up job')"
      fi
    done
  } > "$OUT/env.log" 2>&1
  echo "| env | collected | | \`env.log\` |" >> "$SUMMARY"
  echo "==> env                   collected"
fi

if want go; then
  step go-mod-download "$S" go mod download
  step go-mod-verify   "$S" go mod verify
  step gofmt           "$S" gofmt_check
  step go-vet          "$S" go vet ./...
  if [ $QUICK -eq 1 ]; then
    step go-test       "$S" go test -timeout 20m ./...
    skip go-test-race "--quick"
  else
    step go-test-race  "$S" go test -race -timeout 25m ./...
  fi
  step go-build        "$S" go build -trimpath -o "$OUT/tessera" ./cmd/tessera
  rm -f "$OUT/tessera"
fi

if want security; then
  if [ -x "$GOBIN_DIR/gosec" ]; then step gosec "$S" "$GOBIN_DIR/gosec" -quiet ./...; else skip gosec "not installed (mvp/server/scripts/install-tools.sh)"; fi
  if [ -x "$GOBIN_DIR/govulncheck" ]; then step govulncheck "$S" "$GOBIN_DIR/govulncheck" ./...; else skip govulncheck "not installed (mvp/server/scripts/install-tools.sh)"; fi
  if have gitleaks; then step gitleaks "$ROOT" gitleaks detect --no-banner --redact; else skip gitleaks "not installed"; fi
fi

if want frontend; then
  step npm-ci    "$F" npm ci --no-audit --no-fund
  step npm-build "$F" npm run build
  if grep -q '"test":' "$F/package.json"; then step npm-test "$F" npm test; else skip npm-test "no test script on this branch"; fi
  step npm-audit "$F" npm audit --omit=dev --audit-level=high
fi

if want github; then
  if [ -z "$PR" ]; then
    skip github "pass --pr <number>"
  elif ! have gh || ! gh auth status >/dev/null 2>&1; then
    skip github "GitHub CLI not signed in (run gh auth login)"
  else
    G="$OUT/github" REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null)"
    {
      gh pr view "$PR" --json number,headRefName,headRefOid,mergeable,mergeStateStatus,statusCheckRollup > "$G/pr.json"
      SHA="$(gh pr view "$PR" --json headRefOid -q .headRefOid)"
      gh api "repos/$REPO/actions/runs?head_sha=$SHA&per_page=50" > "$G/runs.json"
      gh api "repos/$REPO/commits/$SHA/check-runs?per_page=100" > "$G/check-runs.json"
      gh api "repos/$REPO/actions/permissions" > "$G/actions-permissions.json" 2>&1 || true
      echo "## Runs for $SHA"
      gh api "repos/$REPO/actions/runs?head_sha=$SHA&per_page=50" \
        -q '.workflow_runs[] | "\(.id)  \(.name)  \(.status)/\(.conclusion)  attempt \(.run_attempt)  \(.html_url)"'
      for run in $(gh api "repos/$REPO/actions/runs?head_sha=$SHA&per_page=50" -q '.workflow_runs[].id'); do
        gh api "repos/$REPO/actions/runs/$run/jobs?per_page=100" > "$G/jobs-$run.json"
        echo
        echo "## Jobs of run $run (runner_id 0 / no runner_name = never got a runner)"
        gh api "repos/$REPO/actions/runs/$run/jobs?per_page=100" \
          -q '.jobs[] | "\(.id)  \(.name)  \(.conclusion)  runner_id=\(.runner_id // 0) runner=\(.runner_name // "-")  steps=\(.steps | length)"'
        for job in $(gh api "repos/$REPO/actions/runs/$run/jobs?per_page=100" -q '.jobs[].id'); do
          gh api "repos/$REPO/actions/jobs/$job/logs" > "$G/job-$job.log" 2>&1 || echo "(no log for job $job)" > "$G/job-$job.log"
        done
      done
      echo
      echo "## Check-run annotations (GitHub explains jobs that never started here)"
      for cr in $(gh api "repos/$REPO/commits/$SHA/check-runs?per_page=100" -q '.check_runs[] | select(.conclusion=="failure") | .id'); do
        gh api "repos/$REPO/check-runs/$cr/annotations" > "$G/annotations-$cr.json"
        gh api "repos/$REPO/check-runs/$cr/annotations" -q ".[] | \"$cr  \\(.annotation_level): \\(.message)\""
      done
    } > "$OUT/github.log" 2>&1
    echo "| github | collected | | \`github.log\`, \`github/\` |" >> "$SUMMARY"
    echo "==> github                collected (see github.log)"
    grep -iE "billing|spending|locked|payment|minutes" "$OUT/github.log" | sort -u | sed 's/^/    /' | head -5
  fi
fi

{
  echo
  if [ $FAILED -eq 0 ]; then echo "All steps that ran passed."; else echo "$FAILED step(s) failed: open their logs above."; fi
  echo
  echo "When CI is red but every local step passes, read \`github.log\`: jobs with"
  echo "runner_id 0, no steps and a billing or spending annotation never ran, and"
  echo "the fix is in the account's GitHub billing settings, not in the code."
} >> "$SUMMARY"
echo
echo "Summary: $SUMMARY"
exit $((FAILED > 0))
