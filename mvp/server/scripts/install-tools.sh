#!/usr/bin/env bash
# Install the pinned security scanners into $(go env GOPATH)/bin.
#   scripts/install-tools.sh            govulncheck + gosec
#
# gosec v2.29.0 pins a golang.org/x/tools that cannot read Go 1.27 export data
# ("export data version 5 is greater than maximum supported version 4"), so it
# is built in a throwaway module against a newer x/tools.
#
# The scanners are built with the Go toolchain go.mod requires (its `toolchain`
# line, else its `go` line), not whatever `go` is first on PATH: a scanner
# built with an older Go cannot read packages that need the newer one
# (govulncheck: "package requires newer Go version go1.27").
set -euo pipefail
GOVULNCHECK_VERSION="v1.8.0"
GOSEC_VERSION="v2.29.0"
XTOOLS_VERSION="v0.51.0"
GO="${GO:-go}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
gomod="${GOMOD_FILE:-$here/../go.mod}"
required="$(awk '$1 == "toolchain" { print $2; found = 1; exit } $1 == "go" && !v { v = "go" $2 } END { if (!found) print v }' "$gomod")"
case "$required" in
  go1.*) ;;
  *) echo "install-tools: cannot read the Go version from $gomod" >&2; exit 1 ;;
esac
# GOTOOLCHAIN makes every go command below (install, mod init, get, build) run
# with the required toolchain, downloading it if needed.
export GOTOOLCHAIN="$required"
echo "building the scanners with $("$GO" env GOVERSION) (go.mod requires $required)"
BIN="$("$GO" env GOPATH)/bin"

"$GO" install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
(
  cd "$work"
  "$GO" mod init gosec-build >/dev/null 2>&1
  "$GO" get "github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}" "golang.org/x/tools@${XTOOLS_VERSION}"
  "$GO" build -trimpath -o "$BIN/gosec" github.com/securego/gosec/v2/cmd/gosec
)
echo "installed with $("$GO" env GOVERSION): govulncheck ${GOVULNCHECK_VERSION} and gosec ${GOSEC_VERSION} (x/tools ${XTOOLS_VERSION}) into $BIN"
