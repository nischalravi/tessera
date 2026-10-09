#!/usr/bin/env bash
# Install the pinned security scanners into $(go env GOPATH)/bin.
#   scripts/install-tools.sh            govulncheck + gosec
#
# gosec v2.29.0 pins a golang.org/x/tools that cannot read Go 1.27 export data
# ("export data version 5 is greater than maximum supported version 4"), so it
# is built in a throwaway module against a newer x/tools.
set -euo pipefail
GOVULNCHECK_VERSION="v1.8.0"
GOSEC_VERSION="v2.29.0"
XTOOLS_VERSION="v0.51.0"
GO="${GO:-go}"
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
echo "installed govulncheck ${GOVULNCHECK_VERSION} and gosec ${GOSEC_VERSION} (x/tools ${XTOOLS_VERSION}) into $BIN"
