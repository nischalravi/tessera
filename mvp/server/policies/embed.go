// Package policies embeds the default policy-as-code YAML files.
//
// The server reads policies from TESSERA_POLICY_DIR (or --policies) when set,
// so they can be edited without rebuilding; otherwise it uses these copies.
package policies

import "embed"

// FS holds the default *.yaml policies.
//
//go:embed *.yaml
var FS embed.FS
