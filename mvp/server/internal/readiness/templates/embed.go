// Package templates embeds the versioned readiness checklist templates
// (design §3). Template data never comes from the database or the network:
// it ships in the binary and changes through code review.
package templates

import "embed"

// FS holds base.yaml and one YAML file per connector template.
//
//go:embed *.yaml
var FS embed.FS
