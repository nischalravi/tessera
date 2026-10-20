// Package mcpauth is Tessera's OAuth 2.1 authorization server for MCP clients
// (issue #115, MCP authorization spec 2025-11-25): client ID metadata
// documents, authorization-code + PKCE S256, RFC 8693 token exchange with an
// act chain, RFC 8707 audience binding, and scopes that are the intersection
// of what the user, the agent and the task may do according to the graph.
//
//   - scope.go: scope names and the intersection (the security core).
//   - cimd.go: fetching and validating client ID metadata documents.
//   - token.go: minting and verifying access tokens (internal/keys).
//   - service.go: authorization codes, token exchange, introspection,
//     tool-call decisions and revocation, all inside the caller's transaction
//     so each decision and its audit event commit together.
package mcpauth

import (
	"errors"
	"sort"
	"strings"
	"unicode"

	"github.com/nischalravi/tessera/mvp/server/internal/graph"
)

// Scope limits.
const (
	MaxScopes      = 64
	MaxScopeLength = 256
)

// ScopeOf is the scope name of an effective permission:
// "<system>:<action>:<resource>" (the system is not repeated when the action
// already starts with it, as in "snowflake:SELECT"). A permission whose parts are empty or hold
// whitespace or control characters has no name (scopes are space-delimited),
// so it can never be granted: the stricter reading.
func ScopeOf(ep *graph.EffectivePermission) (string, bool) {
	if ep == nil {
		return "", false
	}
	action := ep.Action
	if !strings.HasPrefix(action, ep.System+":") {
		action = ep.System + ":" + action
	}
	s := action + ":" + ep.ResourceName
	if ep.System == "" || ep.Action == "" || ep.ResourceName == "" || !validScopeToken(s) {
		return "", false
	}
	return s, true
}

func validScopeToken(s string) bool {
	if s == "" || len(s) > MaxScopeLength {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == '"' || r == '\\' || r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// ScopesOf lists the scope names of eff (sorted, unique).
func ScopesOf(eff *graph.Eff) []string {
	if eff == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, ep := range eff.Values() {
		if s, ok := ScopeOf(ep); ok && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// ParseScope splits a space-delimited scope parameter into unique names. It
// refuses an empty, oversized or malformed list.
func ParseScope(s string) ([]string, error) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return nil, errors.New("scope is required")
	}
	if len(fields) > MaxScopes {
		return nil, errors.New("too many scopes")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if !validScopeToken(f) {
			return nil, errors.New("malformed scope")
		}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out, nil
}

// JoinScope is the space-delimited form (sorted).
func JoinScope(scopes []string) string {
	c := append([]string(nil), scopes...)
	sort.Strings(c)
	return strings.Join(c, " ")
}

// Intersect returns the names present in every set (sorted, unique). With no
// set, or when any set is empty or nil, the result is empty: a missing
// party never widens anything.
func Intersect(sets ...[]string) []string {
	if len(sets) == 0 {
		return nil
	}
	count := map[string]int{}
	for _, set := range sets {
		seen := map[string]bool{}
		for _, s := range set {
			if !seen[s] {
				seen[s] = true
				count[s]++
			}
		}
	}
	var out []string
	for s, n := range count {
		if n == len(sets) {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Subset reports whether every name of sub is in super.
func Subset(sub, super []string) bool {
	in := map[string]bool{}
	for _, s := range super {
		in[s] = true
	}
	for _, s := range sub {
		if !in[s] {
			return false
		}
	}
	return true
}

// Effective is the scope a token for (user, agent) may carry for the task:
// the user's graph permissions, intersected with the agent's (its ceiling) and
// with the task's requested scopes. Every extra set (for example the scope of
// the subject token being exchanged) narrows it further; nothing widens it.
func Effective(g *graph.Snapshot, userID, agentID int64, task []string, narrow ...[]string) []string {
	sets := [][]string{ScopesOf(g.EffectivePermissions(userID)), ScopesOf(g.EffectivePermissions(agentID)), task}
	sets = append(sets, narrow...)
	return Intersect(sets...)
}
